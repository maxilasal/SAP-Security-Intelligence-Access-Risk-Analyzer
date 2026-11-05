"""S/4HANA con Fiori, controles distintos por ambiente (DEV/QA/PRD) y control entre sistemas DEV → PRD."""

from __future__ import annotations

from datetime import date

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from conftest import ROOT, fixture_data
from sapsec.connectors.base import ConnectionParams, LoadLimits
from sapsec.connectors.fixture_connector import FixtureConnector
from sapsec.extraction.extractor import Extractor
from sapsec.storage.db import make_engine
from sapsec.storage.orm import Base, Finding, SapConnection, SapSystem

AS_OF = date(2026, 11, 4)


def _system(db, name, env, landscape, data=None):  # type: ignore[no-untyped-def]
    import sapsec.services as sv
    s = SapSystem(sid="DMO", name=name, environment=env, productive=env == "PRD", landscape=landscape)
    db.add(s)
    db.flush()
    c = SapConnection(system_id=s.id, client="100", name=name, backend="fixture", rfc_user="X")
    db.add(c)
    db.commit()
    con = FixtureConnector(ConnectionParams(client="100", user="X"),
                           LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=10 ** 6), data=data or fixture_data())
    snap = Extractor(con, db, c, "pytest").run()
    db.commit()
    sv.analyze_snapshot(db, snap.id, as_of=AS_OF)
    return snap


@pytest.fixture(scope="module")
def landscape():  # type: ignore[no-untyped-def]
    import sapsec.services as sv
    engine = make_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    orig = sv.get_engine
    sv.get_engine = lambda: engine  # type: ignore[assignment]
    db = Session(engine, expire_on_commit=False)
    prd = _system(db, "S4 PRD", "PRD", "S4 corporativo")
    dev = _system(db, "S4 DEV", "DEV", "S4 corporativo")
    yield db, prd, dev
    sv.get_engine = orig  # type: ignore[assignment]


def _findings(db, snap, **kw):  # type: ignore[no-untyped-def]
    q = select(Finding).where(Finding.snapshot_id == snap.id)
    for k, v in kw.items():
        q = q.where(getattr(Finding, k) == v)
    return list(db.scalars(q))


def test_product_detected_from_cvers(landscape):
    db, prd, dev = landscape
    p = prd.system_info["PRODUCTO"]
    assert p["kind"] == "S4" and p["label"] == "SAP S/4HANA (S4CORE 108)" and p["fiori"]


def test_sod_detected_when_done_from_a_fiori_app(landscape):
    """COMPRA_FIORI crea pedidos con una app Fiori (sin ME21N) y además los libera: el conflicto se detecta."""
    db, prd, dev = landscape
    hits = _findings(db, prd, subject_user="COMPRA_FIORI", rule_id="SOD-MM-001")
    assert hits, "el conflicto vía Fiori no se detectó"
    fn = next(f for f in hits[0].evidence["funciones"] if f["funcion"] == "FN_PO_CREAR")
    assert fn["tcodes"] == [] and fn["servicios"] == ["ZMM_PEDIDOS_DEMO_SRV 0001 (IWSG)"]
    assert "app Fiori" in hits[0].description


def test_view_only_fiori_service_does_not_count_as_creating(rules):
    """Si solo tiene el servicio de VISUALIZAR pedidos, no cuenta como «crear pedidos» aunque tenga M_BEST_BSA 01."""
    from conftest import extract
    from sapsec.engine.analysis import AnalysisContext, analyze_user
    from sapsec.storage.snapshot_data import SnapshotData, load_snapshot_rows
    d = fixture_data()
    t = d["tables"]
    t["UST12"] = [r for r in t["UST12"] if not (r["OBJCT"] == "S_SERVICE" and r["VON"] == "DEMO0FIORI0PEDIDOS0HASH0000001")]
    engine, _, snap, _ = extract(d)
    data = SnapshotData(load_snapshot_rows(engine, snap.id), snap.id)
    a = analyze_user(AnalysisContext(rules, "PRD", 1.0, AS_OF), data, "COMPRA_FIORI")
    assert not [h for h in a.sod if h.risk_id == "SOD-MM-001"]


def test_development_system_has_different_controls(landscape):
    db, prd, dev = landscape
    # Procesos de negocio: no aplican en DEV
    assert _findings(db, prd, kind="sod", rule_id="SOD-FI-001")
    assert not _findings(db, dev, kind="sod", rule_id="SOD-FI-001")
    # Desarrollar: crítico en PRD, normal en DEV (queda solo como dato informativo)
    assert _findings(db, prd, rule_id="CRIT-DEV-001", subject_user="DEV_USER")[0].severity == "critico"
    assert not _findings(db, dev, rule_id="CRIT-DEV-001")
    marker = _findings(db, dev, rule_id="INFO-DEV-001", subject_user="DEV_USER")
    assert marker and marker[0].severity == "informativo"
    # Depurar con modificación: crítico en PRD, bajo en DEV; SAP_ALL sigue siendo grave en DEV
    assert {f.severity for f in _findings(db, prd, rule_id="CRIT-DEV-002")} == {"critico"}
    assert {f.severity for f in _findings(db, dev, rule_id="CRIT-DEV-002")} == {"bajo"}
    assert _findings(db, dev, rule_id="CRIT-PRF-001")[0].severity == "alto"


def test_informative_findings_are_not_tasks(landscape):
    from sapsec.actions import _CACHE, build_tasks
    from sapsec.services import get_rules
    db, prd, dev = landscape
    _CACHE.clear()
    tasks = build_tasks(db, dev, get_rules())
    assert tasks and not any(p.rule_id == "INFO-DEV-001" for t in tasks for p in t.problems)
    assert all(t.severity != "informativo" for t in tasks)


def test_developers_with_critical_access_in_production(landscape):
    from sapsec.services import cross_system
    db, prd, dev = landscape
    x = cross_system(db)
    users = {r["user"] for r in x["rows"]}
    assert {"DEV_USER", "ADMIN_BASIS"} <= users and "USUARIO_TEST" not in users
    dev_user = next(r for r in x["rows"] if r["user"] == "DEV_USER")
    assert dev_user["same"] and {"CRIT-DEV-001", "CRIT-CTS-001"} <= {i["rule_id"] for i in dev_user["items"]}
    # Otro landscape: no se mezclan
    dev.connection.system.landscape = "ECC Uruguay"
    db.commit()
    assert cross_system(db)["rows"] == []
    dev.connection.system.landscape = "S4 corporativo"
    db.commit()


def test_invalid_environment_severity_is_rejected(tmp_path):
    from sapsec.engine.rules import RuleError, load_rules
    for f in (ROOT / "config" / "rules").glob("*.yaml"):
        (tmp_path / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    p = tmp_path / "critical_auth.yaml"
    p.write_text(p.read_text(encoding="utf-8").replace("by_environment: {DEV: alto}", "by_environment: {DEV: altisimo}", 1),
                 encoding="utf-8")
    with pytest.raises(RuleError, match="by_environment"):
        load_rules(tmp_path)
