"""SAP_ALL: una sola alerta por persona, con sus consecuencias adentro; lo que viene de roles sigue aparte."""

from __future__ import annotations

from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from conftest import ROOT, extract, fixture_data
from sapsec.connectors.base import ConnectionParams, LoadLimits
from sapsec.connectors.fixture_connector import FixtureConnector
from sapsec.engine.analysis import AnalysisContext, analyze_user
from sapsec.extraction.extractor import Extractor
from sapsec.storage.db import make_engine
from sapsec.storage.orm import Base, Finding, SapConnection, SapSystem
from sapsec.storage.snapshot_data import SnapshotData, load_snapshot_rows

AS_OF = date(2026, 11, 4)


def test_sap_all_is_one_alert_with_its_consequences(rules, data):
    a = analyze_user(AnalysisContext(rules, "PRD", 1.0, AS_OF), data, "ADMIN_BASIS")
    assert [h.rule_id for h in a.critical] == ["CRIT-PRF-001"] and a.sod == []
    cons = a.critical[0].metrics["consecuencias"]
    assert len(cons) > 30 and {"CRIT-DEV-002", "SOD-FI-001"} <= {c["regla"] for c in cons}
    assert a.risk.inherent_score == 100  # una alerta crítica, no la suma de 40


def test_permission_also_granted_by_a_role_stays_as_its_own_alert(rules):
    """Si además de SAP_ALL tiene un rol que le da desarrollo, quitar SAP_ALL no alcanza: esa alerta sigue aparte."""
    d = fixture_data()
    d["tables"]["AGR_USERS"].append({"AGR_NAME": "Z_BC_DESARROLLO", "UNAME": "ADMIN_BASIS", "FROM_DAT": "20250101",
                                     "TO_DAT": "99991231", "EXCLUDE": "", "CHANGE_DAT": "20250101", "ORG_FLAG": "",
                                     "COL_FLAG": ""})
    prof = next(r["PROFILE"] for r in d["tables"]["AGR_1016"] if r["AGR_NAME"] == "Z_BC_DESARROLLO")
    d["tables"]["UST04"].append({"BNAME": "ADMIN_BASIS", "PROFILE": prof})
    engine, _, snap, _ = extract(d)
    data = SnapshotData(load_snapshot_rows(engine, snap.id), snap.id)
    a = analyze_user(AnalysisContext(rules, "PRD", 1.0, AS_OF), data, "ADMIN_BASIS")
    dev = next(h for h in a.critical if h.rule_id == "CRIT-DEV-001")
    assert dev.roles == ["Z_BC_DESARROLLO"]                       # la evidencia cita el rol, no SAP_ALL
    prf = next(h for h in a.critical if h.rule_id == "CRIT-PRF-001")
    assert "CRIT-DEV-001" not in {c["regla"] for c in prf.metrics["consecuencias"]}


def test_reanalysis_does_not_mark_folded_alerts_as_fixed(monkeypatch):
    """Una alerta suelta de un análisis anterior que ahora va dentro de SAP_ALL no se informa como «corregida»."""
    import sapsec.services as sv
    from sapsec.engine.rules import load_rules
    engine = make_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(sv, "get_engine", lambda: engine)
    db = Session(engine, expire_on_commit=False)
    system = SapSystem(sid="DMO", name="PRD", environment="PRD", productive=True)
    db.add(system)
    db.flush()
    conn = SapConnection(system_id=system.id, client="100", name="t", backend="fixture", rfc_user="X")
    db.add(conn)
    db.commit()

    def run():  # type: ignore[no-untyped-def]
        c = FixtureConnector(ConnectionParams(client="100", user="X"),
                             LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=10 ** 6), data=fixture_data())
        s = Extractor(c, db, conn, "pytest").run()
        db.commit()
        sv.analyze_snapshot(db, s.id, as_of=AS_OF)
        return s

    s1 = run()
    # Hallazgo «suelto» como lo guardaban las versiones anteriores (consecuencia de SAP_ALL como alerta propia)
    db.add(Finding(code="H-LEGACY", fingerprint=sv.fingerprint("DMO", "100", "critica", "CRIT-TAB-001",
                                                               "ADMIN_BASIS", ""),
                   snapshot_id=s1.id, kind="critica", rule_id="CRIT-TAB-001", severity="critico",
                   title="Modificar todas las tablas", sid="DMO", client="100", subject_user="ADMIN_BASIS",
                   status="abierto"))
    db.commit()
    s2 = run()
    fixed = db.scalars(select(Finding).where(Finding.snapshot_id == s2.id, Finding.status == "corregido",
                                             Finding.subject_user == "ADMIN_BASIS")).all()
    assert fixed == []
    assert load_rules(ROOT / "config" / "rules").critical_by_id("CRIT-PRF-001") is not None
