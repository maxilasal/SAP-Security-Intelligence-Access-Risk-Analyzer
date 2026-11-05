"""Regresión: al quitar SAP_ALL en SAP y volver a extraer, el usuario deja de figurar en la tarea."""

from sqlalchemy.orm import Session

from conftest import fixture_data
from sapsec.connectors.base import ConnectionParams, LoadLimits
from sapsec.connectors.fixture_connector import FixtureConnector
from sapsec.extraction.extractor import Extractor
from sapsec.storage.db import make_engine
from sapsec.storage.orm import Base, SapConnection, SapSystem


def _extract(db, conn, data):  # type: ignore[no-untyped-def]
    c = FixtureConnector(ConnectionParams(client="100", user="X"),
                         LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=10 ** 6), data=data)
    snap = Extractor(c, db, conn, "pytest").run()
    db.commit()
    return snap


def test_removed_sap_all_disappears_from_task(monkeypatch):
    import sapsec.services as sv
    from sapsec.actions import _CACHE, build_tasks
    from sapsec.engine.rules import load_rules
    from conftest import ROOT
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
    rules = load_rules(ROOT / "config" / "rules")

    d1 = fixture_data()
    d1["tables"]["UST04"].append({"BNAME": "REPORTE1", "PROFILE": "SAP_ALL"})  # segundo usuario con SAP_ALL
    s1 = _extract(db, conn, d1)
    sv.analyze_snapshot(db, s1.id)
    t1 = next(t for t in build_tasks(db, s1, rules) if t.title == "Quitar el perfil SAP_ALL")
    assert t1.users == ["ADMIN_BASIS", "REPORTE1"]

    # Se quita SAP_ALL a REPORTE1 en SAP y se vuelve a extraer
    d2 = fixture_data()
    s2 = _extract(db, conn, d2)
    sv.analyze_snapshot(db, s2.id)
    _CACHE.clear()
    t2 = next(t for t in build_tasks(db, s2, rules) if t.title == "Quitar el perfil SAP_ALL")
    assert t2.users == ["ADMIN_BASIS"]               # ya no figura como afectado
    assert t2.fixed_users == ["REPORTE1"]            # se informa como corregido
    assert t2.pending

    # Se quita también a ADMIN_BASIS: la tarea queda resuelta
    d3 = fixture_data()
    d3["tables"]["UST04"] = [r for r in d3["tables"]["UST04"] if r["PROFILE"] != "SAP_ALL"]
    s3 = _extract(db, conn, d3)
    sv.analyze_snapshot(db, s3.id)
    t3 = next(t for t in build_tasks(db, s3, rules) if t.title == "Quitar el perfil SAP_ALL")
    assert not t3.pending and t3.users == [] and "ADMIN_BASIS" in t3.fixed_users
