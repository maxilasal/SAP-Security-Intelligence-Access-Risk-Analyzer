"""«Qué cambió» entre dos extracciones del mismo sistema: alertas nuevas/resueltas y los cambios en SAP que las explican."""

from __future__ import annotations

from datetime import date

import pytest
from sqlalchemy.orm import Session

from conftest import fixture_data
from sapsec.connectors.base import ConnectionParams, LoadLimits
from sapsec.connectors.fixture_connector import FixtureConnector
from sapsec.extraction.extractor import Extractor
from sapsec.storage.db import make_engine
from sapsec.storage.orm import Base, SapConnection, SapSystem

AS_OF = date(2026, 11, 4)


@pytest.fixture(scope="module")
def pair():  # type: ignore[no-untyped-def]
    import sapsec.services as sv
    engine = make_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    orig = sv.get_engine
    sv.get_engine = lambda: engine  # type: ignore[assignment]
    db = Session(engine, expire_on_commit=False)
    system = SapSystem(sid="DMO", name="PRD", environment="PRD", productive=True)
    db.add(system)
    db.flush()
    conn = SapConnection(system_id=system.id, client="100", name="t", backend="fixture", rfc_user="X")
    db.add(conn)
    db.commit()

    def run(d):  # type: ignore[no-untyped-def]
        c = FixtureConnector(ConnectionParams(client="100", user="X"),
                             LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=10 ** 6), data=d)
        s = Extractor(c, db, conn, "pytest").run()
        db.commit()
        sv.analyze_snapshot(db, s.id, as_of=AS_OF)
        return s

    a = run(fixture_data())
    d = fixture_data()
    t = d["tables"]
    # Lo que pasó «durante el día» en el sistema ficticio:
    t["AGR_USERS"].append({"AGR_NAME": "Z_FI_PAGOS", "UNAME": "USUARIO_TEST", "FROM_DAT": "20261104",
                           "TO_DAT": "99991231", "EXCLUDE": "", "CHANGE_DAT": "20261104", "ORG_FLAG": "", "COL_FLAG": ""})
    t["UST04"].append({"BNAME": "USUARIO_TEST",
                       "PROFILE": next(r["PROFILE"] for r in t["AGR_1016"] if r["AGR_NAME"] == "Z_FI_PAGOS")})
    t["UST04"].append({"BNAME": "CONTADOR1", "PROFILE": "SAP_ALL"})            # SAP_ALL asignado a mano
    for u in t["USR02"]:
        if u["BNAME"] == "INACTIVO1":
            u["UFLAG"] = "64"                                                    # se bloqueó
    t["USR02"] = [u for u in t["USR02"] if u["BNAME"] != "REPORTE1"]             # se borró
    for r in t["AGR_DEFINE"]:
        if r["AGR_NAME"] == "Z_BC_DESARROLLO":
            r["CHANGE_DAT"], r["CHANGE_USR"] = "20261104", "SEG_ADMIN"           # se modificó en PFCG
    b = run(d)
    yield db, a, b
    sv.get_engine = orig  # type: ignore[assignment]


def test_alerts_and_sap_changes_between_two_dates(pair):
    from sapsec import changes
    db, a, b = pair
    x = changes.compare(db, b, a)  # el orden de los argumentos no importa
    assert x["a"].id == a.id and x["b"].id == b.id
    new = {(r["title"], r["user"]) for r in x["new"]}
    assert ("Perfil SAP_ALL asignado", "CONTADOR1") in new
    assert any(r["user"] == "USUARIO_TEST" and r["severity"] == "critico" for r in x["new"])
    assert {(r["user"], r["rule_id"]) for r in x["resolved"]} == {("INACTIVO1", "CRIT-USR-INA-001")}
    assert [(r["user"], r["role"]) for r in x["assign_added"]] == [("USUARIO_TEST", "Z_FI_PAGOS")]
    assert x["assign_removed"] == []  # los roles de REPORTE1 no se repiten: se informa que el usuario se borró
    assert [r["user"] for r in x["users_deleted"]] == ["REPORTE1"]
    assert [r["user"] for r in x["users_locked"]] == ["INACTIVO1"] and x["users_unlocked"] == []
    assert [(r["user"], r["profile"], r["super"]) for r in x["profiles_added"]] == [("CONTADOR1", "SAP_ALL", True)]
    assert [(r["role"], r["changed_by"]) for r in x["roles_changed"]] == [("Z_BC_DESARROLLO", "SEG_ADMIN")]
    assert x["roles_new"] == [] and x["roles_deleted"] == []
    assert changes.alert_delta(db, a, b) == {"nuevas": len(x["new"]), "resueltas": 1,
                                             "nuevas_criticas": sum(1 for r in x["new"] if r["severity"] == "critico")}


def test_changes_recommendation_and_report(pair):
    from sapsec import changes
    from sapsec.advice import changes_advice
    from sapsec.reports.builders import changes_report
    from sapsec.reports.exporters import EXPORTERS
    db, a, b = pair
    x = changes.compare(db, a, b)
    adv = changes_advice(x)
    assert adv.level == "critico" and adv.headline.startswith("Revisar por qué se asignó SAP_ALL a CONTADOR1")
    assert any("RSUSR100N" in s.text for s in adv.steps)
    doc = changes_report(x, adv)
    assert [s.heading for s in doc.sections][:3] == ["Resumen", "Alertas nuevas", "Alertas resueltas"]
    rows = next(s for s in doc.sections if s.heading == "Cambios en SAP").table.rows  # type: ignore[union-attr]
    assert ["Perfil asignado a mano", "CONTADOR1", "SAP_ALL", "superusuario"] in rows
    assert any(r[0] == "Usuario borrado" and r[1] == "REPORTE1" for r in rows)
    for fmt in ("xlsx", "pdf", "csv", "html"):
        assert EXPORTERS[fmt][0](doc)


def test_only_the_same_system_can_be_compared(pair):
    from sapsec import changes
    from sapsec.storage.orm import Snapshot
    db, a, b = pair
    other = Snapshot(id=9999, connection_id=a.connection_id + 1, sid="XYZ", client="100")
    with pytest.raises(changes.ChangesError, match="mismo sistema"):
        changes.ordered(a, other)
    assert changes.previous_of(db, b).id == a.id and changes.previous_of(db, a) is None
