"""Usuarios de emergencia declarados: bloqueados = controlados; desbloqueados o con la declaración vencida = pendientes."""

from __future__ import annotations

from datetime import date, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from conftest import fixture_data
from sapsec.connectors.base import ConnectionParams, LoadLimits
from sapsec.connectors.fixture_connector import FixtureConnector
from sapsec.extraction.extractor import Extractor
from sapsec.storage.db import make_engine
from sapsec.storage.orm import Base, Finding, SapConnection, SapSystem

AS_OF = date(2026, 11, 4)
PROC = "Se desbloquea solo con un ticket aprobado por el jefe de Basis y se revisa el registro de auditoría."


@pytest.fixture()
def env(monkeypatch):  # type: ignore[no-untyped-def]
    import sapsec.services as sv
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

    def run(locked: bool = True):  # type: ignore[no-untyped-def]
        d = fixture_data()
        for u in d["tables"]["USR02"]:
            if u["BNAME"] == "ADMIN_BASIS":
                u["UFLAG"] = "64" if locked else "0"
        c = FixtureConnector(ConnectionParams(client="100", user="X"),
                             LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=10 ** 6), data=d)
        s = Extractor(c, db, conn, "pytest").run()
        db.commit()
        sv.analyze_snapshot(db, s.id, as_of=AS_OF)
        return s
    return db, conn, run


def _status(db, snap, user: str = "ADMIN_BASIS") -> dict:  # type: ignore[no-untyped-def]
    return {r: (st, auto) for r, st, auto in db.execute(select(Finding.rule_id, Finding.status, Finding.auto_status).where(
        Finding.snapshot_id == snap.id, Finding.subject_user == user))}


def _tasks(db, snap):  # type: ignore[no-untyped-def]
    from sapsec.actions import _CACHE, build_tasks
    from sapsec.services import get_rules
    _CACHE.clear()
    return build_tasks(db, snap, get_rules())


def _sap_all_task(tasks):  # type: ignore[no-untyped-def]
    return next((t for t in tasks if t.kind == "perfil" and t.profile == "SAP_ALL"), None)


def test_locked_emergency_user_is_not_pending_every_night(env):
    from sapsec import emergency
    db, conn, run = env
    s1 = run(locked=True)
    t = _sap_all_task(_tasks(db, s1))
    assert t is not None and t.pending and "ADMIN_BASIS" in t.users

    emergency.declare(db, conn.id, "ADMIN_BASIS", "Jefe de Basis", PROC, date.today() + timedelta(days=90), "pytest")
    emergency.apply_latest(db, conn.id)
    assert _status(db, s1)["CRIT-PRF-001"] == ("mitigado", "emergencia")
    tasks = _tasks(db, s1)
    assert _sap_all_task(tasks) is None  # era el único con SAP_ALL: la tarea ya no existe
    em = next(t for t in tasks if t.kind == "emergencia")
    assert not em.pending and em.users == ["ADMIN_BASIS"]
    assert em.title == "Mantener bloqueados los usuarios de emergencia"

    s2 = run(locked=True)  # la extracción de la noche siguiente: sigue controlado sin tocar nada
    assert _status(db, s2)["CRIT-PRF-001"] == ("mitigado", "emergencia")
    assert not next(t for t in _tasks(db, s2) if t.kind == "emergencia").pending
    assert s2.stats["emergencia"]["ADMIN_BASIS"]["estado"] == "controlado"


def test_unlocked_or_expired_declaration_is_pending_again(env):
    from sapsec import emergency
    from sapsec.advice import emergency_user_advice, task_advice
    db, conn, run = env
    d, created = emergency.declare(db, None, "ADMIN_BASIS", "Jefe de Basis", PROC, date.today() + timedelta(days=30),
                                   "pytest")  # para todos los sistemas
    assert created
    s1 = run(locked=False)
    assert _status(db, s1)["CRIT-PRF-001"] == ("abierto", "")
    em = next(t for t in _tasks(db, s1) if t.kind == "emergencia")
    assert em.pending
    adv = task_advice(em, None, "PRD")
    assert adv.headline == "Bloquear el usuario de emergencia ADMIN_BASIS si no hay una emergencia en curso."
    assert adv.level == "critico" and any("Jefe de Basis" in s.text for s in adv.steps)
    assert emergency_user_advice("ADMIN_BASIS", s1.stats["emergencia"]["ADMIN_BASIS"]).level == "critico"

    s2 = run(locked=True)  # lo bloquearon
    assert _status(db, s2)["CRIT-PRF-001"] == ("mitigado", "emergencia")
    d.review_by = date.today() - timedelta(days=1)  # pasó la fecha de revisión: pendiente sin esperar otra extracción
    db.commit()
    em = next(t for t in _tasks(db, s2) if t.kind == "emergencia")
    assert em.pending and _status(db, s2)["CRIT-PRF-001"] == ("abierto", "")
    assert task_advice(em, None, "PRD").headline.startswith("Renovar o quitar la declaración de ADMIN_BASIS")


def test_removing_the_declaration_restores_the_sap_all_task(env):
    from sapsec import emergency
    from sapsec.storage.orm import EmergencyUser
    db, conn, run = env
    d, _ = emergency.declare(db, conn.id, "ADMIN_BASIS", "Jefe de Basis", PROC, date.today() + timedelta(days=90),
                             "pytest")
    s1 = run(locked=True)
    assert _status(db, s1)["CRIT-PRF-001"] == ("mitigado", "emergencia")
    db.delete(d)
    db.commit()
    emergency.apply_latest(db, conn.id)
    assert _status(db, s1)["CRIT-PRF-001"] == ("abierto", "")
    t = _sap_all_task(_tasks(db, s1))
    assert t is not None and t.pending and "ADMIN_BASIS" in t.users
    assert "emergencia" not in (s1.stats or {})
    # El estado automático nunca se hereda: si la declaración desaparece entre dos extracciones, vuelve a abierto.
    d2, _ = emergency.declare(db, conn.id, "ADMIN_BASIS", "Jefe de Basis", PROC, date.today() + timedelta(days=90),
                              "pytest")
    s2 = run(locked=True)
    assert _status(db, s2)["CRIT-PRF-001"] == ("mitigado", "emergencia")
    db.execute(EmergencyUser.__table__.delete())
    db.commit()
    s3 = run(locked=True)
    assert _status(db, s3)["CRIT-PRF-001"] == ("abierto", "")


def test_decisions_taken_by_a_person_are_not_changed(env):
    from sapsec import emergency
    db, conn, run = env
    s1 = run(locked=True)
    f = db.scalars(select(Finding).where(Finding.snapshot_id == s1.id, Finding.subject_user == "ADMIN_BASIS",
                                         Finding.rule_id == "CRIT-PRF-001")).one()
    f.status, f.exception_justification = "excepcion", "Aceptado por el comité hasta la migración"
    db.commit()
    emergency.declare(db, conn.id, "ADMIN_BASIS", "Jefe de Basis", PROC, date.today() + timedelta(days=90), "pytest")
    emergency.apply_latest(db, conn.id)
    assert _status(db, s1)["CRIT-PRF-001"] == ("excepcion", "")
    s2 = run(locked=False)  # aunque se desbloquee, la excepción la decidió una persona
    assert _status(db, s2)["CRIT-PRF-001"] == ("excepcion", "")


def test_overview_candidates_and_validation(env):
    from sapsec import emergency
    db, conn, run = env
    run(locked=True)
    cands = emergency.sap_all_candidates(db)
    assert [(c["username"], c["bloqueado"]) for c in cands] == [("ADMIN_BASIS", True)]
    emergency.declare(db, conn.id, "ADMIN_BASIS", "Jefe de Basis", PROC, date.today() + timedelta(days=10), "pytest")
    emergency.declare(db, None, "FF_NO_EXISTE", "Jefe de Basis", PROC, date.today() + timedelta(days=10), "pytest")
    assert emergency.sap_all_candidates(db) == []
    rows = {r["d"].username: r for r in emergency.overview(db)}
    assert rows["ADMIN_BASIS"]["estado"] == "controlado" and rows["ADMIN_BASIS"]["dias"] == 10
    assert rows["FF_NO_EXISTE"]["estado"] == "no_existe"
    # misma persona y alcance: se actualiza, no se duplica
    d, created = emergency.declare(db, conn.id, "ADMIN_BASIS", "Seguridad", PROC, date.today() + timedelta(days=20),
                                   "otro")
    assert not created and d.responsible == "Seguridad" and d.updated_by == "otro"
    assert emergency.normalize_user(" ff_basis ") == "FF_BASIS"
    for bad in ("", "ADMIN*", "DOS PALABRAS", "UN_NOMBRE_MUY_LARGO"):
        with pytest.raises(emergency.DeclarationError):
            emergency.normalize_user(bad)
    with pytest.raises(emergency.DeclarationError, match="como máximo dentro de un año"):
        emergency.parse_review((date.today() + timedelta(days=400)).isoformat())
    with pytest.raises(emergency.DeclarationError, match="anterior a hoy"):
        emergency.parse_review((date.today() - timedelta(days=1)).isoformat())
    with pytest.raises(emergency.DeclarationError, match="responsable"):
        emergency.declare(db, conn.id, "X", " ", PROC, date.today(), "pytest")
    with pytest.raises(emergency.DeclarationError, match="procedimiento"):
        emergency.declare(db, conn.id, "X", "Alguien", "corto", date.today(), "pytest")
