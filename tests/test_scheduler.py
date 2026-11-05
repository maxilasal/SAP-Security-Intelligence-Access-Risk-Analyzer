"""Extracciones programadas: cuándo corresponde, reclamo atómico y ejecución."""

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from conftest import ROOT
from sapsec.scheduler import (claim, describe_when, due_slot, execute, matching_connections, next_run,
                              run_due_inline)
from sapsec.storage.db import make_engine
from sapsec.storage.orm import Base, ExtractionSchedule, SapConnection, SapSystem, Snapshot

MON_0310 = datetime(2026, 11, 2, 3, 10)   # lunes


def test_due_window_days_and_midnight():
    s = ExtractionSchedule(name="x", enabled=True, time_hhmm="03:00", days="0,1,2,3,4,5,6")
    assert due_slot(s, MON_0310) == datetime(2026, 11, 2, 3, 0)
    s.last_slot = datetime(2026, 11, 2, 3, 0)
    assert due_slot(s, MON_0310) is None                       # ya ejecutada
    s.last_slot = None
    assert due_slot(s, datetime(2026, 11, 2, 7, 0)) is None     # fuera de la ventana de 3 h
    assert due_slot(s, datetime(2026, 11, 2, 2, 59)) is None    # todavía no es la hora
    tue = ExtractionSchedule(name="x", enabled=True, time_hhmm="03:00", days="1")  # solo martes
    assert due_slot(tue, MON_0310) is None
    late = ExtractionSchedule(name="x", enabled=True, time_hhmm="23:30", days="0")  # lunes 23:30
    assert due_slot(late, datetime(2026, 11, 3, 0, 10)) == datetime(2026, 11, 2, 23, 30)
    assert next_run(s, MON_0310) == datetime(2026, 11, 3, 3, 0)
    assert describe_when(s) == "Todos los días a las 03:00"
    assert describe_when(ExtractionSchedule(time_hhmm="02:30", days="0,1,2,3,4")) == "De lunes a viernes a las 02:30"
    paused = ExtractionSchedule(name="x", enabled=False, time_hhmm="03:00", days="0")
    assert due_slot(paused, MON_0310) is None


def _setup(monkeypatch):  # type: ignore[no-untyped-def]
    import sapsec.services as sv
    engine = make_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(sv, "get_engine", lambda: engine)
    db = Session(engine, expire_on_commit=False)
    fx = str(ROOT / "tests" / "fixtures" / "demo_system.json")
    for name, env, client in (("PRD Uruguay", "PRD", "100"), ("PRD Argentina", "PRD", "300"), ("DEV Uruguay", "DEV", "200")):
        s = SapSystem(sid="DMO", name=name, environment=env)
        db.add(s)
        db.flush()
        db.add(SapConnection(system_id=s.id, client=client, name=name, backend="fixture", rfc_user="X", fixture_path=fx))
    db.commit()
    return engine, db


def test_claim_is_atomic_and_execute_extracts_matching_systems(monkeypatch):
    engine, db = _setup(monkeypatch)
    sch = ExtractionSchedule(name="PRD de madrugada", time_hhmm="03:00", days="0,1,2,3,4,5,6", environment="PRD")
    db.add(sch)
    db.commit()
    assert [c.system.name for c in matching_connections(db, sch)] == ["PRD Uruguay", "PRD Argentina"]
    slot = datetime(2026, 11, 2, 3, 0)
    assert claim(db, sch.id, slot) is True
    assert claim(db, sch.id, slot) is False        # la misma franja no corre dos veces
    res = execute(db, sch.id, "prueba")
    assert [r["estado"] for r in res] == ["completo", "completo"]
    sch = db.get(ExtractionSchedule, sch.id)
    assert sch.state == "terminado" and len(sch.last_result) == 2 and sch.finished_at
    assert db.scalar(select(func.count()).select_from(Snapshot)) == 2   # el DEV no se tocó


def test_run_due_inline_runs_only_due(monkeypatch):
    engine, db = _setup(monkeypatch)
    now = datetime.now()
    due = ExtractionSchedule(name="vencida", time_hhmm=(now - timedelta(minutes=5)).strftime("%H:%M"),
                             days="0,1,2,3,4,5,6", environment="DEV")
    later = ExtractionSchedule(name="más tarde", time_hhmm=(now + timedelta(hours=1)).strftime("%H:%M"),
                               days="0,1,2,3,4,5,6", environment="PRD")
    db.add_all([due, later])
    db.commit()
    if (now - timedelta(minutes=5)).date() != now.date():
        return  # justo en la medianoche: el caso se cubre en test_due_window_days_and_midnight

    class _Ctx:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return db

        def __exit__(self, *a):  # type: ignore[no-untyped-def]
            db.commit()
    assert run_due_inline(lambda: _Ctx(), "prueba") == 1
    assert run_due_inline(lambda: _Ctx(), "prueba") == 0   # ya reclamada
    assert db.get(ExtractionSchedule, due.id).state == "terminado"
    assert db.get(ExtractionSchedule, later.id).state == ""
