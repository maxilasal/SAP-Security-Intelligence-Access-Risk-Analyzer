"""Varios sistemas: huella del sistema, retención de snapshots."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from conftest import fixture_data
from sapsec.connectors.base import ConnectionParams, LoadLimits
from sapsec.connectors.fixture_connector import FixtureConnector
from sapsec.extraction.extractor import Extractor, system_fingerprint
from sapsec.storage.db import make_engine
from sapsec.storage.orm import Base, SapConnection, SapSystem, Snapshot


def _env():  # type: ignore[no-untyped-def]
    engine = make_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    system = SapSystem(sid="DMO", name="PRD Uruguay", environment="PRD", productive=True)
    db.add(system)
    db.flush()
    conn = SapConnection(system_id=system.id, client="100", name="t", backend="fixture", rfc_user="X")
    db.add(conn)
    db.commit()
    return engine, db, conn


def _run(db, conn, data):  # type: ignore[no-untyped-def]
    c = FixtureConnector(ConnectionParams(client="100", user="X"),
                         LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=10 ** 6), data=data)
    snap = Extractor(c, db, conn, "pytest").run()
    db.commit()
    return snap


def test_fingerprint_registered_and_mismatch_cancels():
    engine, db, conn = _env()
    data = fixture_data()
    s1 = _run(db, conn, data)
    assert s1.status == "completo"
    assert conn.fingerprint == system_fingerprint(data["system"]) == "DMO|DEMO-HOST|HDB"
    other = fixture_data()
    other["system"]["RFCHOST"] = "otro-servidor"  # mismo SID, otro sistema
    s2 = _run(db, conn, other)
    assert s2.status == "error"
    assert "sistema distinto" in s2.issues[0]["message"]
    conn.fingerprint = ""  # restablecer huella (migración legítima)
    db.commit()
    assert _run(db, conn, other).status == "completo"


def test_retention_keeps_last_n(monkeypatch):
    import sapsec.services as sv
    engine, db, conn = _env()
    ids = [_run(db, conn, fixture_data()).id for _ in range(4)]
    removed = sv.prune_snapshots(db, conn.id, keep=2)
    assert removed == 2
    left = list(db.scalars(select(Snapshot.id).order_by(Snapshot.id)))
    assert left == ids[-2:]
    assert sv.prune_snapshots(db, conn.id, keep=0) == 0


def test_same_sid_two_systems_allowed():
    engine, db, conn = _env()
    db.add(SapSystem(sid="DMO", name="PRD Argentina", environment="PRD"))
    db.commit()
    assert db.scalar(select(func.count()).select_from(SapSystem).where(SapSystem.sid == "DMO")) == 2
