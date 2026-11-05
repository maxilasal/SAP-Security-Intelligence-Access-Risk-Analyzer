"""Fixtures de prueba: sistema SAP ficticio extraído a una base SQLite temporal."""

from __future__ import annotations

import copy
import os
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_TMP = tempfile.mkdtemp(prefix="sapsec_test_")
os.environ["SAPSEC_DATABASE_URL"] = f"sqlite:///{_TMP}/test.db"
os.environ["SAPSEC_SESSION_SECRET"] = "test-secret-no-usar-en-produccion"
os.environ["SAPSEC_CONFIG"] = str(Path(_TMP) / "no-existe.yaml")
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import pytest  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from build_demo_fixture import build  # noqa: E402
from sapsec.connectors.base import ConnectionParams, LoadLimits  # noqa: E402
from sapsec.connectors.fixture_connector import FixtureConnector  # noqa: E402
from sapsec.engine.analysis import AnalysisContext  # noqa: E402
from sapsec.engine.rules import load_rules  # noqa: E402
from sapsec.extraction.extractor import Extractor  # noqa: E402
from sapsec.storage.db import make_engine  # noqa: E402
from sapsec.storage.orm import Base, SapConnection, SapSystem  # noqa: E402
from sapsec.storage.snapshot_data import SnapshotData, load_snapshot_rows  # noqa: E402

AS_OF = date(2026, 11, 4)


def fixture_data() -> dict:
    return copy.deepcopy(_BASE)


_BASE = build()


def extract(data: dict, sid: str = "DMO", env: str = "PRD", limits: LoadLimits | None = None,
            logon_source: str = "usr02_restricted"):  # type: ignore[no-untyped-def]
    engine = make_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    system = SapSystem(sid=sid, environment=env, productive=env == "PRD", sensitivity=1.0)
    db.add(system)
    db.flush()
    conn = SapConnection(system_id=system.id, client="100", name="t", backend="fixture", rfc_user="SECX",
                         user_logon_source=logon_source)
    db.add(conn)
    db.flush()
    lim = limits or LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=10 ** 6, max_rows_per_call=40,
                               batch_size_in_list=4)
    connector = FixtureConnector(ConnectionParams(client="100", user="SECX"), lim, data=data)
    snap = Extractor(connector, db, conn, "pytest").run()
    db.commit()
    return engine, db, snap, connector


@pytest.fixture(scope="session")
def extracted():  # type: ignore[no-untyped-def]
    return extract(fixture_data())


@pytest.fixture(scope="session")
def data(extracted) -> SnapshotData:  # type: ignore[no-untyped-def]
    engine, _, snap, _ = extracted
    return SnapshotData(load_snapshot_rows(engine, snap.id), snap.id)


@pytest.fixture(scope="session")
def rules():  # type: ignore[no-untyped-def]
    return load_rules(ROOT / "config" / "rules")


@pytest.fixture()
def ctx(rules) -> AnalysisContext:  # type: ignore[no-untyped-def]
    return AnalysisContext(rules, "PRD", 1.0, AS_OF)
