"""Motor y sesiones de base de datos."""

from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..config import get_settings
from .orm import Base


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        # timeout: si otra operación está escribiendo, esperar hasta 60 s en lugar de fallar ("database is locked")
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 60})

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _):  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=60000")
            cur.close()
        return engine
    return create_engine(url, pool_pre_ping=True)


@lru_cache
def get_engine() -> Engine:
    return make_engine(get_settings().database_url)


@lru_cache
def _factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def init_db(engine: Engine | None = None) -> None:
    from .migrate import migrate
    eng = engine or get_engine()
    migrate(eng)
    Base.metadata.create_all(eng)


@contextmanager
def session_scope() -> Iterator[Session]:
    s = _factory()()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_session() -> Iterator[Session]:
    """Dependencia FastAPI."""
    with session_scope() as s:
        yield s
