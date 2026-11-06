"""Migraciones livianas e idempotentes del esquema (sin herramientas externas).

Se ejecutan al iniciar (``init_db``) y actualizan bases creadas con versiones anteriores:

1. ``sap_system.name``: nombre del sistema (permite SID repetidos entre landscapes).
2. Elimina la restricción de SID único de ``sap_system``.
3. ``sap_connection.fingerprint``: huella del sistema real.
4. ``app_user.last_failed_at``: bloqueo temporal tras intentos fallidos.
5. ``sap_system.landscape``: grupo de sistemas que comparten transportes (DEV → QA → PRD).
6. ``finding.auto_status``: estado fijado automáticamente (usuarios de emergencia declarados).
7. ``app_user.theme``: tema de colores elegido por cada persona.
"""

from __future__ import annotations

import logging

from sqlalchemy import inspect
from sqlalchemy.engine import Engine
from sqlalchemy.schema import CreateTable

log = logging.getLogger(__name__)


def _columns(engine: Engine, table: str) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns(table)}


def _sid_is_unique(engine: Engine) -> bool:
    insp = inspect(engine)
    for u in insp.get_unique_constraints("sap_system"):
        if u.get("column_names") == ["sid"]:
            return True
    return any(ix.get("unique") and ix.get("column_names") == ["sid"] for ix in insp.get_indexes("sap_system"))


def migrate(engine: Engine) -> None:
    from .orm import Base
    tables = set(inspect(engine).get_table_names())
    if "sap_system" in tables:
        if "name" not in _columns(engine, "sap_system"):
            with engine.begin() as c:
                c.exec_driver_sql("ALTER TABLE sap_system ADD COLUMN name VARCHAR(100) DEFAULT '' NOT NULL")
            log.info("Migración: agregada sap_system.name")
        if _sid_is_unique(engine):
            if engine.dialect.name == "sqlite":
                _rebuild_sqlite(engine, "sap_system", Base.metadata.tables["sap_system"])
            else:
                with engine.begin() as c:
                    c.exec_driver_sql("ALTER TABLE sap_system DROP CONSTRAINT IF EXISTS uq_system_sid")
            log.info("Migración: el SID ya no es único (se identifica al sistema por su nombre)")
    if "sap_connection" in tables and "fingerprint" not in _columns(engine, "sap_connection"):
        with engine.begin() as c:
            c.exec_driver_sql("ALTER TABLE sap_connection ADD COLUMN fingerprint VARCHAR(300) DEFAULT '' NOT NULL")
        log.info("Migración: agregada sap_connection.fingerprint")
    if "sap_system" in tables and "landscape" not in _columns(engine, "sap_system"):
        with engine.begin() as c:
            c.exec_driver_sql("ALTER TABLE sap_system ADD COLUMN landscape VARCHAR(100) DEFAULT '' NOT NULL")
        log.info("Migración: agregada sap_system.landscape")
    if "finding" in tables and "auto_status" not in _columns(engine, "finding"):
        with engine.begin() as c:
            c.exec_driver_sql("ALTER TABLE finding ADD COLUMN auto_status VARCHAR(20) DEFAULT '' NOT NULL")
        log.info("Migración: agregada finding.auto_status")
    if "app_user" in tables and "theme" not in _columns(engine, "app_user"):
        with engine.begin() as c:
            c.exec_driver_sql("ALTER TABLE app_user ADD COLUMN theme VARCHAR(20) DEFAULT '' NOT NULL")
        log.info("Migración: agregada app_user.theme")
    if "app_user" in tables and "last_failed_at" not in _columns(engine, "app_user"):
        with engine.begin() as c:
            c.exec_driver_sql("ALTER TABLE app_user ADD COLUMN last_failed_at TIMESTAMP NULL")
        log.info("Migración: agregada app_user.last_failed_at")


def _rebuild_sqlite(engine: Engine, name: str, table) -> None:  # type: ignore[no-untyped-def]
    """SQLite no permite quitar restricciones: se recrea la tabla conservando los datos."""
    cols = [c.name for c in table.columns]
    ddl = str(CreateTable(table).compile(engine)).replace(f"CREATE TABLE {name}", f"CREATE TABLE {name}__new", 1)
    raw = engine.raw_connection()
    try:
        cur = raw.cursor()
        cur.execute("PRAGMA foreign_keys=OFF")
        cur.execute("BEGIN")
        cur.execute(ddl)
        col_list = ", ".join(cols)
        cur.execute(f"INSERT INTO {name}__new ({col_list}) SELECT {col_list} FROM {name}")
        cur.execute(f"DROP TABLE {name}")
        cur.execute(f"ALTER TABLE {name}__new RENAME TO {name}")
        raw.commit()
        cur.execute("PRAGMA foreign_keys=ON")
    except Exception:
        raw.rollback()
        raise
    finally:
        raw.close()
