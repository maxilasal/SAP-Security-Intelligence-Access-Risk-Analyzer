"""Orquestación de la extracción de un snapshot de seguridad (solo lectura).

Principios:
* Selección dirigida: primero se obtienen las claves (usuarios, roles, perfiles,
  objetos) y luego solo los datos relacionados, por lotes.
* Cada dataset registra método, filas, llamadas y estado; un fallo de
  autorización no aborta todo el snapshot sino que lo marca como incompleto.
* Validación cruzada por muestreo con BAPI_USER_GET_DETAIL (API liberada).
* Verificación de identidad del sistema (SID/mandante) antes de guardar datos.
"""

from __future__ import annotations

import logging
import random
from datetime import datetime
from typing import Iterable

from sqlalchemy import insert
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..connectors.base import (RfcAbapException, RfcAuthorizationError, RfcCommunicationError, RfcConnector,
                               RfcError, RfcFunctionNotFound, RfcLogonError)
from ..connectors.table_reader import TableAccessDenied, TableReader
from ..storage.orm import SAP_TABLES, SapConnection, Snapshot, utcnow
from .sources import DATASETS_BY_NAME, DatasetStats

log = logging.getLogger(__name__)


class SystemIdentityMismatch(RfcError):
    pass


def system_fingerprint(info: dict) -> str:
    """Huella estable del sistema: SID | host de base de datos | motor de BD (no depende del servidor de
    aplicación, que puede variar con balanceo de carga)."""
    sid = (info.get("RFCSYSID") or "").strip().upper()
    host = (info.get("RFCDBHOST") or info.get("RFCHOST") or "").strip().upper()
    dbsys = (info.get("RFCDBSYS") or "").strip().upper()
    return f"{sid}|{host}|{dbsys}" if sid else ""


class Extractor:
    def __init__(self, connector: RfcConnector, session: Session, connection: SapConnection,
                 started_by: str, settings: Settings | None = None):
        self.conn = connector
        self.db = session
        self.connection = connection
        self.started_by = started_by
        self.settings = settings or get_settings()
        self.reader = TableReader(connector)
        self.stats: dict[str, DatasetStats] = {}
        self.issues: list[dict] = []
        self.snapshot: Snapshot | None = None
        self._cache: dict[str, list[dict[str, str]]] = {}
        self.progress = lambda msg: None  # callback opcional (UI / CLI)

    def _step(self, msg: str) -> None:
        log.info(msg)
        self.progress(msg)

    # ---------------------------------------------------------------------------------
    def run(self) -> Snapshot:
        sys_ = self.connection.system
        snap = Snapshot(connection_id=self.connection.id, sid=sys_.sid, client=self.connection.client,
                        backend=self.conn.backend_name, started_by=self.started_by,
                        is_test_data=self.conn.backend_name == "fixture")
        self.db.add(snap)
        self.db.commit()
        self.snapshot = snap
        try:
            self.conn.open()
            info = self.conn.system_info()
            snap.system_info = info
            sid = info.get("RFCSYSID", "")
            if sid and sid.upper() != sys_.sid.upper():
                raise SystemIdentityMismatch(
                    f"El sistema conectado es {sid}, pero la conexión está registrada para {sys_.sid}. "
                    "Extracción cancelada para evitar datos mal atribuidos.")
            fp = system_fingerprint(info)
            if self.connection.fingerprint and fp and self.connection.fingerprint != fp:
                raise SystemIdentityMismatch(
                    f"La conexión «{self.connection.name}» apunta a un sistema distinto del registrado "
                    f"(antes: {self.connection.fingerprint}; ahora: {fp}). Puede haber dos sistemas con el mismo "
                    "SID. Extracción cancelada. Si el cambio es correcto (p. ej. migración de servidor), "
                    "restablezca la huella en Conexiones SAP.")
            if fp and not self.connection.fingerprint:
                self.connection.fingerprint = fp
                self.db.commit()
            self._extract_all()
            self._validate_sample()
            required_failed = [n for n, s in self.stats.items()
                               if DATASETS_BY_NAME.get(n) and DATASETS_BY_NAME[n].required and s.status != "ok"]
            mismatches = self.stats.get("_validacion", DatasetStats("_validacion")).extra.get("diferencias", 0)
            snap.status = "completo" if not required_failed and not mismatches else "incompleto"
            if required_failed:
                self.issues.append({"code": "DATASET_INCOMPLETO", "message":
                                    "Datasets obligatorios sin datos completos: " + ", ".join(required_failed)})
        except Exception as exc:  # noqa: BLE001 - se registra y se propaga el estado
            log.exception("Extracción fallida")
            snap.status = "error"
            self.issues.append({"code": "ERROR_EXTRACCION", "message": str(exc)})
        finally:
            self.conn.close()
            snap.finished_at = utcnow()
            snap.stats = {k: vars(v) for k, v in self.stats.items()}
            snap.stats["_rfc_calls"] = {"calls": self.conn.call_count,
                                        "truncation_events": self.reader.truncation_events}
            snap.issues = self.issues
            self.db.flush()
        return snap

    # ---------------------------------------------------------------------------------
    def _extract_all(self) -> None:
        langs = self.settings.languages
        self._product()
        users = self._extract_users()
        self._full("agr_define")
        self._full("agr_texts", extra_where=self._in_clause("SPRAS", langs))
        self._full("agr_flags")
        self._full("agr_agrs")
        self._full("agr_1016")
        roles = [r["AGR_NAME"] for r in self._cache.get("agr_define", [])]
        self._partitioned("agr_users", "UNAME", users)
        self._partitioned("agr_1251", "AGR_NAME", roles)
        self._partitioned("agr_1252", "AGR_NAME", roles)
        self._partitioned("agr_tcodes", "AGR_NAME", roles)
        self._partitioned("ust04", "BNAME", users)

        # Perfiles relevantes: asignados + generados + expansión de compuestos
        profiles = {r["PROFILE"] for r in self._cache.get("ust04", [])}
        profiles |= {r["PROFILE"] for r in self._cache.get("agr_1016", [])}
        profiles |= {"SAP_ALL", "SAP_NEW"}  # referencia para equivalencia a SAP_ALL
        seen: set[str] = set()
        pending = set(profiles)
        while pending:
            batch = sorted(pending - seen)
            seen |= set(batch)
            rows = self._partitioned("ust10c", "PROFN", batch, append=True)
            pending = {r["SUBPROF"] for r in rows} - seen
        self._partitioned("ust10s", "PROFN", sorted(seen))
        rule_tcodes, rule_objects = self._rule_references()
        objects = sorted({r["OBJCT"] for r in self._cache.get("ust10s", [])}
                         | {r["OBJECT"] for r in self._cache.get("agr_1251", [])} | rule_objects)
        self._partitioned("ust12", "OBJCT", [o for o in objects if o])
        self._partitioned("tobj", "OBJCT", objects)
        self._partitioned("tobjt", "OBJECT", objects, extra_where=self._in_clause("LANGU", langs))
        self._full("tact", extra_where=self._in_clause("SPRAS", langs))

        tcodes = {r["TCODE"] for r in self._cache.get("agr_tcodes", []) if r.get("TYPE") in ("TR", "")}
        tcodes |= {r["VON"] for r in self._cache.get("ust12", [])
                   if r["OBJCT"] == "S_TCODE" and r["FIELD"] == "TCD" and "*" not in r["VON"] and not r["BIS"]}
        tcodes |= {r["LOW"] for r in self._cache.get("agr_1251", [])
                   if r["OBJECT"] == "S_TCODE" and "*" not in r["LOW"] and not r["HIGH"]}
        tcodes |= rule_tcodes
        tcodes = {t for t in tcodes if t and not t.startswith("$")}
        self._partitioned("tstc", "TCODE", sorted(tcodes))
        self._partitioned("tstct", "TCODE", sorted(tcodes), extra_where=self._in_clause("SPRSL", langs))
        self._partitioned("tstca", "TCODE", sorted(tcodes))
        # SU24 del propio sistema para las transacciones de las reglas (validación de reglas)
        self._partitioned("usobx_c", "NAME", sorted(rule_tcodes), extra_where="TYPE = 'TR'")
        self._partitioned("usobt_c", "NAME", sorted(rule_tcodes), extra_where="TYPE = 'TR'")
        release = (self.snapshot.system_info or {}).get("RFCSAPRL", "") if self.snapshot else ""
        if release.isdigit() and int(release) < 740:
            # En SAP_BASIS < 7.40 RFC_READ_TABLE produce un dump con USOBHASH y no suele haber Fiori.
            st = self.stats.setdefault("usobhash", DatasetStats("usobhash"))
            st.status, st.method = "omitido", "No aplica"
            st.message = f"Omitido en SAP_BASIS {release} (< 7.40): sin Fiori/OData relevante y evita un dump conocido."
            return
        services = [r for r in self._cache.get("ust12", []) if r["OBJCT"] == "S_SERVICE" and r["FIELD"] == "SRV_NAME"]
        hashes = {r["VON"] for r in services if "*" not in r["VON"]}
        self._partitioned("usobhash", "NAME", sorted(hashes))
        if services and rule_objects:
            # Fiori/OData: qué servicios verifican (SU24 del propio sistema) los objetos de negocio de las reglas.
            # Así un conflicto SoD se detecta aunque la persona lo haga desde una app Fiori y no por transacción.
            objs = sorted(rule_objects - {"S_TCODE", "S_SERVICE"})
            self._partitioned("usobx_c", "OBJECT", objs, extra_where="TYPE = 'HT'")
            self._partitioned("usobt_c", "OBJECT", objs, extra_where="TYPE = 'HT' AND FIELD = 'ACTVT'")

    def _product(self) -> None:
        """Producto (S/4HANA, ECC, front-end Fiori) según CVERS; se guarda con el snapshot."""
        from ..domain.product import describe
        rows = self._full("cvers")
        info = describe(rows)
        if info and self.snapshot is not None:
            self.snapshot.system_info = {**(self.snapshot.system_info or {}), "PRODUCTO": info}
            self.db.commit()

    def _rule_references(self) -> tuple[set[str], set[str]]:
        """Transacciones y objetos citados por las reglas (para leerlos aunque ningún rol los tenga)."""
        try:
            from ..engine.rules import load_rules
            rs = load_rules(self.settings.rules_dir)
        except Exception as exc:  # noqa: BLE001 - la extracción no depende de las reglas
            log.warning("No se pudieron cargar las reglas para la extracción: %s", exc)
            return set(), set()
        tcodes = {t for r in rs.critical for t in r.tcodes}
        objects = {q.object for r in rs.critical for q in r.requirements}
        for f in rs.functions.values():
            for a in f.actions:
                tcodes |= set(a.tcodes)
                objects |= {q.object for q in a.requirements}
        return tcodes, objects

    @staticmethod
    def _in_clause(field: str, values: Iterable[str]) -> str:
        vals = ", ".join(f"'{v}'" for v in values)
        return f"{field} IN ( {vals} )"

    # ---------------------------------------------------------------------------------
    def _extract_users(self) -> list[str]:
        self._step("Leyendo usuarios")
        st = self.stats.setdefault("usr02", DatasetStats("usr02"))
        names: dict[str, str] = {}
        try:
            res = self.conn.call("BAPI_USER_GETLIST", MAX_ROWS=0, WITH_USERNAME="X")
            for u in res.get("USERLIST", []):
                names[u["USERNAME"].strip()] = (u.get("FULLNAME", "") or "").strip()
            st.method = "BAPI_USER_GETLIST"
        except (RfcAuthorizationError, RfcAbapException, RfcFunctionNotFound) as exc:
            self.issues.append({"code": "USERLIST_NO_DISPONIBLE", "message": str(exc)})
        source = self.connection.user_logon_source
        rows: list[dict[str, str]] = []
        try:
            if source == "usr02_restricted":
                ds = DATASETS_BY_NAME["usr02"]
                if names:
                    for chunk in self.reader.read_partitioned(ds.table, ds.fields, "BNAME", names):
                        rows += chunk
                        st.calls += 1
                else:
                    rows = self.reader.read(ds.table, ds.fields)
                st.method += " + RFC_READ_TABLE(USR02, campos restringidos)"
            else:
                rows = self._users_via_bapi(sorted(names))
                st.method += " + BAPI_USER_GET_DETAIL"
                self.issues.append({"code": "SIN_ULTIMO_ACCESO", "message":
                                    "Modo BAPI: el último acceso (USR02-TRDAT) no está disponible."})
            st.status = "ok"
        except (RfcAuthorizationError, TableAccessDenied) as exc:
            st.status, st.message = "sin_autorizacion", str(exc)
            rows = [{"BNAME": n} for n in names]
        except RfcError as exc:
            st.status, st.message = "error", str(exc)
        include_name = self.settings.include_user_fullname
        for r in rows:
            r["FULLNAME"] = names.get(r["BNAME"], "") if include_name else ""
        st.rows = len(rows)
        self._store("usr02", rows)
        return [r["BNAME"] for r in rows]

    def _users_via_bapi(self, names: list[str]) -> list[dict[str, str]]:
        rows = []
        for n in names:
            d = self.conn.call("BAPI_USER_GET_DETAIL", USERNAME=n)
            lg, lk = d.get("LOGONDATA", {}), d.get("ISLOCKED", {})
            flag = (64 if lk.get("LOCAL_LOCK") == "L" else 0) | (32 if lk.get("GLOB_LOCK") == "L" else 0) \
                | (128 if lk.get("WRNG_LOGON") == "L" else 0)
            rows.append({"BNAME": n, "USTYP": lg.get("USTYP", ""), "CLASS": lg.get("CLASS", ""),
                         "GLTGV": lg.get("GLTGV", ""), "GLTGB": lg.get("GLTGB", ""), "UFLAG": str(flag),
                         "TRDAT": "", "LTIME": "", "ERDAT": "", "ANAME": ""})
        return rows

    def _full(self, name: str, extra_where: str | None = None) -> list[dict[str, str]]:
        ds = DATASETS_BY_NAME[name]
        self._step(f"Leyendo {ds.table}")
        st = self.stats.setdefault(name, DatasetStats(name, method=f"RFC_READ_TABLE({ds.table})"))
        where = list(ds.fixed_where) + ([extra_where] if extra_where else [])
        try:
            rows = self.reader.read(ds.table, ds.fields, where)
            st.status = "ok"
        except (RfcAuthorizationError, TableAccessDenied) as exc:
            rows, st.status, st.message = [], "sin_autorizacion", str(exc)
        except (RfcCommunicationError, RfcLogonError):
            raise
        except RfcError as exc:
            rows, st.status, st.message = [], "error", self._explain(ds.table, exc)
            self.issues.append({"code": "DATASET_ERROR", "message": f"{ds.table}: {st.message}"})
        st.rows, st.calls = len(rows), st.calls + 1
        self._store(name, rows)
        return rows

    def _partitioned(self, name: str, key: str, keys: Iterable[str], extra_where: str | None = None,
                     append: bool = False) -> list[dict[str, str]]:
        ds = DATASETS_BY_NAME[name]
        self._step(f"Leyendo {ds.table}")
        st = self.stats.setdefault(name, DatasetStats(name, method=f"RFC_READ_TABLE({ds.table}) por lotes de {key}"))
        where = list(ds.fixed_where) + ([extra_where] if extra_where else [])
        rows: list[dict[str, str]] = []
        keys = list(keys)
        if not keys:
            if st.status == "pendiente":
                st.status = "ok"
                st.message = "Sin claves para consultar"
            return rows
        try:
            for chunk in self.reader.read_partitioned(ds.table, ds.fields, key, keys, where):
                rows += chunk
                st.calls += 1
            if st.status in ("pendiente", "ok"):
                st.status = "ok"
        except (RfcAuthorizationError, TableAccessDenied) as exc:
            st.status, st.message = "sin_autorizacion", str(exc)
        except (RfcCommunicationError, RfcLogonError):
            raise
        except RfcError as exc:
            # p. ej. dump de RFC_READ_TABLE (ASSIGN_CASTING_ILLEGAL_CAST) en esta tabla: se registra y se sigue
            st.status, st.message = "error", self._explain(ds.table, exc)
            self.issues.append({"code": "DATASET_ERROR", "message": f"{ds.table}: {st.message}"})
        st.rows += len(rows)
        self._store(name, rows)
        return rows

    @staticmethod
    def _explain(table: str, exc: RfcError) -> str:
        msg = str(exc)
        if "ASSIGN_CASTING_ILLEGAL_CAST" in msg or "SAPLSDTX" in msg:
            return (f"RFC_READ_TABLE produjo un dump en SAP al leer {table} (limitación conocida de esa función con "
                    "tablas que tienen campos no textuales). El resto de la extracción continuó. Ver ST22. "
                    f"Detalle: {msg}")
        return msg

    def _store(self, name: str, rows: list[dict[str, str]]) -> None:
        self._cache.setdefault(name, []).extend(rows)
        if not rows or self.snapshot is None:
            return
        table = SAP_TABLES[name]
        cols = {c.name for c in table.columns}
        payload = [{"snapshot_id": self.snapshot.id,
                    **{k.lower(): (v or "") for k, v in r.items() if k.lower() in cols}} for r in rows]
        for i in range(0, len(payload), 5000):
            self.db.execute(insert(table), payload[i:i + 5000])
            # Confirmar por bloques: SQLite admite un solo escritor; así la interfaz no queda bloqueada.
            self.db.commit()

    # ---------------------------------------------------------------------------------
    def _validate_sample(self) -> None:
        """Compara una muestra de usuarios contra BAPI_USER_GET_DETAIL (fuente liberada)."""
        self._step("Validación cruzada con BAPI_USER_GET_DETAIL")
        st = DatasetStats("_validacion", method="Muestreo BAPI_USER_GET_DETAIL")
        self.stats["_validacion"] = st
        users = [r["BNAME"] for r in self._cache.get("usr02", [])]
        if not users:
            st.status = "omitido"
            return
        rnd = random.Random(datetime.now().toordinal())
        sample = rnd.sample(users, min(self.settings.analysis.validation_sample_size, len(users)))
        diffs = []
        try:
            for u in sample:
                d = self.conn.call("BAPI_USER_GET_DETAIL", USERNAME=u)
                bapi_roles = {a["AGR_NAME"].strip() for a in d.get("ACTIVITYGROUPS", [])}
                tab_roles = {r["AGR_NAME"] for r in self._cache.get("agr_users", []) if r["UNAME"] == u}
                bapi_prof = {p["BAPIPROF"].strip() for p in d.get("PROFILES", [])}
                tab_prof = {r["PROFILE"] for r in self._cache.get("ust04", []) if r["BNAME"] == u}
                if bapi_roles != tab_roles or bapi_prof != tab_prof:
                    diffs.append({"usuario": u,
                                  "roles_solo_bapi": sorted(bapi_roles - tab_roles),
                                  "roles_solo_tabla": sorted(tab_roles - bapi_roles),
                                  "perfiles_solo_bapi": sorted(bapi_prof - tab_prof),
                                  "perfiles_solo_tabla": sorted(tab_prof - bapi_prof)})
            st.status = "ok" if not diffs else "incompleto"
            st.rows = len(sample)
            st.extra = {"muestra": len(sample), "diferencias": len(diffs), "detalle": diffs[:50]}
            if diffs:
                self.issues.append({"code": "VALIDACION_DIFERENCIAS",
                                    "message": f"{len(diffs)} usuarios difieren entre tablas y BAPI"})
        except RfcError as exc:
            st.status, st.message = "omitido", f"No se pudo validar: {exc}"
