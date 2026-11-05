"""Conector de datos ficticios para pruebas y demostraciones sin SAP.

Emula el contrato de RFC_READ_TABLE (FIELDS con OFFSET/LENGTH, DATA-WA de ancho
fijo, OPTIONS con un subconjunto de Open SQL: ``=``, ``IN``, ``AND``), así como
BAPI_USER_GETLIST y BAPI_USER_GET_DETAIL. Los datos provienen de un JSON.

Todo lo que se obtiene con este conector se marca como DATOS DE PRUEBA.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .base import (ConnectionParams, LoadLimits, RfcAbapException, RfcAbapRuntimeError, RfcConnector,
                   RfcFunctionNotFound, RfcLogonError)

FIELD_LENGTHS = {
    "AGR_NAME": 30, "PARENT_AGR": 30, "CHILD_AGR": 30, "UNAME": 12, "BNAME": 12, "ANAME": 12,
    "CREATE_USR": 12, "CHANGE_USR": 12, "PROFILE": 12, "PROFN": 12, "SUBPROF": 12,
    "OBJCT": 10, "OBJECT": 10, "AUTH": 12, "FIELD": 10, "VON": 40, "BIS": 40, "LOW": 40,
    "HIGH": 40, "VARIANT": 30, "VARBL": 30, "TCODE": 20, "TEXT": 80, "TTEXT": 60, "LTEXT": 30,
    "COUNTER": 6, "LINE": 5, "SPRAS": 1, "SPRSL": 1, "LANGU": 1, "AKTPS": 1, "USTYP": 1,
    "CLASS": 12, "UFLAG": 3, "GLTGV": 8, "GLTGB": 8, "TRDAT": 8, "LTIME": 6, "ERDAT": 8,
    "FROM_DAT": 8, "TO_DAT": 8, "CHANGE_DAT": 8, "CREATE_DAT": 8, "ACTVT": 2, "PGMNA": 40,
    "VALUE": 40, "NAME": 40, "OBJ_NAME": 40, "TYPE": 2, "PGMID": 4, "FLAG_TYPE": 10,
    "FLAG_VALUE": 10, "OCLSS": 4, "OKFLAG": 1,
}

_IN_RE = re.compile(r"^(\w+)\s+IN\s*\((.*)\)$", re.S)
_EQ_RE = re.compile(r"^(\w+)\s*(=|EQ|<>|NE)\s*'((?:[^']|'')*)'$", re.S)


def _parse_where(options: list[dict[str, str]]) -> list[tuple[str, str, list[str]]]:
    text = " ".join(o["TEXT"] for o in options).strip()
    if not text:
        return []
    conds = []
    for part in re.split(r"\s+AND\s+", text):
        part = part.strip()
        m = _IN_RE.match(part)
        if m:
            vals = re.findall(r"'((?:[^']|'')*)'", m.group(2))
            conds.append((m.group(1), "IN", [v.replace("''", "'") for v in vals]))
            continue
        m = _EQ_RE.match(part)
        if m:
            op = "NE" if m.group(2) in ("<>", "NE") else "EQ"
            conds.append((m.group(1), op, [m.group(3).replace("''", "'")]))
            continue
        raise RfcAbapException(f"OPTION_NOT_VALID: {part}", key="OPTION_NOT_VALID")
    return conds


class FixtureConnector(RfcConnector):
    backend_name = "fixture"

    def __init__(self, params: ConnectionParams, limits: LoadLimits | None = None,
                 fixture_path: str | Path | None = None, data: dict | None = None):
        limits = limits or LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=100000)
        super().__init__(params, limits)
        if data is None:
            if fixture_path is None:
                raise ValueError("Se requiere fixture_path o data")
            data = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
        self.data = data
        self._open = False

    def open(self) -> None:
        if self.params.user.upper() in {u.upper() for u in self.data.get("logon_fail_users", [])}:
            raise RfcLogonError("Name or password is incorrect (repeat logon)", key="RFC_LOGON_FAILURE")
        self._open = True

    def close(self) -> None:
        self._open = False

    def function_exists(self, function: str) -> bool:
        return function.upper() not in {f.upper() for f in self.data.get("missing_functions", [])}

    # ---------------------------------------------------------------------------------
    def _call(self, function: str, **kwargs: Any) -> dict[str, Any]:
        if not self._open:
            self.open()
        fn = function.upper()
        if not self.function_exists(fn):
            raise RfcFunctionNotFound(f"Function module {fn} not found", key="FU_NOT_FOUND")
        if fn == "RFC_PING":
            return {}
        if fn == "RFC_SYSTEM_INFO":
            return {"RFCSI_EXPORT": self.data.get("system", {})}
        if fn == "RFC_READ_TABLE":
            return self._read_table(**kwargs)
        if fn == "BAPI_USER_GETLIST":
            users = self.data["tables"].get("USR02", [])
            return {"USERLIST": [{"USERNAME": u["BNAME"], "FULLNAME": u.get("_FULLNAME", "")} for u in users],
                    "RETURN": []}
        if fn == "BAPI_USER_GET_DETAIL":
            return self._user_detail(kwargs["USERNAME"])
        raise RfcFunctionNotFound(f"{fn} no emulado por el conector de prueba", key="FU_NOT_FOUND")

    def _read_table(self, QUERY_TABLE: str, FIELDS: list, OPTIONS: list | None = None,
                    ROWCOUNT: int = 0, ROWSKIPS: int = 0, NO_DATA: str = "", **_: Any) -> dict:
        table = QUERY_TABLE.upper()
        if table in {t.upper() for t in self.data.get("unauthorized_tables", [])}:
            raise RfcAbapException("NOT_AUTHORIZED", key="NOT_AUTHORIZED")
        if table in {t.upper() for t in self.data.get("dump_tables", [])}:
            raise RfcAbapRuntimeError("RFC_READ_TABLE: RFC_ABAP_RUNTIME_FAILURE ASSIGN_CASTING_ILLEGAL_CAST "
                                      "Error with ASSIGN ... CASTING in program SAPLSDTX", key="ASSIGN_CASTING_ILLEGAL_CAST")
        if table not in self.data["tables"]:
            raise RfcAbapException("TABLE_NOT_AVAILABLE", key="TABLE_NOT_AVAILABLE")
        rows = self.data["tables"][table]
        names = [f["FIELDNAME"].upper() for f in FIELDS]
        metas, off = [], 0
        for n in names:
            ln = FIELD_LENGTHS.get(n, 30)
            metas.append({"FIELDNAME": n, "OFFSET": f"{off:06d}", "LENGTH": f"{ln:06d}", "TYPE": "C",
                          "FIELDTEXT": n})
            off += ln
        if NO_DATA == "X":
            return {"FIELDS": metas, "DATA": []}
        conds = _parse_where(OPTIONS or [])

        def ok(r: dict) -> bool:
            for f, op, vals in conds:
                v = str(r.get(f, ""))
                if op == "EQ" and v != vals[0]:
                    return False
                if op == "NE" and v == vals[0]:
                    return False
                if op == "IN" and v not in vals:
                    return False
            return True

        selected = [r for r in rows if ok(r)]
        selected = selected[int(ROWSKIPS or 0):]
        if ROWCOUNT:
            selected = selected[: int(ROWCOUNT)]
        data = []
        for r in selected:
            wa = "".join(str(r.get(n, "")).ljust(FIELD_LENGTHS.get(n, 30))[: FIELD_LENGTHS.get(n, 30)]
                         for n in names)
            data.append({"WA": wa.rstrip()})
        return {"FIELDS": metas, "DATA": data}

    def _user_detail(self, username: str) -> dict:
        t = self.data["tables"]
        u = next((r for r in t.get("USR02", []) if r["BNAME"] == username), None)
        if u is None:
            return {"RETURN": [{"TYPE": "E", "MESSAGE": f"User {username} does not exist"}]}
        return {
            "LOGONDATA": {"USTYP": u.get("USTYP", ""), "CLASS": u.get("CLASS", ""),
                          "GLTGV": u.get("GLTGV", ""), "GLTGB": u.get("GLTGB", ""),
                          "BCODE": "0000000000000000", "PWDSALTEDHASH": "{x-issha, 1024}NOTREAL"},
            "ISLOCKED": {"LOCAL_LOCK": "L" if int(u.get("UFLAG", "0") or 0) & 64 else "U",
                         "GLOB_LOCK": "L" if int(u.get("UFLAG", "0") or 0) & 32 else "U",
                         "WRNG_LOGON": "L" if int(u.get("UFLAG", "0") or 0) & 128 else "U"},
            "ACTIVITYGROUPS": [{"AGR_NAME": a["AGR_NAME"], "FROM_DAT": a["FROM_DAT"], "TO_DAT": a["TO_DAT"]}
                               for a in t.get("AGR_USERS", []) if a["UNAME"] == username],
            "PROFILES": [{"BAPIPROF": p["PROFILE"]} for p in t.get("UST04", []) if p["BNAME"] == username],
            "RETURN": [],
        }
