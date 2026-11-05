"""Vista en memoria e indexada de un snapshot inmutable.

Para el MVP el snapshot se carga completo en memoria (adecuado para decenas de
miles de usuarios y algunos millones de valores). La fase 4 prevé consultas
directas en PostgreSQL o un almacén columnar para volúmenes mayores.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime
import threading
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.engine import Engine

from ..domain.models import RoleAssignment, UserInfo
from ..engine.values import AuthInstance, FieldValue
from .orm import SAP_TABLES


def parse_date(value: str | None) -> date | None:
    if not value or value.strip() in ("", "00000000"):
        return None
    try:
        return datetime.strptime(value.strip(), "%Y%m%d").date()
    except ValueError:
        return None


class SnapshotData:
    def __init__(self, rows: dict[str, list[dict[str, str]]], snapshot_id: int = 0):
        self.snapshot_id = snapshot_id
        self.rows = rows
        r = rows
        self.users: dict[str, UserInfo] = {}
        for u in r.get("usr02", []):
            self.users[u["bname"]] = UserInfo(
                username=u["bname"], user_type=u.get("ustyp", ""), user_group=u.get("class", ""),
                valid_from=parse_date(u.get("gltgv")), valid_to=parse_date(u.get("gltgb")),
                lock_flag=int(u.get("uflag") or 0), last_logon=parse_date(u.get("trdat")),
                full_name=u.get("fullname", ""))

        self.role_names: set[str] = {x["agr_name"] for x in r.get("agr_define", [])}
        self.role_parent: dict[str, str] = {x["agr_name"]: x.get("parent_agr", "")
                                            for x in r.get("agr_define", []) if x.get("parent_agr")}
        self.role_meta: dict[str, dict[str, str]] = {x["agr_name"]: x for x in r.get("agr_define", [])}
        self.role_text: dict[str, str] = {}
        for t in sorted(r.get("agr_texts", []), key=lambda x: 0 if x.get("spras") == "S" else 1):
            self.role_text.setdefault(t["agr_name"], t.get("text", ""))
        self.composite_children: dict[str, list[str]] = defaultdict(list)
        for x in r.get("agr_agrs", []):
            self.composite_children[x["agr_name"]].append(x["child_agr"])
        self.composite_flag: set[str] = {x["agr_name"] for x in r.get("agr_flags", [])
                                         if x.get("flag_type") == "COLL_AGR" and x.get("flag_value") == "X"}
        self.role_profiles: dict[str, list[str]] = defaultdict(list)
        self.profile_role: dict[str, str] = {}
        for x in r.get("agr_1016", []):
            self.role_profiles[x["agr_name"]].append(x["profile"])
            self.profile_role[x["profile"]] = x["agr_name"]
        self.role_values: dict[str, list[dict[str, str]]] = defaultdict(list)
        for x in r.get("agr_1251", []):
            self.role_values[x["agr_name"]].append(x)
        self.role_org: dict[str, list[dict[str, str]]] = defaultdict(list)
        for x in r.get("agr_1252", []):
            self.role_org[x["agr_name"]].append(x)
        self.role_menu: dict[str, list[dict[str, str]]] = defaultdict(list)
        for x in r.get("agr_tcodes", []):
            self.role_menu[x["agr_name"]].append(x)
        self.user_roles_raw: dict[str, list[dict[str, str]]] = defaultdict(list)
        self.role_users_raw: dict[str, list[dict[str, str]]] = defaultdict(list)
        for x in r.get("agr_users", []):
            self.user_roles_raw[x["uname"]].append(x)
            self.role_users_raw[x["agr_name"]].append(x)
        self.user_profiles: dict[str, list[str]] = defaultdict(list)
        self.profile_users: dict[str, set[str]] = defaultdict(set)
        for x in r.get("ust04", []):
            self.user_profiles[x["bname"]].append(x["profile"])
            self.profile_users[x["profile"]].add(x["bname"])
        self.subprofiles: dict[str, list[str]] = defaultdict(list)
        for x in r.get("ust10c", []):
            self.subprofiles[x["profn"]].append(x["subprof"])
        self.profile_auths: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for x in r.get("ust10s", []):
            self.profile_auths[x["profn"]].append((x["objct"], x["auth"]))
        vals: dict[tuple[str, str], dict[str, list[FieldValue]]] = defaultdict(lambda: defaultdict(list))
        for x in r.get("ust12", []):
            vals[(x["objct"], x["auth"])][x["field"]].append(FieldValue(x.get("von", ""), x.get("bis", "")))
        self.auth_values = vals
        self.object_fields: dict[str, list[str]] = {}
        for o in r.get("tobj", []):
            fs = [o.get(f"fiel{i}", "") for i in (1, 2, 3, 4, 5, 6, 7, 8, 9, 0)]
            self.object_fields[o["objct"]] = [f for f in fs if f]
        self.object_class = {o["objct"]: o.get("oclss", "") for o in r.get("tobj", [])}
        self.object_text: dict[str, str] = {}
        for o in r.get("tobjt", []):
            self.object_text.setdefault(o["object"], o.get("ttext", ""))
        self.activity_text: dict[str, str] = {}
        for a in sorted(r.get("tact", []), key=lambda x: 0 if x.get("spras") == "S" else 1):
            self.activity_text.setdefault(a["actvt"], a.get("ltext", ""))
        self.tcode_text: dict[str, str] = {}
        for t in sorted(r.get("tstct", []), key=lambda x: 0 if x.get("sprsl") == "S" else 1):
            self.tcode_text.setdefault(t["tcode"], t.get("ttext", ""))
        self.tcode_program = {t["tcode"]: t.get("pgmna", "") for t in r.get("tstc", [])}
        self.tcode_start_checks: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
        for t in r.get("tstca", []):
            self.tcode_start_checks[t["tcode"]].setdefault(t["objct"], {})[t["field"]] = t.get("value", "")
        self.service_hash = {h["name"]: h for h in r.get("usobhash", [])}
        # SU24 del sistema: (transacción, objeto) -> indicador de verificación (X/Y = se verifica)
        self.su24_check: dict[tuple[str, str], str] = {(x["name"], x["object"]): x.get("okflag", "")
                                                      for x in r.get("usobx_c", [])
                                                      if (x.get("type") or "TR") == "TR"}
        self.su24_loaded = bool(self.su24_check)
        # SU24 de servicios Fiori/OData (TYPE HT): objeto -> {hash del servicio: actividades propuestas | None}
        self.fiori_checks: dict[str, dict[str, list[FieldValue] | None]] = defaultdict(dict)
        for x in r.get("usobx_c", []):
            if x.get("type") == "HT" and x.get("okflag") in ("X", "Y"):
                self.fiori_checks[x["object"]].setdefault(x["name"], None)
        for x in r.get("usobt_c", []):
            if x.get("type") == "HT" and x.get("field") == "ACTVT" and x["name"] in self.fiori_checks.get(x["object"], {}):
                cur = self.fiori_checks[x["object"]][x["name"]] or []
                cur.append(FieldValue(x.get("low", ""), x.get("high", "")))
                self.fiori_checks[x["object"]][x["name"]] = cur

    def service_label(self, hash_value: str) -> str:
        """Nombre del servicio OData/ICF que corresponde al hash de S_SERVICE (USOBHASH)."""
        h = self.service_hash.get(hash_value)
        if not h:
            return ""
        return f"{(h.get('obj_name') or '').strip()} ({h.get('object', '')})".strip()

    # ---------------------------------------------------------------------------------
    def is_composite(self, role: str) -> bool:
        return role in self.composite_flag or bool(self.composite_children.get(role))

    def role_type(self, role: str) -> str:
        if self.is_composite(role):
            return "compuesto"
        if self.role_parent.get(role):
            return "derivado"
        parents = self.__dict__.get("_parents")
        if parents is None:
            parents = self.__dict__["_parents"] = set(self.role_parent.values())
        if role in parents:
            return "padre"
        return "simple"

    def user_assignments(self, username: str) -> list[RoleAssignment]:
        return [RoleAssignment(role=x["agr_name"], valid_from=parse_date(x.get("from_dat")),
                               valid_to=parse_date(x.get("to_dat")),
                               via_composite="(compuesto)" if x.get("col_flag") == "X" else None,
                               org_flag=x.get("org_flag", ""))
                for x in self.user_roles_raw.get(username, [])]

    def expand_profile(self, profile: str, _seen: set[str] | None = None) -> list[str]:
        """Perfil (simple o compuesto) → lista de perfiles simples."""
        seen = _seen if _seen is not None else set()
        if profile in seen:
            return []
        seen.add(profile)
        subs = self.subprofiles.get(profile)
        if not subs:
            return [profile]
        out: list[str] = []
        for s in subs:
            out += self.expand_profile(s, seen)
        return out

    def profile_tree(self, profile: str, _seen: set[str] | None = None) -> set[str]:
        """Todos los perfiles alcanzables desde ``profile`` (él mismo, compuestos intermedios y simples)."""
        seen = _seen if _seen is not None else set()
        if profile in seen:
            return seen
        seen.add(profile)
        for sub in self.subprofiles.get(profile, []):
            self.profile_tree(sub, seen)
        return seen

    def instance(self, obj: str, auth: str) -> AuthInstance:
        return AuthInstance(obj, auth, {f: list(v) for f, v in self.auth_values.get((obj, auth), {}).items()})

    def profile_instances(self, profile: str) -> list[AuthInstance]:
        """Instancias de un perfil (cacheadas: el snapshot es inmutable). Las instancias son compartidas
        y no deben modificarse (el simulador copia antes de cambiar valores)."""
        cache = self.__dict__.setdefault("_prof_cache", {})
        res = cache.get(profile)
        if res is None:
            res = []
            for simple in self.expand_profile(profile):
                for obj, auth in self.profile_auths.get(simple, []):
                    res.append(self.instance(obj, auth))
            cache[profile] = res
        return res

    def sap_all_objects(self) -> frozenset[str]:
        cached = self.__dict__.get("_sap_all_objs")
        if cached is None:
            cached = frozenset()
            if self.subprofiles.get("SAP_ALL") or self.profile_auths.get("SAP_ALL"):
                cached = frozenset({o for p in self.expand_profile("SAP_ALL") for o, _ in self.profile_auths.get(p, [])})
            self.__dict__["_sap_all_objs"] = cached
        return cached

    def role_defined_instances(self, role: str) -> list[AuthInstance]:
        """Instancias tal como están definidas en PFCG (AGR_1251, excluye borradas)."""
        grouped: dict[tuple[str, str], dict[str, list[FieldValue]]] = defaultdict(lambda: defaultdict(list))
        for x in self.role_values.get(role, []):
            if x.get("deleted") == "X":
                continue
            grouped[(x["object"], x["auth"])][x["field"]].append(FieldValue(x.get("low", ""), x.get("high", "")))
        return [AuthInstance(o, a, dict(f)) for (o, a), f in grouped.items()]


def load_snapshot_rows(engine: Engine, snapshot_id: int) -> dict[str, list[dict[str, str]]]:
    rows: dict[str, list[dict[str, str]]] = {}
    with engine.connect() as c:
        for name, table in SAP_TABLES.items():
            res = c.execute(select(table).where(table.c.snapshot_id == snapshot_id))
            rows[name] = [{k: (v or "") for k, v in m.items() if k not in ("id", "snapshot_id")}
                          for m in res.mappings()]
    return rows


@lru_cache(maxsize=2)  # cada snapshot real ocupa bastante memoria
def _cached(engine_id: int, snapshot_id: int, version: str, engine: Engine) -> SnapshotData:  # noqa: ARG001
    return SnapshotData(load_snapshot_rows(engine, snapshot_id), snapshot_id)


_load_lock = threading.Lock()


def get_snapshot_data(engine: Engine, snapshot_id: int, version: str = "") -> SnapshotData:
    """Los snapshots son inmutables: se pueden cachear con seguridad. ``version`` (fecha de inicio) evita
    reutilizar datos de un snapshot borrado cuyo número fue reasignado. El candado evita cargas duplicadas."""
    with _load_lock:
        return _cached(id(engine), snapshot_id, version, engine)


def clear_cache() -> None:
    with _load_lock:
        _cached.cache_clear()
