"""Plan de acción: convierte los hallazgos en TAREAS concretas agrupadas por causa.

En SAP casi todo se corrige en un rol (PFCG) o en la asignación de roles/perfiles de un
usuario (SU01/SU10). Por eso los hallazgos "usuario × regla" se agrupan en tareas:

* ``rol``          – Corregir el rol R (autorizaciones críticas o conflictos SoD dentro del rol).
* ``combinacion``  – Separar los roles A y B (juntos generan un riesgo en ciertos usuarios).
* ``perfil``       – Quitar un perfil asignado directamente (SAP_ALL, SAP_NEW…) y todo lo que origina.
* ``perfil_otro``  – Permisos críticos que no vienen de ningún rol (perfiles directos o residuales).
* ``usuarios``     – Ajustar usuarios (estándar desbloqueados, inactivos…).
* ``emergencia``   – Usuarios de emergencia declarados: se controlan manteniéndolos bloqueados (ver emergency.py).
* ``calidad``      – Regenerar perfiles de roles desactualizados.

Cada tarea tiene una lista de *puntos* (problemas) con qué cambiar y por qué. Las tareas se
ordenan por gravedad y cantidad de usuarios afectados.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .engine.rules import RuleSet
from .storage.orm import SAP_TABLES, Finding, Snapshot

SEV_RANK = {"critico": 4, "alto": 3, "medio": 2, "bajo": 1, "informativo": 0}
HANDLED = {"corregido", "falso_positivo", "excepcion", "mitigado"}

KIND_LABEL = {"rol": "Corregir rol", "combinacion": "Separar roles", "perfil": "Quitar perfil",
              "perfil_otro": "Perfiles sin rol", "usuarios": "Ajustar usuarios", "emergencia": "Usuarios de emergencia",
              "calidad": "Regenerar perfiles"}


@dataclass
class Problem:
    rule_id: str
    kind: str              # critica | sod | calidad | usuario
    severity: str
    title: str
    change: str            # qué cambiar exactamente (objeto/valores o funciones a separar)
    why: str
    finding_ids: list[int] = field(default_factory=list)
    roles: set[str] = field(default_factory=set)
    fid_user: dict[int, str] = field(default_factory=dict)   # hallazgo → usuario
    static_users: set[str] = field(default_factory=set)     # usuarios del rol (problemas a nivel de rol)
    # Calculados en cada consulta según el estado de los hallazgos (ver build_tasks):
    users: set[str] = field(default_factory=set)            # usuarios que HOY tienen el problema
    fixed_users: set[str] = field(default_factory=set)      # usuarios corregidos desde la extracción anterior
    resolved: bool = False                                  # todos sus hallazgos están corregidos
    # Perfiles de superusuario (SAP_ALL…): riesgos que hoy existen SOLO por el perfil y desaparecen al quitarlo.
    consequences: dict[str, dict[str, Any]] = field(default_factory=dict)  # regla → título, gravedad, usuarios

    @property
    def consequence_list(self) -> list[dict[str, Any]]:
        """Consecuencias ordenadas: primero las más graves y las que alcanzan a más usuarios."""
        out = [{"regla": k, "titulo": v["titulo"], "gravedad": v["gravedad"], "tipo": v.get("tipo", ""),
                "n_users": len(v["usuarios"])} for k, v in self.consequences.items()]
        return sorted(out, key=lambda c: (-SEV_RANK.get(c["gravedad"], 0), -c["n_users"], c["titulo"]))


@dataclass
class Task:
    key: str
    kind: str
    title: str             # imperativo: "Corregir el rol Z_X"
    subtitle: str          # descripción del rol / contexto
    what: str              # qué hacer (1 frase)
    where: str             # dónde, en SAP
    roles: list[str]
    problems: list[Problem]
    open_ids: list[int] = field(default_factory=list)
    status_counts: dict[str, int] = field(default_factory=dict)
    profile: str = ""      # tareas «perfil»: perfil a quitar
    rule_id: str = ""      # tareas «usuarios»: regla que las origina
    info: dict[str, Any] = field(default_factory=dict)   # tareas «emergencia»: estado de cada usuario declarado

    @property
    def visible_problems(self) -> list[Problem]:
        """Puntos que siguen vigentes (los totalmente corregidos se informan aparte)."""
        vis = [p for p in self.problems if not p.resolved]
        return vis or self.problems

    @property
    def resolved_problems(self) -> list[Problem]:
        return [p for p in self.problems if p.resolved]

    @property
    def severity(self) -> str:
        return max((p.severity for p in self.visible_problems), key=lambda s: SEV_RANK.get(s, 0),
                   default="informativo")

    @property
    def users(self) -> list[str]:
        return sorted({u for p in self.problems for u in p.users})

    @property
    def n_users(self) -> int:
        return len({u for p in self.problems for u in p.users})

    @property
    def fixed_users(self) -> list[str]:
        """Usuarios que tenían el problema en la extracción anterior y ya no lo tienen."""
        current = {u for p in self.problems for u in p.users}
        return sorted({u for p in self.problems for u in p.fixed_users} - current)

    @property
    def finding_ids(self) -> list[int]:
        return [f for p in self.problems for f in p.finding_ids]

    @property
    def pending(self) -> bool:
        return bool(self.open_ids)

    @property
    def n_critical(self) -> int:
        return sum(1 for p in self.visible_problems if p.severity == "critico")

    @property
    def main_problem(self) -> Problem:
        vis = self.visible_problems
        if self.kind == "perfil" and vis and vis[0].rule_id == self.problems[0].rule_id:
            return vis[0]  # la causa raíz (el perfil) va primero
        return sorted(vis, key=lambda p: (-SEV_RANK.get(p.severity, 0), -len(p.users)))[0]


def _key(*parts: Any) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _sentence(text: str, limit: int = 180) -> str:
    text = (text or "").strip()
    if ". " in text:
        text = text.split(". ", 1)[0] + "."
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


_CACHE: dict[tuple, list[Task]] = {}


def build_tasks(db: Session, snap: Snapshot, rules: RuleSet) -> list[Task]:
    """Tareas del snapshot. La agrupación se cachea; el estado de los hallazgos se lee en cada llamada."""
    from .emergency import record_for
    emergency = record_for(db, snap)  # vuelve a aplicar las declaraciones si alguna venció desde la última vez
    ckey = (snap.id, snap.analyzed_at, rules.hash, json.dumps(emergency, sort_keys=True, default=str))
    tasks = _CACHE.get(ckey)
    if tasks is None:
        tasks = _group(db, snap, rules, emergency)
        _CACHE.clear()
        _CACHE[ckey] = tasks
    status = dict(db.execute(select(Finding.id, Finding.status).where(Finding.snapshot_id == snap.id)).all())
    for t in tasks:
        counts: dict[str, int] = {}
        for fid in t.finding_ids:
            st = status.get(fid, "abierto")
            counts[st] = counts.get(st, 0) + 1
        t.status_counts = counts
        t.open_ids = [f for f in t.finding_ids if status.get(f, "abierto") not in HANDLED]
        for p in t.problems:
            sts = [status.get(f, "abierto") for f in p.finding_ids]
            # «corregido» = el problema ya no está en SAP (la extracción lo verificó). Esos usuarios NO son
            # usuarios afectados: se muestran aparte como corregidos.
            p.resolved = bool(sts) and all(x == "corregido" for x in sts)
            p.users = {u for f, u in p.fid_user.items() if status.get(f) != "corregido"}
            if not p.resolved:
                p.users |= p.static_users
            p.fixed_users = {u for f, u in p.fid_user.items() if status.get(f) == "corregido"} - p.users
    return tasks


def get_task(db: Session, snap: Snapshot, rules: RuleSet, key: str) -> Task | None:
    return next((t for t in build_tasks(db, snap, rules) if t.key == key), None)


def _group(db: Session, snap: Snapshot, rules: RuleSet,
           emergency: dict[str, dict[str, Any]] | None = None) -> list[Task]:
    risks = {r.id: r for r in rules.risks}
    tasks: dict[str, dict[str, Any]] = {}
    # Usuarios de emergencia declarados (y existentes en el snapshot): todo lo suyo va a una tarea propia, que se
    # resuelve manteniéndolos bloqueados y no quitándoles los permisos.
    emer = {u for u, r in (emergency or {}).items() if r.get("estado") != "no_existe"}

    def task(key: str, kind: str, roles: tuple[str, ...] = (), **extra: Any) -> dict[str, Any]:
        t = tasks.get(key)
        if t is None:
            t = tasks[key] = {"kind": kind, "roles": roles, "problems": {}, **extra}
        return t

    def problem(t: dict[str, Any], pid: str, **kw: Any) -> Problem:
        p = t["problems"].get(pid)
        if p is None:
            p = t["problems"][pid] = Problem(**kw)
        elif SEV_RANK.get(kw["severity"], 0) > SEV_RANK.get(p.severity, 0):
            p.severity = kw["severity"]
        return p

    def crit_change(rule_id: str) -> str:
        rule = rules.critical_by_id(rule_id)
        if not rule:
            return ""
        if rule.requirements:
            return "Quitar o restringir: " + "; ".join(q.describe().replace(" (comodín total)", "")
                                                      for q in rule.requirements)
        return _sentence(rule.recommendation)

    def sod_change(rid: str, funcs: list[dict] | None = None) -> str:
        r = risks.get(rid)
        if funcs:
            parts = [f"«{f.get('titulo', '')}» ({', '.join(f.get('roles', [])) or 'perfil'})" for f in funcs]
            return "Separar " + " de ".join(parts[:2])
        if r:
            names = [rules.functions[f].title for f in r.functions if f in rules.functions]
            return "Separar «" + "» de «".join(names) + "»"
        return ""

    def emergency_problem(fid: int, kind: str, rid: str, sev: str, user: str, ev: Any, st: str) -> None:
        t = task(_key("emergencia"), "emergencia", info={"emergencia": emergency or {}})
        if kind == "sod":
            r = risks.get(rid)
            title, why, pkind = (r.title if r else rid), _sentence(r.description if r else ""), "sod"
        else:
            rule = rules.critical_by_id(rid)
            title, why = (rule.title if rule else rid), (_sentence(rule.description) if rule else "")
            pkind = "usuario" if rule is not None and rule.type == "user_attributes" else "critica"
        p = problem(t, rid, rule_id=rid, kind=pkind, severity=sev, title=title,
                    change="Lo tiene a propósito: se controla manteniendo el usuario bloqueado", why=why)
        p.finding_ids.append(fid)
        p.fid_user[fid] = user
        ev = ev if isinstance(ev, dict) else {}
        if st != "corregido":
            for c in ev.get("consecuencias") or []:
                e = p.consequences.setdefault(c["regla"], {"titulo": c["titulo"], "gravedad": c["gravedad"],
                                                           "tipo": c.get("tipo", ""), "usuarios": set()})
                e["usuarios"].add(user)

    rows = list(db.execute(select(
        Finding.id, Finding.kind, Finding.rule_id, Finding.severity, Finding.subject_user, Finding.subject_role,
        Finding.roles_responsible, Finding.title, Finding.status, Finding.evidence).where(
        Finding.snapshot_id == snap.id, Finding.kind.in_(["critica", "calidad", "sod_rol"]),
        Finding.severity != "informativo")))  # lo informativo (p. ej. quién desarrolla en DEV) no es una tarea

    # 1) Perfiles críticos (SAP_ALL…): causa raíz de lo que no proviene de roles.
    #    Un hallazgo «corregido» (el usuario YA no tiene el perfil) no decide a qué tarea van sus otros
    #    hallazgos vigentes; sí agrupa sus consecuencias también corregidas.
    profile_open: dict[str, str] = {}
    profile_any: dict[str, str] = {}
    for (fid, kind, rid, sev, user, role, roles, title, st, ev) in rows:
        if user in emer:
            continue  # va a la tarea de usuarios de emergencia (más abajo)
        rule = rules.critical_by_id(rid) if kind == "critica" else None
        if rule is not None and rule.type == "profile" and user:
            prof = ", ".join(rule.profiles)
            k = _key("perfil", prof)
            t = task(k, "perfil", profile=prof, rule=rule)
            p = problem(t, rid, rule_id=rid, kind="critica", severity=sev, title=rule.title,
                        change=f"Quitar el perfil {prof} del usuario", why=_sentence(rule.description))
            p.finding_ids.append(fid)
            p.fid_user[fid] = user
            ev = ev if isinstance(ev, dict) else {}
            if "consecuencias" in ev:
                # Análisis actual: las consecuencias del perfil vienen DENTRO de su hallazgo; lo que queda
                # aparte no se resuelve quitando el perfil.
                if st != "corregido":
                    for c in ev.get("consecuencias") or []:
                        e = p.consequences.setdefault(c["regla"], {"titulo": c["titulo"], "gravedad": c["gravedad"],
                                                                   "tipo": c.get("tipo", ""), "usuarios": set()})
                        e["usuarios"].add(user)
                continue
            # Snapshots analizados antes: las consecuencias son hallazgos sueltos que se agrupan acá.
            profile_any.setdefault(user, k)
            if st != "corregido":
                profile_open.setdefault(user, k)

    def profile_key(user: str | None, st: str) -> str:
        m = profile_any if st == "corregido" else profile_open
        return m.get(user or "") or _key("perfil_otro")

    for (fid, kind, rid, sev, user, role, roles, title, st, ev) in rows:
        if kind == "critica" and user in emer:
            emergency_problem(fid, kind, rid, sev, user, ev, st)
            continue
        roles = tuple(sorted(roles or []))
        if kind == "calidad":
            t = task(_key("calidad"), "calidad")
            p = problem(t, role, rule_id=rid, kind="calidad", severity=sev, title=f"Rol {role}",
                        change="Generar el perfil y ejecutar la comparación de usuarios",
                        why="El perfil no coincide con lo definido en PFCG.")
            p.finding_ids.append(fid)
            p.roles.add(role)
            continue
        if kind == "sod_rol":
            t = task(_key("rol", role), "rol", (role,))
            r = risks.get(rid)
            p = problem(t, rid, rule_id=rid, kind="sod", severity=sev, title=r.title if r else title,
                        change=sod_change(rid), why=_sentence(r.description if r else ""))
            p.finding_ids.append(fid)
            continue
        rule = rules.critical_by_id(rid)
        if rule is None or rule.type == "profile":
            continue
        if rule.type == "user_attributes":
            t = task(_key("usuarios", rid), "usuarios", rule=rule)
            p = problem(t, rid, rule_id=rid, kind="usuario", severity=sev, title=rule.title,
                        change=_sentence(rule.recommendation), why=_sentence(rule.description))
        elif not roles:
            k = profile_key(user, st)
            t = tasks.get(k) or task(k, "perfil_otro")
            chg = (f"Se resuelve al quitar el perfil {t['profile']}" if t["kind"] == "perfil" else crit_change(rid))
            p = problem(t, rid, rule_id=rid, kind="critica", severity=sev, title=rule.title,
                        change=chg, why=_sentence(rule.description))
        elif len(roles) == 1:
            t = task(_key("rol", roles[0]), "rol", roles)
            p = problem(t, rid, rule_id=rid, kind="critica", severity=sev, title=rule.title,
                        change=crit_change(rid), why=_sentence(rule.description))
        else:
            t = task(_key("combinacion", *roles), "combinacion", roles)
            p = problem(t, rid, rule_id=rid, kind="critica", severity=sev, title=rule.title,
                        change=crit_change(rid) + " (el permiso se arma combinando estos roles)",
                        why=_sentence(rule.description))
        p.finding_ids.append(fid)
        if user:
            p.fid_user[fid] = user

    # 2) Conflictos SoD de usuarios
    for (fid, rid, sev, user, ev, st) in db.execute(select(
            Finding.id, Finding.rule_id, Finding.severity, Finding.subject_user, Finding.evidence, Finding.status)
            .where(Finding.snapshot_id == snap.id, Finding.kind == "sod", Finding.severity != "informativo")):
        if user in emer:
            emergency_problem(fid, "sod", rid, sev, user, ev, st)
            continue
        r = risks.get(rid)
        ev = ev or {}
        scope = str(ev.get("alcance", ""))
        funcs = ev.get("funciones", [])
        if scope.startswith("intra-rol"):
            inside = scope[scope.find("(") + 1: scope.rfind(")")].split(", ")[0] if "(" in scope else ""
            t = task(_key("rol", inside), "rol", (inside,))
            p = problem(t, rid, rule_id=rid, kind="sod", severity=sev, title=r.title if r else rid,
                        change=sod_change(rid), why=_sentence(r.description if r else ""))
        elif scope == "incluye perfil directo":
            k = profile_key(user, st)
            t = tasks.get(k) or task(k, "perfil_otro")
            chg = (f"Se resuelve al quitar el perfil {t['profile']}" if t["kind"] == "perfil"
                   else sod_change(rid, funcs))
            p = problem(t, rid, rule_id=rid, kind="sod", severity=sev, title=r.title if r else rid,
                        change=chg, why=_sentence(r.description if r else ""))
        else:
            roles = tuple(sorted({x for f in funcs for x in f.get("roles", [])}))
            t = task(_key("combinacion", *roles), "combinacion", roles)
            p = problem(t, rid, rule_id=rid, kind="sod", severity=sev, title=r.title if r else rid,
                        change=sod_change(rid, funcs), why=_sentence(r.description if r else ""))
        p.finding_ids.append(fid)
        if user:
            p.fid_user[fid] = user

    # Textos de roles (para el subtítulo) y usuarios asignados a roles (tareas de rol sin usuarios con hallazgo)
    role_names = {r for t in tasks.values() for r in t["roles"]}
    texts: dict[str, str] = {}
    if role_names:
        tt = SAP_TABLES["agr_texts"]
        for name, text, lang in db.execute(select(tt.c.agr_name, tt.c.text, tt.c.spras).where(
                tt.c.snapshot_id == snap.id)):
            if name in role_names and (name not in texts or lang == "S"):
                texts[name] = text
        tu = SAP_TABLES["agr_users"]
        assigned: dict[str, set[str]] = {}
        for name, uname in db.execute(select(tu.c.agr_name, tu.c.uname).where(tu.c.snapshot_id == snap.id)):
            if name in role_names:
                assigned.setdefault(name, set()).add(uname)
        for t in tasks.values():
            if t["kind"] == "rol" and t["roles"]:
                users = assigned.get(t["roles"][0], set())
                for p in t["problems"].values():
                    if not p.fid_user:
                        p.static_users |= users  # problema del rol: afecta a todos sus usuarios

    out = [_describe(k, t, texts) for k, t in tasks.items() if t["problems"]]
    out.sort(key=lambda x: (-SEV_RANK.get(x.severity, 0),
                            -len({u for p in x.problems for u in p.fid_user.values()} |
                                 {u for p in x.problems for u in p.static_users}),
                            -(len(x.problems) + sum(len(p.consequences) for p in x.problems)), x.title))
    return out


def _describe(key: str, t: dict[str, Any], texts: dict[str, str]) -> Task:
    kind, roles = t["kind"], list(t["roles"])
    root = t["rule"].id if kind == "perfil" and t.get("rule") else None
    problems = sorted(t["problems"].values(), key=lambda p: (p.rule_id != root, -SEV_RANK.get(p.severity, 0),
                                                            -len(set(p.fid_user.values()) | p.static_users),
                                                            p.title))
    if kind == "rol":
        r = roles[0]
        title = f"Corregir el rol {r}"
        subtitle = texts.get(r, "")
        what = "Quitar o restringir en el rol las autorizaciones indicadas; si mezcla funciones incompatibles, " \
               "dividirlo en roles separados."
        where = f"PFCG › {r} › Autorizaciones (modo experto)"
    elif kind == "combinacion":
        title = "Separar los roles " + " y ".join(roles) if len(roles) <= 3 else \
            f"Separar la combinación de {len(roles)} roles"
        subtitle = " · ".join(f"{r}: {texts.get(r, '')}" for r in roles[:3] if texts.get(r))
        what = "Ningún usuario debería tener estos roles juntos: quitar uno a cada usuario afectado. " \
               "Si es indispensable, documentar un control mitigante con vencimiento."
        where = "SU01 / SU10 › pestaña Roles de cada usuario afectado"
    elif kind == "perfil":
        prof = t.get("profile", "")
        title = f"Quitar el perfil {prof}"
        subtitle = "Perfil asignado directamente, fuera del gobierno de roles PFCG."
        what = t["rule"].recommendation if t.get("rule") else "Retirar el perfil y asignar roles acotados."
        where = "SU01 / SU10 › pestaña Perfiles"
    elif kind == "perfil_otro":
        title = "Revisar permisos críticos que no provienen de ningún rol"
        subtitle = "Perfiles asignados directamente o perfiles residuales (rol vencido sin comparación PFUD)."
        what = "Retirar los perfiles directos o ejecutar la comparación de usuarios, y asignar roles acotados."
        where = "SU01 › pestaña Perfiles · PFUD"
    elif kind == "emergencia":
        title = "Mantener bloqueados los usuarios de emergencia"
        subtitle = ("Usuarios declarados de emergencia: tienen permisos amplios a propósito y solo se habilitan ante "
                    "una emergencia.")
        what = ("Que estén bloqueados mientras no haya una emergencia en curso; después de usarlos, volver a "
                "bloquearlos y revisar lo que se hizo.")
        where = "SU01 / SU10 › Bloquear · Usuarios de emergencia (en esta aplicación)"
    elif kind == "usuarios":
        rule = t.get("rule")
        title = {"CRIT-STD-001": "Bloquear usuarios estándar de SAP",
                 "CRIT-USR-INA-001": "Revisar usuarios sin actividad"}.get(rule.id if rule else "",
                                                                         rule.title if rule else "Ajustar usuarios")
        subtitle = rule.title if rule else ""
        what = _sentence(rule.recommendation) if rule else ""
        where = "SU01 / SU10 › Bloquear o ajustar validez"
    else:  # calidad
        title = f"Regenerar el perfil de {len(problems)} rol(es)"
        subtitle = "La definición en PFCG no coincide con el perfil que reciben los usuarios."
        what = "Generar el perfil de cada rol y ejecutar la comparación de usuarios."
        where = "PFCG › Autorizaciones › Generar · luego PFUD"
        roles = sorted({r for p in problems for r in p.roles})
    rule = t.get("rule")
    return Task(key=key, kind=kind, title=title, subtitle=subtitle, what=what, where=where, roles=roles,
                problems=problems, profile=t.get("profile", "") if kind == "perfil" else "",
                rule_id=rule.id if rule is not None and kind == "usuarios" else "", info=t.get("info") or {})


def summary(tasks: list[Task]) -> dict[str, Any]:
    pend = [t for t in tasks if t.pending]
    return {
        "tareas": len(pend),
        "criticas": sum(1 for t in pend if t.severity == "critico"),
        "altas": sum(1 for t in pend if t.severity == "alto"),
        "usuarios": len({u for t in pend for u in t.users}),
        "resueltas": sum(1 for t in tasks if not t.pending),
        "por_tipo": {k: sum(1 for t in pend if t.kind == k) for k in KIND_LABEL},
    }


# ---------------------------------------------------------------------------------- fichas de usuario y rol
def _crit_change(rule: Any) -> str:
    if rule is None:
        return ""
    if rule.requirements:
        return "Quitar o restringir: " + "; ".join(q.describe().replace(" (comodín total)", "")
                                                  for q in rule.requirements)
    return _sentence(rule.recommendation)


def user_fix_items(rules: RuleSet, a: Any) -> list[dict[str, Any]]:
    """Lista corta de qué corregir en un usuario, con enlace a la tarea del plan que lo resuelve."""
    items: list[dict[str, Any]] = []
    # El análisis ya dejó dentro del perfil (SAP_ALL…) lo que desaparece al quitarlo: lo que sigue sin rol
    # proviene de otros perfiles asignados a mano.
    profile_key = None
    for h in a.critical:
        if h.severity.value == "informativo":
            continue  # dato, no algo a corregir
        rule = rules.critical_by_id(h.rule_id)
        rtype = rule.type if rule else ""
        roles = sorted(h.roles)
        profile = ""
        if rtype == "user_attributes":
            key, origin, change = _key("usuarios", h.rule_id), "datos del usuario", _sentence(h.recommendation)
            cause = "usuarios"
        elif rtype == "profile":
            key = _key("perfil", ", ".join(rule.profiles))
            origin, change = "perfil asignado directamente", f"Quitar el perfil {', '.join(rule.profiles)}"
            cause, profile = "perfil", ", ".join(rule.profiles)
        elif not roles:
            key, origin, change = profile_key or _key("perfil_otro"), "perfil directo o residual", _crit_change(rule)
            cause = "perfil" if profile_key else "perfil_otro"
        elif len(roles) == 1:
            key, origin, change, cause = _key("rol", roles[0]), f"rol {roles[0]}", _crit_change(rule), "rol"
        else:
            key, origin, change = _key("combinacion", *roles), "roles " + " + ".join(roles), _crit_change(rule)
            cause = "combinacion"
        items.append({"severity": h.severity.value, "title": h.title, "origin": origin, "change": change,
                      "why": _sentence(h.description), "evidence": h.evidence, "task": key, "cause": cause,
                      "roles": roles, "profile": profile, "consequences": h.metrics.get("consecuencias", [])})
    for h in a.sod:
        names = [m.title for m in h.functions]
        change = "Separar «" + "» de «".join(names) + "»"
        if h.scope.startswith("intra-rol"):
            inside = h.scope[h.scope.find("(") + 1: h.scope.rfind(")")].split(", ")[0]
            key, origin, cause, roles = _key("rol", inside), f"rol {inside} (lo permite por sí solo)", "rol", [inside]
        elif h.scope == "incluye perfil directo":
            key, origin = profile_key or _key("perfil_otro"), "perfil directo"
            cause, roles = ("perfil" if profile_key else "perfil_otro"), []
        else:
            roles = sorted({r for m in h.functions for r in m.roles})
            key, cause = _key("combinacion", *roles), "combinacion"
            origin = " + ".join(f"{', '.join(m.roles) or 'perfil'}" for m in h.functions)
        ev = [e for m in h.functions for e in m.evidence]
        items.append({"severity": h.severity.value, "title": h.title, "origin": origin, "change": change,
                      "why": _sentence(h.description), "evidence": ev, "task": key, "cause": cause,
                      "roles": roles, "profile": ""})
    items.sort(key=lambda x: -SEV_RANK.get(x["severity"], 0))
    return items


_QUALITY_SEV = {"perfil": "medio", "genericos": "medio", "mezcla": "medio", "descripcion": "bajo", "uso": "bajo"}
_QUALITY_FIX = {
    "perfil": "Generar el perfil en PFCG y ejecutar la comparación de usuarios (PFUD).",
    "genericos": "Reemplazar los comodines (*) por los valores necesarios.",
    "mezcla": "Separar la administración técnica (objetos S_*) de las funciones de negocio en roles distintos.",
    "descripcion": "Completar la descripción del rol en PFCG.",
    "uso": "Confirmar si el rol se usa; si no, marcarlo para baja.",
}


def role_fix_items(rules: RuleSet, ra: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for h in ra.critical:
        if h.severity.value == "informativo":
            continue
        rule = rules.critical_by_id(h.rule_id)
        items.append({"severity": h.severity.value, "title": h.title, "origin": "autorización del rol",
                      "change": _crit_change(rule), "why": _sentence(h.description), "evidence": h.evidence,
                      "cause": "critica"})
    for h in ra.sod:
        names = [m.title for m in h.functions]
        items.append({"severity": h.severity.value, "title": h.title, "origin": "conflicto dentro del rol",
                      "change": "Dividir el rol: separar «" + "» de «".join(names) + "»",
                      "why": _sentence(h.description), "evidence": [e for m in h.functions for e in m.evidence],
                      "cause": "sod"})
    for c in ra.quality.criteria:
        if c.passed or c.id in ("criticos", "sod"):
            continue
        items.append({"severity": _QUALITY_SEV.get(c.id, "bajo"), "title": c.label.replace("Tiene", "No tiene", 1)
                      if c.id in ("descripcion", "uso") else f"Incumple: {c.label.lower()}",
                      "origin": c.detail, "change": _QUALITY_FIX.get(c.id, ""), "why": "", "evidence": [],
                      "cause": "calidad"})
    items.sort(key=lambda x: -SEV_RANK.get(x["severity"], 0))
    return items
