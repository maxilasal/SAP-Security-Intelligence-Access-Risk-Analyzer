"""Qué cambió en un sistema entre dos extracciones (dos fechas).

Compara dos snapshots del MISMO sistema y mandante y muestra:

* **Alertas** nuevas y resueltas (por su huella estable: regla + usuario o rol).
* **Cambios en SAP** que las explican: asignaciones de roles (AGR_USERS), perfiles asignados a mano (UST04 sin los
  perfiles generados de roles, AGR_1016), usuarios nuevos, borrados, bloqueados o desbloqueados (USR02) y roles
  nuevos, borrados o modificados (AGR_DEFINE y valores de AGR_1251).
* **Decisiones** registradas en la aplicación en ese período (auditoría propia).

Se reconstruye por diferencia entre las dos extracciones: la aplicación no lee los documentos de modificación de SAP,
así que un cambio hecho y deshecho entre una extracción y la otra no se ve, y no se sabe QUIÉN asignó un rol (eso lo
dicen los documentos de modificación en SAP: SUIM, RSUSR100N para usuarios y RSSCD100_PFCG para roles).
Todo se calcula con consultas SQL sobre los snapshots (no carga los snapshots completos en memoria).
"""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .storage.orm import SAP_TABLES, AuditLog, Finding, Snapshot

SEV_RANK = {"critico": 4, "alto": 3, "medio": 2, "bajo": 1, "informativo": 0}
SUPERUSER_PROFILES = ("SAP_ALL", "SAP_NEW")
DECISION_ACTIONS = ("tarea_gestionada", "hallazgo_actualizado", "mitigacion_creada", "emergencia_declarada",
                    "emergencia_modificada", "emergencia_renovada", "emergencia_quitada")
ACTION_LABEL = {"tarea_gestionada": "Decisión sobre una tarea", "hallazgo_actualizado": "Decisión sobre un hallazgo",
                "mitigacion_creada": "Control mitigante registrado",
                "emergencia_declarada": "Usuario de emergencia declarado",
                "emergencia_modificada": "Declaración de emergencia modificada",
                "emergencia_renovada": "Declaración de emergencia renovada",
                "emergencia_quitada": "Declaración de emergencia quitada"}
KIND_LABEL = {"critica": "Permiso crítico", "sod": "Conflicto de funciones", "sod_rol": "Conflicto dentro de un rol",
              "calidad": "Calidad del rol"}


class ChangesError(ValueError):
    pass


def _d(value: str | None) -> date | None:
    if not value or value.strip() in ("", "00000000"):
        return None
    try:
        return datetime.strptime(value.strip(), "%Y%m%d").date()
    except ValueError:
        return None


def ordered(a: Snapshot, b: Snapshot) -> tuple[Snapshot, Snapshot]:
    """(anterior, posterior), validando que sean del mismo sistema y mandante."""
    if a.connection_id != b.connection_id:
        raise ChangesError("Las dos extracciones tienen que ser del mismo sistema y mandante. Para comparar sistemas "
                           "distintos, use Comparar › Sistemas o fechas.")
    return (a, b) if (a.started_at, a.id) <= (b.started_at, b.id) else (b, a)


def previous_of(db: Session, snap: Snapshot) -> Snapshot | None:
    """La extracción analizada anterior del mismo sistema."""
    return db.scalars(select(Snapshot).where(Snapshot.connection_id == snap.connection_id, Snapshot.id < snap.id,
                                             Snapshot.analyzed_at.is_not(None),
                                             Snapshot.status.in_(("completo", "incompleto")))
                      .order_by(Snapshot.id.desc())).first()


# ------------------------------------------------------------------------------------------------ alertas
def _fp(*parts: str) -> str:
    from .services import fingerprint
    return fingerprint(*parts)


def _alerts(db: Session, snap: Snapshot) -> tuple[dict[str, Finding], set[str]]:
    """Alertas vigentes del snapshot (todo lo que no está «corregido») y huellas que van dentro de SAP_ALL."""
    current: dict[str, Finding] = {}
    folded: set[str] = set()
    for f in db.scalars(select(Finding).where(Finding.snapshot_id == snap.id, Finding.status != "corregido",
                                              Finding.severity != "informativo")):
        current[f.fingerprint] = f
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        for c in ev.get("consecuencias") or []:
            folded.add(_fp(snap.sid, snap.client, "critica" if c.get("tipo") == "critica" else "sod", c.get("regla", ""),
                           f.subject_user or "", ""))
    return current, folded


def _row(f: Finding, note: str = "") -> dict[str, Any]:
    return {"id": f.id, "severity": f.severity, "title": f.title, "kind": KIND_LABEL.get(f.kind, f.kind),
            "user": f.subject_user or "", "role": f.subject_role or "", "rule_id": f.rule_id, "status": f.status,
            "note": note}


def alert_delta(db: Session, a: Snapshot, b: Snapshot) -> dict[str, int]:
    """Solo los conteos (para el inicio): alertas nuevas, nuevas críticas y resueltas."""
    def fps(s: Snapshot) -> dict[str, str]:
        return dict(db.execute(select(Finding.fingerprint, Finding.severity).where(
            Finding.snapshot_id == s.id, Finding.status != "corregido", Finding.severity != "informativo")).all())
    fa, fb = fps(a), fps(b)
    _, folded_b = _alerts(db, b) if set(fa) - set(fb) else ({}, set())
    new = [fp for fp in fb if fp not in fa]
    return {"nuevas": len(new), "nuevas_criticas": sum(1 for fp in new if fb[fp] == "critico"),
            "resueltas": sum(1 for fp in fa if fp not in fb and fp not in folded_b)}


# ------------------------------------------------------------------------------------------- datos de SAP
def _usr02(db: Session, sid: int) -> dict[str, dict[str, Any]]:
    t = SAP_TABLES["usr02"]
    out: dict[str, dict[str, Any]] = {}
    for r in db.execute(select(t.c.bname, t.c.uflag, t.c.ustyp, t.c.gltgb, t.c.erdat, t.c.aname, t.c.fullname)
                        .where(t.c.snapshot_id == sid)):
        try:
            flag = int(r.uflag or 0)
        except ValueError:
            flag = 0
        out[r.bname] = {"locked": flag != 0, "type": r.ustyp or "", "valid_to": _d(r.gltgb), "created": _d(r.erdat),
                        "creator": r.aname or "", "name": r.fullname or ""}
    return out


def _assignments(db: Session, sid: int) -> dict[tuple[str, str], dict[str, Any]]:
    t = SAP_TABLES["agr_users"]
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for r in db.execute(select(t.c.uname, t.c.agr_name, t.c.from_dat, t.c.to_dat, t.c.change_dat, t.c.col_flag)
                        .where(t.c.snapshot_id == sid)):
        e = out.setdefault((r.uname, r.agr_name), {"inherited": True, "to": None, "changed": None})
        e["inherited"] = e["inherited"] and (r.col_flag or "") == "X"
        to = _d(r.to_dat)
        e["to"] = max(filter(None, [e["to"], to]), default=None)
        ch = _d(r.change_dat)
        e["changed"] = max(filter(None, [e["changed"], ch]), default=None)
    return out


def _direct_profiles(db: Session, a_id: int, b_id: int) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Perfiles asignados a mano: UST04 sin los perfiles generados de roles (AGR_1016 de cualquiera de los dos)."""
    t4, t16 = SAP_TABLES["ust04"], SAP_TABLES["agr_1016"]
    generated = set(db.scalars(select(t16.c.profile).where(t16.c.snapshot_id.in_((a_id, b_id)))))

    def pairs(sid: int) -> set[tuple[str, str]]:
        return {(u, p) for u, p in db.execute(select(t4.c.bname, t4.c.profile).where(t4.c.snapshot_id == sid))
                if p not in generated}
    return pairs(a_id), pairs(b_id)


def _roles(db: Session, sid: int) -> dict[str, dict[str, Any]]:
    td, tv = SAP_TABLES["agr_define"], SAP_TABLES["agr_1251"]
    counts = dict(db.execute(select(tv.c.agr_name, func.count()).where(tv.c.snapshot_id == sid)
                             .group_by(tv.c.agr_name)).all())
    out: dict[str, dict[str, Any]] = {}
    for r in db.execute(select(td.c.agr_name, td.c.create_usr, td.c.create_dat, td.c.change_usr, td.c.change_dat)
                        .where(td.c.snapshot_id == sid)):
        out[r.agr_name] = {"created_by": r.create_usr or "", "created": _d(r.create_dat),
                           "changed_by": r.change_usr or "", "changed": _d(r.change_dat),
                           "n_values": counts.get(r.agr_name, 0)}
    return out


def _role_users(db: Session, sid: int) -> Counter:
    t = SAP_TABLES["agr_users"]
    return Counter(dict(db.execute(select(t.c.agr_name, func.count(func.distinct(t.c.uname)))
                                   .where(t.c.snapshot_id == sid).group_by(t.c.agr_name)).all()))


# ------------------------------------------------------------------------------------------------ comparación
def compare(db: Session, a: Snapshot, b: Snapshot) -> dict[str, Any]:
    a, b = ordered(a, b)
    out: dict[str, Any] = {"a": a, "b": b, "days": max((b.started_at - a.started_at).days, 0)}

    # Alertas
    al_a, folded_a = _alerts(db, a)
    al_b, folded_b = _alerts(db, b)
    new = [_row(f, "antes iba dentro de la alerta de SAP_ALL" if fp in folded_a else "")
           for fp, f in al_b.items() if fp not in al_a]
    resolved = [_row(f) for fp, f in al_a.items() if fp not in al_b and fp not in folded_b]
    grouped = [_row(f, "ahora va dentro de la alerta de SAP_ALL") for fp, f in al_a.items()
               if fp not in al_b and fp in folded_b]
    key = (lambda r: (-SEV_RANK.get(r["severity"], 0), r["title"], r["user"] or r["role"]))
    out["new"], out["resolved"], out["grouped"] = sorted(new, key=key), sorted(resolved, key=key), sorted(grouped, key=key)
    sev_a = Counter(f.severity for f in al_a.values())
    sev_b = Counter(f.severity for f in al_b.values())
    out["open"] = {"a": len(al_a), "b": len(al_b), "critico_a": sev_a.get("critico", 0),
                   "critico_b": sev_b.get("critico", 0)}

    # Usuarios
    ua, ub = _usr02(db, a.id), _usr02(db, b.id)
    out["users_new"] = [{"user": u, **ub[u]} for u in sorted(set(ub) - set(ua))]
    out["users_deleted"] = [{"user": u, **ua[u]} for u in sorted(set(ua) - set(ub))]
    both = sorted(set(ua) & set(ub))
    out["users_locked"] = [{"user": u, **ub[u]} for u in both if ub[u]["locked"] and not ua[u]["locked"]]
    out["users_unlocked"] = [{"user": u, **ub[u]} for u in both if ua[u]["locked"] and not ub[u]["locked"]]
    out["users_validity"] = [{"user": u, "before": ua[u]["valid_to"], "after": ub[u]["valid_to"], "name": ub[u]["name"]}
                             for u in both if ua[u]["valid_to"] != ub[u]["valid_to"]]

    # Asignaciones de roles
    asg_a, asg_b = _assignments(db, a.id), _assignments(db, b.id)
    added = sorted(k for k in set(asg_b) - set(asg_a))
    removed = sorted(k for k in set(asg_a) - set(asg_b))
    out["assign_added"] = [{"user": u, "role": r, **asg_b[(u, r)]} for u, r in added if not asg_b[(u, r)]["inherited"]]
    gone = set(ua) - set(ub)  # a los usuarios borrados no se les listan aparte sus roles ni perfiles
    out["assign_removed"] = [{"user": u, "role": r, **asg_a[(u, r)]} for u, r in removed
                             if not asg_a[(u, r)]["inherited"] and u not in gone]
    out["assign_inherited"] = {"added": sum(1 for k in added if asg_b[k]["inherited"]),
                               "removed": sum(1 for k in removed if asg_a[k]["inherited"] and k[0] not in gone)}
    out["assign_validity"] = [{"user": u, "role": r, "before": asg_a[(u, r)]["to"], "after": asg_b[(u, r)]["to"]}
                              for (u, r) in sorted(set(asg_a) & set(asg_b))
                              if asg_a[(u, r)]["to"] != asg_b[(u, r)]["to"] and not asg_b[(u, r)]["inherited"]]

    # Perfiles asignados a mano
    pa, pb = _direct_profiles(db, a.id, b.id)
    out["profiles_added"] = [{"user": u, "profile": p, "super": p in SUPERUSER_PROFILES} for u, p in sorted(pb - pa)]
    out["profiles_removed"] = [{"user": u, "profile": p, "super": p in SUPERUSER_PROFILES} for u, p in sorted(pa - pb)
                               if u not in gone]

    # Roles
    ra, rb = _roles(db, a.id), _roles(db, b.id)
    users_b = _role_users(db, b.id)
    out["roles_new"] = [{"role": r, **rb[r], "users": users_b.get(r, 0)} for r in sorted(set(rb) - set(ra))]
    out["roles_deleted"] = [{"role": r, **ra[r]} for r in sorted(set(ra) - set(rb))]
    out["roles_changed"] = [{"role": r, **rb[r], "n_values_before": ra[r]["n_values"], "users": users_b.get(r, 0)}
                            for r in sorted(set(ra) & set(rb))
                            if (ra[r]["changed"], ra[r]["changed_by"]) != (rb[r]["changed"], rb[r]["changed_by"])
                            or ra[r]["n_values"] != rb[r]["n_values"]]
    sap_all = [x for x in out["profiles_added"] if x["profile"] == "SAP_ALL"]
    out["sap_all_added"] = sap_all

    # Decisiones registradas en la aplicación entre las dos extracciones
    out["decisions"] = [{"ts": x.ts, "user": x.username, "action": ACTION_LABEL.get(x.action, x.action),
                         "target": x.target, "details": x.details or {}}
                        for x in db.scalars(select(AuditLog).where(AuditLog.action.in_(DECISION_ACTIONS),
                                                                   AuditLog.ts >= a.started_at,
                                                                   AuditLog.ts <= b.started_at)
                                            .order_by(AuditLog.ts.desc()).limit(100))]
    sections = ("users_new", "users_deleted", "users_locked", "users_unlocked", "users_validity", "assign_added",
                "assign_removed", "assign_validity", "profiles_added", "profiles_removed", "roles_new",
                "roles_deleted", "roles_changed")
    out["n_sap_changes"] = sum(len(out[k]) for k in sections) + sum(out["assign_inherited"].values())
    return out
