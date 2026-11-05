"""Usuarios de emergencia declarados.

Un usuario de emergencia tiene permisos amplios A PROPÓSITO (normalmente SAP_ALL): se mantiene bloqueado y se
habilita solo ante una emergencia, con aprobación, y lo que se hizo con él se revisa después. Declararlo en la
aplicación cambia cómo se informan sus alertas:

* **Bloqueado** (o fuera de su período de validez) y con la declaración vigente: sus alertas quedan *controladas*
  (estado «mitigado», fijado automáticamente) y no aparecen como pendientes en cada extracción.
* **Desbloqueado**: la tarea «Usuarios de emergencia» queda pendiente: confirmar que hay una emergencia en curso o
  volver a bloquearlo.
* **Declaración vencida** (pasó la fecha de revisión): vuelve a ser pendiente hasta que alguien la renueve o la quite.

Reglas que no cambian:

* Las decisiones que tomó una persona (excepción, falso positivo, control mitigante) nunca se modifican: solo se
  ajustan las alertas pendientes (abiertas o en revisión) y las que esta misma lógica marcó antes.
* La aplicación no bloquea ni desbloquea nada en SAP: lee el estado de bloqueo y la validez del usuario
  (USR02-UFLAG, GLTGV y GLTGB) de cada extracción.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .storage.orm import SAP_TABLES, EmergencyUser, Finding, Snapshot, utcnow

AUTO = "emergencia"                 # valor de Finding.auto_status
PENDING = ("abierto", "en_revision")
MAX_REVIEW_DAYS = 366               # una declaración se revisa al menos una vez por año
DEFAULT_REVIEW_DAYS = 180

STATE_LABEL = {
    "controlado": "Bloqueado: controlado",
    "fuera_de_validez": "Fuera de validez: controlado",
    "desbloqueado": "Desbloqueado",
    "vencida": "Declaración vencida",
    "no_existe": "No existe en este sistema",
}
CONTROLLED = ("controlado", "fuera_de_validez")
PENDING_STATES = ("desbloqueado", "vencida")


class DeclarationError(ValueError):
    """Datos inválidos en una declaración (se muestra al usuario tal cual)."""


# ------------------------------------------------------------------------------------------ consultas
def declarations_for(db: Session, connection_id: int) -> dict[str, EmergencyUser]:
    """Declaraciones que aplican a una conexión: las del sistema y las de «todos los sistemas».
    Si un usuario tiene ambas, vale la del sistema (puede tener otro responsable o procedimiento)."""
    rows = db.scalars(select(EmergencyUser).where(or_(EmergencyUser.connection_id == connection_id,
                                                      EmergencyUser.connection_id.is_(None)))).all()
    out: dict[str, EmergencyUser] = {}
    for d in sorted(rows, key=lambda d: d.connection_id is not None):
        out[d.username] = d
    return out


def _parse(value: str | None) -> date | None:
    if not value or value.strip() in ("", "00000000"):
        return None
    try:
        return datetime.strptime(value.strip(), "%Y%m%d").date()
    except ValueError:
        return None


def _users_in_snapshot(db: Session, snapshot_id: int, users: list[str]) -> dict[str, dict[str, Any]]:
    """Bloqueo, validez y último acceso de los usuarios declarados, leídos del snapshot (USR02)."""
    if not users:
        return {}
    t = SAP_TABLES["usr02"]
    out: dict[str, dict[str, Any]] = {}
    for bname, uflag, gltgv, gltgb, trdat in db.execute(select(
            t.c.bname, t.c.uflag, t.c.gltgv, t.c.gltgb, t.c.trdat).where(
            t.c.snapshot_id == snapshot_id, t.c.bname.in_(users))):
        try:
            flag = int(uflag or 0)
        except ValueError:
            flag = 0
        out[bname] = {"bloqueado": flag != 0, "desde": _parse(gltgv), "hasta": _parse(gltgb),
                      "ultimo_acceso": _parse(trdat)}
    return out


def _state(exists: bool, locked: bool, in_validity: bool, valid_declaration: bool) -> str:
    if not exists:
        return "no_existe"
    if not valid_declaration:
        return "vencida"
    if locked:
        return "controlado"
    if not in_validity:
        return "fuera_de_validez"
    return "desbloqueado"


# ------------------------------------------------------------------------------------------ aplicación
def apply(db: Session, snap: Snapshot, today: date | None = None) -> dict[str, dict[str, Any]]:
    """Aplica las declaraciones al snapshot: ajusta el estado de las alertas de esos usuarios y deja en
    ``snap.stats["emergencia"]`` qué se aplicó (usuario → estado, responsable, fecha de revisión…)."""
    today = today or date.today()
    snap_day = (snap.started_at or utcnow()).date()
    decl = declarations_for(db, snap.connection_id)
    info = _users_in_snapshot(db, snap.id, list(decl))
    record: dict[str, dict[str, Any]] = {}
    for name, d in sorted(decl.items()):
        u = info.get(name)
        in_validity = bool(u) and not ((u["desde"] and u["desde"] > snap_day) or (u["hasta"] and u["hasta"] < snap_day))
        state = _state(u is not None, bool(u and u["bloqueado"]), in_validity, d.review_by >= today)
        record[name] = {
            "id": d.id, "estado": state, "responsable": d.responsible, "procedimiento": d.procedure,
            "revisar": d.review_by.isoformat(), "todos_los_sistemas": d.connection_id is None,
            "bloqueado": bool(u and u["bloqueado"]),
            "valido_hasta": u["hasta"].isoformat() if u and u["hasta"] else "",
            "ultimo_acceso": u["ultimo_acceso"].isoformat() if u and u["ultimo_acceso"] else "",
        }
    controlled = {n for n, r in record.items() if r["estado"] in CONTROLLED}
    q = select(Finding).where(Finding.snapshot_id == snap.id, Finding.kind.in_(("critica", "sod")),
                              Finding.subject_user.is_not(None), Finding.severity != "informativo",
                              or_(Finding.subject_user.in_(list(record)), Finding.auto_status == AUTO))
    for f in db.scalars(q):
        if f.subject_user in controlled:
            if f.status in PENDING:
                f.status, f.auto_status = "mitigado", AUTO
        elif f.auto_status == AUTO:  # se desbloqueó, venció o ya no está declarado: vuelve a ser pendiente
            f.status, f.auto_status = "abierto", ""
    stats = dict(snap.stats or {})
    if record:
        stats["emergencia"] = record
    else:
        stats.pop("emergencia", None)
    snap.stats = stats
    db.commit()
    return record


def _signature(decl: dict[str, EmergencyUser]) -> dict[str, tuple[Any, ...]]:
    return {n: (d.id, d.review_by.isoformat(), d.responsible, d.procedure) for n, d in decl.items()}


def record_for(db: Session, snap: Snapshot) -> dict[str, dict[str, Any]]:
    """Lo aplicado al snapshot. En el último snapshot analizado de cada sistema se mantiene al día: si desde la
    última aplicación cambió alguna declaración o venció su fecha de revisión, se vuelve a aplicar. Los snapshots
    anteriores conservan lo que se les aplicó en su momento (son historia)."""
    from sqlalchemy import func
    rec: dict[str, dict[str, Any]] = (snap.stats or {}).get("emergencia") or {}
    latest = db.scalar(select(func.max(Snapshot.id)).where(Snapshot.connection_id == snap.connection_id,
                                                          Snapshot.analyzed_at.is_not(None),
                                                          Snapshot.status.in_(("completo", "incompleto"))))
    if snap.analyzed_at is None or latest != snap.id:
        return rec
    stored = {n: (r.get("id"), r.get("revisar"), r.get("responsable"), r.get("procedimiento")) for n, r in rec.items()}
    today = date.today().isoformat()
    expired = any(r.get("estado") not in ("vencida", "no_existe") and r.get("revisar", "9999") < today
                  for r in rec.values())
    if expired or stored != _signature(declarations_for(db, snap.connection_id)):
        rec = apply(db, snap)
    return rec


def apply_latest(db: Session, connection_id: int | None) -> int:
    """Aplica las declaraciones al último snapshot analizado de una conexión (o de todas, con ``None``)."""
    from .services import latest_by_connection
    n = 0
    for cid, snap in latest_by_connection(db).items():
        if connection_id is None or cid == connection_id:
            apply(db, snap)
            n += 1
    return n


# ------------------------------------------------------------------------------------------ altas y bajas
def normalize_user(value: str) -> str:
    name = (value or "").strip().upper()
    if not name or len(name) > 12 or " " in name or "*" in name or "+" in name:
        raise DeclarationError("Indique un usuario SAP exacto (hasta 12 caracteres, sin espacios ni comodines).")
    return name


def parse_review(value: str, today: date | None = None) -> date:
    today = today or date.today()
    try:
        d = date.fromisoformat((value or "").strip())
    except ValueError as exc:
        raise DeclarationError("Indique la fecha de revisión.") from exc
    if d < today:
        raise DeclarationError("La fecha de revisión no puede ser anterior a hoy.")
    if d > today + timedelta(days=MAX_REVIEW_DAYS):
        raise DeclarationError("La fecha de revisión puede ser como máximo dentro de un año: obliga a confirmar "
                               "periódicamente que el usuario sigue haciendo falta.")
    return d


def declare(db: Session, connection_id: int | None, username: str, responsible: str, procedure: str,
            review_by: date, by: str) -> tuple[EmergencyUser, bool]:
    """Crea la declaración (o actualiza la existente del mismo usuario y alcance). Devuelve (declaración, nueva)."""
    responsible, procedure = (responsible or "").strip(), (procedure or "").strip()
    if not responsible:
        raise DeclarationError("Indique el responsable: quién aprueba que se use el usuario.")
    if len(procedure) < 10:
        raise DeclarationError("Describa el procedimiento: cuándo se habilita, quién lo aprueba y cómo se revisa lo "
                               "que se hizo.")
    q = select(EmergencyUser).where(EmergencyUser.username == username)
    q = q.where(EmergencyUser.connection_id.is_(None) if connection_id is None
                else EmergencyUser.connection_id == connection_id)
    d = db.scalars(q).first()
    created = d is None
    if d is None:
        d = EmergencyUser(connection_id=connection_id, username=username, created_by=by, created_at=utcnow())
        db.add(d)
    else:
        d.updated_by, d.updated_at = by, utcnow()
    d.responsible, d.procedure, d.review_by = responsible[:100], procedure[:2000], review_by
    db.commit()
    return d, created


def overview(db: Session) -> list[dict[str, Any]]:
    """Una fila por declaración y sistema donde aplica, con el estado según la última extracción de ese sistema."""
    from .services import latest_by_connection
    from .storage.orm import SapConnection
    latest = latest_by_connection(db)
    conns = list(db.scalars(select(SapConnection).order_by(SapConnection.id)))
    today = date.today()
    rows: list[dict[str, Any]] = []
    for d in db.scalars(select(EmergencyUser).order_by(EmergencyUser.username, EmergencyUser.id)):
        general = d.connection_id is None
        mine: list[dict[str, Any]] = []
        for c in [c for c in conns if general or c.id == d.connection_id]:
            if general:
                specific = declarations_for(db, c.id).get(d.username)
                if specific is not None and specific.id != d.id:
                    continue  # en ese sistema vale su declaración propia
            snap = latest.get(c.id)
            state, u = "sin_datos", None
            if snap is not None:
                u = _users_in_snapshot(db, snap.id, [d.username]).get(d.username)
                snap_day = snap.started_at.date()
                in_validity = bool(u) and not ((u["desde"] and u["desde"] > snap_day)
                                               or (u["hasta"] and u["hasta"] < snap_day))
                state = _state(u is not None, bool(u and u["bloqueado"]), in_validity, d.review_by >= today)
            elif d.review_by < today:
                state = "vencida"
            if general and state in ("no_existe", "sin_datos"):
                continue  # «todos los sistemas»: se muestran solo los sistemas donde el usuario existe
            mine.append({"d": d, "conn": c, "snap": snap, "estado": state, "user": u})
        if not mine:  # no existe en ningún sistema (o ese sistema todavía no tiene datos)
            c = next((x for x in conns if x.id == d.connection_id), None)
            mine.append({"d": d, "conn": c, "snap": latest.get(c.id) if c else None, "user": None,
                         "estado": "vencida" if d.review_by < today else
                                   ("no_existe" if (c is None or latest.get(c.id)) else "sin_datos")})
        for r in mine:
            r["dias"] = (d.review_by - today).days
        rows += mine
    order = {"desbloqueado": 0, "vencida": 1, "no_existe": 3, "sin_datos": 4}
    rows.sort(key=lambda r: (order.get(r["estado"], 2), r["d"].username, r["conn"].id if r["conn"] else 0))
    return rows


def sap_all_candidates(db: Session) -> list[dict[str, Any]]:
    """Usuarios con SAP_ALL (según la última extracción de cada sistema) que todavía no están declarados."""
    from .services import latest_by_connection
    t_p = SAP_TABLES["ust04"]
    out: list[dict[str, Any]] = []
    for cid, snap in sorted(latest_by_connection(db).items()):
        names = sorted(set(db.scalars(select(t_p.c.bname).where(t_p.c.snapshot_id == snap.id,
                                                                t_p.c.profile == "SAP_ALL"))))
        declared = declarations_for(db, cid)
        info = _users_in_snapshot(db, snap.id, names)
        for n in names:
            if n not in declared:
                u = info.get(n) or {}
                out.append({"username": n, "conn": snap.connection, "snap": snap,
                            "bloqueado": bool(u.get("bloqueado")), "ultimo_acceso": u.get("ultimo_acceso")})
    return out
