"""Dependencias web: sesión, usuario actual, permisos, CSRF y contexto de snapshot."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..domain.models import Severity
from ..security.auth import has_permission
from ..storage.db import get_session
from ..storage.orm import AppUser, Snapshot

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "web" / "templates"))

SEV_LABEL = {s.value: s.label for s in Severity}
TEMPLATES.env.globals["SEV_LABEL"] = SEV_LABEL
from ..actions import KIND_LABEL  # noqa: E402

TEMPLATES.env.globals["KIND_LABEL"] = KIND_LABEL
from .. import __version__  # noqa: E402

TEMPLATES.env.globals["APP_VERSION"] = __version__
from ..search import HINT as _SEARCH_HINT  # noqa: E402

TEMPLATES.env.globals["SEARCH_HINT"] = _SEARCH_HINT
TEMPLATES.env.filters["sev"] = lambda v: SEV_LABEL.get(getattr(v, "value", v), v)


def _isofecha(value: str | None) -> str:
    """«2026-11-06T14:05:59» → «06/11/2026 14:05» (hora local del servidor)."""
    from datetime import datetime
    try:
        return datetime.fromisoformat(value or "").strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return value or ""


TEMPLATES.env.filters["isofecha"] = _isofecha


class LoginRequired(Exception):
    pass


@dataclass
class CurrentUser:
    username: str
    role: str

    def can(self, perm: str) -> bool:
        return has_permission(self.role, perm)


def current_user(request: Request, db: Session = Depends(get_session)) -> CurrentUser:
    uid = request.session.get("uid")
    if not uid:
        raise LoginRequired()
    u = db.get(AppUser, uid)
    if not u or not u.active:
        request.session.clear()
        raise LoginRequired()
    return CurrentUser(u.username, u.role)


def require(perm: str):  # type: ignore[no-untyped-def]
    def dep(user: CurrentUser = Depends(current_user)) -> CurrentUser:
        if not user.can(perm):
            raise HTTPException(403, f"Permiso '{perm}' requerido")
        return user
    return dep


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["csrf"] = tok
    return tok


async def check_csrf(request: Request) -> None:
    if request.method != "POST":
        return
    form = await request.form()
    sent = form.get("csrf") or request.headers.get("x-csrf-token")
    if not sent or not secrets.compare_digest(str(sent), request.session.get("csrf", "")):
        raise HTTPException(403, "Token CSRF inválido")


_VALID = ("completo", "incompleto")


def _latest_for(db: Session, conn_id: int) -> Snapshot | None:
    q = select(Snapshot).where(Snapshot.connection_id == conn_id, Snapshot.status.in_(_VALID))
    return (db.scalars(q.where(Snapshot.analyzed_at.is_not(None)).order_by(Snapshot.id.desc())).first()
            or db.scalars(q.order_by(Snapshot.id.desc())).first())


def current_snapshot(request: Request, db: Session) -> Snapshot | None:
    """Snapshot en uso. Se trabaja por SISTEMA (conexión): por defecto, su último snapshot analizado.
    ``?sistema=<id>`` cambia de sistema; ``?snap=<id>`` fija un snapshot anterior (historial)."""
    qp, ses = request.query_params, request.session
    if qp.get("sistema", "").isdigit():
        ses["conn"] = int(qp["sistema"])
        ses.pop("snap_pin", None)
    if qp.get("snap", "").isdigit():
        snap = db.get(Snapshot, int(qp["snap"]))
        if snap is not None:
            ses["snap_pin"], ses["conn"] = snap.id, snap.connection_id
            return snap
    if ses.get("snap_pin"):
        snap = db.get(Snapshot, ses["snap_pin"])
        if snap is not None:
            return snap
        ses.pop("snap_pin", None)
    if ses.get("conn"):
        snap = _latest_for(db, ses["conn"])
        if snap is not None:
            return snap
        ses.pop("conn", None)
    # Sin sistema elegido: el primer sistema PRD (por nombre) con datos; si no hay, el último snapshot.
    from ..storage.orm import SapConnection, SapSystem
    prd = db.scalars(select(SapConnection).join(SapSystem).where(func.upper(SapSystem.environment) == "PRD")
                     .order_by(SapSystem.name, SapConnection.client)).all()
    snap = next((x for x in (_latest_for(db, c.id) for c in prd) if x is not None), None)
    snap = snap or (db.scalars(select(Snapshot).where(Snapshot.status.in_(_VALID), Snapshot.analyzed_at.is_not(None))
                               .order_by(Snapshot.id.desc())).first()
                    or db.scalars(select(Snapshot).where(Snapshot.status.in_(_VALID)).order_by(Snapshot.id.desc())).first())
    if snap is not None:
        ses["conn"] = snap.connection_id
    return snap


def systems_menu(db: Session) -> list[tuple[str, list[dict]]]:
    """Sistemas agrupados por ambiente para el selector superior (con la fecha de su último snapshot)."""
    from ..storage.orm import SapConnection
    latest: dict[int, Snapshot] = {}
    for s in db.scalars(select(Snapshot).where(Snapshot.status.in_(_VALID)).order_by(Snapshot.id.desc())):
        latest.setdefault(s.connection_id, s)
    groups: dict[str, list[dict]] = {}
    for c in db.scalars(select(SapConnection).order_by(SapConnection.id)):
        env = (c.system.environment or "OTRO").upper()
        s = latest.get(c.id)
        groups.setdefault(env, []).append({"cid": c.id, "label": c.system.label, "sid": c.system.sid,
                                           "client": c.client, "date": s.started_at if s else None,
                                           "test": bool(s and s.is_test_data)})
    order = {"PRD": 0, "QA": 1, "DEV": 2}
    return sorted(((k, sorted(v, key=lambda x: (x["label"], x["client"]))) for k, v in groups.items()),
                  key=lambda kv: order.get(kv[0], 3))


def render(request: Request, template: str, user: CurrentUser | None, db: Session, **ctx):  # type: ignore[no-untyped-def]
    cur = ctx.get("snap") or (current_snapshot(request, db) if user else None)
    pinned = None
    if cur is not None and user:
        latest = _latest_for(db, cur.connection_id)
        if latest is not None and latest.id != cur.id:
            pinned = latest  # se está viendo un snapshot anterior: ofrecer volver al último
    pending_snap = None
    if cur is not None and user:
        newest = db.scalars(select(Snapshot).where(Snapshot.connection_id == cur.connection_id)
                            .order_by(Snapshot.id.desc())).first()
        if newest is not None and newest.id > cur.id and (newest.analyzed_at is None or newest.status == "error"):
            pending_snap = newest  # extracción más nueva fallida o aún en análisis: se avisa
    base = {"request": request, "user": user, "csrf": csrf_token(request),
            "systems": systems_menu(db) if user else [], "current_snap": cur, "newer_snap": pinned,
            "pending_snap": pending_snap,
            "active": ctx.pop("active", "")}
    base.update(ctx)
    return TEMPLATES.TemplateResponse(request, template, base)
