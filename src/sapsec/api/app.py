"""Aplicación web FastAPI (interfaz en español, server-side rendering + API JSON)."""

from __future__ import annotations

import logging
import os
import secrets
import sys
from datetime import date, datetime, timedelta
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .. import __version__
from ..config import get_settings
from ..engine.analysis import analyze_role, analyze_user
from ..engine.effective import compute_effective, tcode_executable
from ..engine.incompat import forbidden_for_user, incompatible_with_role, role_function_map_if_ready
from ..engine.recommend import redundant_roles as _redundant_roles
from ..actions import (KIND_LABEL, build_tasks, get_task, role_fix_items, summary as tasks_summary,
                       user_fix_items, _key as task_key)
from .. import changes, emergency
from ..advice import emergency_user_advice, home_advice, role_advice, simulation_advice, task_advice, user_advice
from ..search import filter_values, has_wildcards, matches
from ..engine.rule_check import check_rules, summarize
from ..engine.simulator import LABELS, Scenario, ValueOverride, simulate
from ..reports.builders import executive_report, findings_report, simulation_report, user_report
from ..reports.exporters import EXPORTERS, ReportDoc
from ..security.audit import audit
from ..security.auth import AppRole, hash_password, verify_password
from ..security.secrets import store_password
import threading

from ..services import (ANALYZING, analyze_snapshot, cross_system, delete_connection, delete_snapshot, load_recommendations,
                        reset_sap_data, system_overview, context_for, dashboard_stats, data_for, get_rules, run_extraction,
                        snapshot_meta, test_connection)
from ..storage.db import get_session, init_db
from ..storage.orm import (AppUser, AuditLog, EmergencyUser, Finding, Mitigation, SapConnection, SapSystem, Snapshot,
                           utcnow)
from .deps import LoginRequired, CurrentUser, check_csrf, current_snapshot, current_user, render, require

log = logging.getLogger(__name__)
SEV_ORDER = {"critico": 4, "alto": 3, "medio": 2, "bajo": 1, "informativo": 0}


def _persistent_secret() -> str:
    """Clave de sesión guardada en data/session.key (se crea una vez). Así reiniciar no invalida los ingresos."""
    from ..config import data_dir
    path = data_dir() / "session.key"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    key = secrets.token_urlsafe(48)
    path.write_text(key, encoding="utf-8")
    return key


_BLOCKED_PAGE = (
    "<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Acceso no permitido</title>"
    "<link rel='stylesheet' href='/static/app.css'></head><body><main class='content narrow'>"
    "<h1>Acceso no permitido desde esta red</h1><div class='warnbox'>Su dirección ({ip}) no pertenece a la red de "
    "la empresa. <b>Si está fuera de la oficina, conéctese primero a la VPN</b> y vuelva a intentar.</div>"
    "<p class='muted'>Si cree que debería poder entrar, pida al administrador que agregue su red en "
    "<code>config/settings.yaml</code> (<code>network.allowed_networks</code>).</p></main></body></html>")


def create_app() -> FastAPI:
    settings = get_settings()
    secret = settings.security.session_secret or _persistent_secret()
    network_mode = os.environ.get("SAPSEC_SERVE_MODE") == "red"
    # En modo red no se publica la descripción técnica de la API (no hace falta para usar la aplicación).
    app = FastAPI(title="SAP Security Intelligence & Access Risk Analyzer", version=__version__,
                  docs_url=None if network_mode else "/api/docs", redoc_url=None,
                  openapi_url=None if network_mode else "/openapi.json")
    https = os.environ.get("SAPSEC_SERVE_HTTPS") == "1"
    # Cookie «Secure» con HTTPS. En modo red sin HTTPS (solo pruebas) no puede serlo: el navegador no la guardaría.
    secure_cookie = https if network_mode else (settings.security.secure_cookies or https)
    app.add_middleware(SessionMiddleware, secret_key=secret, same_site="strict", https_only=secure_cookie,
                       max_age=settings.security.session_max_age_minutes * 60)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parents[1] / "web" / "static")),
              name="static")
    init_db()

    @app.exception_handler(LoginRequired)
    async def _login(request: Request, exc: LoginRequired):  # type: ignore[no-untyped-def]
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "No autenticado"}, status_code=401)
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(HTTPException)
    async def _http(request: Request, exc: HTTPException):  # type: ignore[no-untyped-def]
        if exc.status_code == 403 and "CSRF" in str(exc.detail) and not request.url.path.startswith("/api/"):
            if request.url.path == "/login":
                return RedirectResponse("/login?expirado=1", status_code=303)
            return HTMLResponse(
                "<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Sesión vencida</title>"
                "<link rel='stylesheet' href='/static/app.css'></head><body><main class='content'>"
                "<h1>El formulario venció</h1><div class='warnbox'>La página estaba abierta desde antes de un reinicio "
                "o de un nuevo ingreso. Vuelva atrás, recargue la página (F5) e intente de nuevo.</div>"
                "<p><a href='/'>Ir al inicio</a></p></main></body></html>", status_code=403)
        if request.url.path.startswith("/api/") or exc.status_code not in (400, 403, 404, 409):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        import html as _h
        return HTMLResponse(
            "<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Aviso</title>"
            "<link rel='stylesheet' href='/static/app.css'></head><body><main class='content'>"
            f"<h1>No se pudo completar la acción</h1><div class='warnbox'>{_h.escape(str(exc.detail))}</div>"
            "<p><a href='javascript:history.back()'>Volver</a> · <a href='/'>Inicio</a></p></main></body></html>",
            status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):  # type: ignore[no-untyped-def]
        ref = secrets.token_hex(4).upper()
        log.exception("Error no controlado ref=%s en %s", ref, request.url.path)
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "Error interno", "referencia": ref}, status_code=500)
        return HTMLResponse(
            "<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Error</title>"
            "<link rel='stylesheet' href='/static/app.css'></head><body><main class='content'>"
            f"<h1>Ocurrió un error inesperado</h1><div class='errbox'>Referencia <b>{ref}</b>: "
            f"{type(exc).__name__}: {str(exc)[:300]}</div>"
            "<p>El detalle técnico completo quedó en <code>data\\logs\\sapsec.log</code> "
            f"(buscar «ref={ref}»).</p><p><a href='javascript:history.back()'>Volver</a> · <a href='/'>Inicio</a></p>"
            "</main></body></html>", status_code=500)

    @app.middleware("http")
    async def _headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                                   "style-src 'self'; script-src 'self'")
        return resp

    from ..security.network import client_allowed, parse_networks
    allowed_nets = parse_networks(settings.network.allowed_networks)

    @app.middleware("http")
    async def _network_guard(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Solo la red de la empresa (y la VPN): las direcciones de internet no llegan a la aplicación."""
        host = request.client.host if request.client else None
        if not client_allowed(host, allowed_nets):
            log.warning("Acceso rechazado desde %s (fuera de las redes permitidas): %s", host, request.url.path)
            import html as _h
            resp: Response = HTMLResponse(_BLOCKED_PAGE.replace("{ip}", _h.escape(str(host))), status_code=403)
            resp.headers["Content-Security-Policy"] = "default-src 'self'"
            resp.headers["X-Frame-Options"] = "DENY"
            return resp
        return await call_next(request)

    _routes(app)
    _warm_up_async()
    threading.Thread(target=_queue_worker, daemon=True, name="cola-extracciones").start()
    return app


def _need_snap(request: Request, db: Session) -> Snapshot:
    snap = current_snapshot(request, db)
    if snap is None:
        raise HTTPException(409, "No hay snapshots. Registre una conexión y ejecute una extracción.")
    return snap


def _eff_cache(data: Any, ctx: Any) -> dict:
    cache = getattr(data, "_eff_cache", None)
    if cache is None or cache.get("_as_of") != ctx.as_of:
        cache = {"_as_of": ctx.as_of}
        data._eff_cache = cache  # noqa: SLF001
    return cache


def _routes(app: FastAPI) -> None:  # noqa: C901 - registro de rutas
    # ------------------------------------------------------------------ autenticación
    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        msg = "La sesión anterior venció. Ingrese nuevamente." if request.query_params.get("expirado") else None
        return render(request, "login.html", None, db, error=msg, **_login_ctx(request))

    @app.post("/login")
    async def login(request: Request, username: str = Form(...), password: str = Form(...),
                    db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        u = db.scalars(select(AppUser).where(AppUser.username == username.strip())).first()
        ip = request.client.host if request.client else ""
        sec = get_settings().security
        locked = u is not None and _is_locked(u, sec.max_failed_logins, sec.lockout_minutes)
        if not u or not u.active or locked or not verify_password(password, u.password_hash):
            if u and not locked:
                u.failed_logins += 1
                u.last_failed_at = utcnow()
            audit(db, username, "login_fallido", "", {"bloqueado": True} if locked else None, ip=ip)
            wait = (f"se bloquea {sec.lockout_minutes} minutos" if sec.lockout_minutes
                    else "se bloquea hasta que un administrador lo desbloquee")
            return render(request, "login.html", None, db,
                          error=f"Credenciales inválidas o usuario bloqueado (tras {sec.max_failed_logins} intentos "
                                f"fallidos {wait}).", **_login_ctx(request))
        u.failed_logins, u.last_failed_at, u.last_login_at = 0, None, utcnow()
        request.session.clear()
        request.session["uid"] = u.id
        audit(db, u.username, "login", ip=ip)
        n_conn = db.scalar(select(func.count()).select_from(SapConnection)) or 0
        return RedirectResponse("/sistemas" if n_conn > 1 else "/", status_code=303)

    @app.get("/logout")
    def logout(request: Request):  # type: ignore[no-untyped-def]
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    # ------------------------------------------------------------------ certificado HTTPS (público: no es secreto)
    @app.get("/certificado", response_class=HTMLResponse)
    def certificate_page(request: Request, db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..security.network import serve_info
        uid = request.session.get("uid")
        u = db.get(AppUser, uid) if uid else None
        cu = CurrentUser(u.username, u.role) if u and u.active else None
        return render(request, "certificate.html", cu, db, active="configuracion", net=serve_info())

    @app.get("/certificado/ca.crt")
    def certificate_download():  # type: ignore[no-untyped-def]
        from ..security.network import local_ca
        ca = local_ca()
        if ca is None:
            raise HTTPException(404, "Esta instalación usa un certificado de la empresa: no hay CA local para instalar.")
        return Response(ca.read_bytes(), media_type="application/x-x509-ca-cert",
                        headers={"Content-Disposition": 'attachment; filename="SAP-Security-Analyzer-CA.crt"'})

    # ------------------------------------------------------------------ mi cuenta
    @app.get("/mi-cuenta", response_class=HTMLResponse)
    def my_account(request: Request, user: CurrentUser = Depends(current_user), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        me = db.scalars(select(AppUser).where(AppUser.username == user.username)).one()
        return render(request, "account.html", user, db, active="", me=me, ok=request.query_params.get("ok"))

    @app.post("/mi-cuenta/contrasena")
    async def my_password(request: Request, user: CurrentUser = Depends(current_user), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        form = await request.form()
        me = db.scalars(select(AppUser).where(AppUser.username == user.username)).one()
        if not verify_password(str(form.get("actual", "")), me.password_hash):
            raise HTTPException(400, "La contraseña actual no es correcta.")
        new_pw = str(form.get("nueva", ""))
        if new_pw != str(form.get("repetir", "")):
            raise HTTPException(400, "La contraseña nueva y su repetición no coinciden.")
        try:
            me.password_hash = hash_password(new_pw)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        audit(db, user.username, "contrasena_cambiada", user.username, ip=_ip(request))
        return RedirectResponse("/mi-cuenta?ok=1", status_code=303)

    # ------------------------------------------------------------------ dashboard
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = current_snapshot(request, db)
        if snap is None:
            return render(request, "empty.html", user, db, active="dashboard")
        if snap.analyzed_at is None:
            if snap.id in ANALYZING or _job_running():
                return render(request, "empty.html", user, db, active="dashboard",
                              busy=f"El snapshot #{snap.id} se está analizando. Vuelva en unos minutos.")
            analyze_snapshot(db, snap.id)
        stats = dashboard_stats(db, snap)
        tasks = build_tasks(db, snap, get_rules())
        top = [t for t in tasks if t.pending][:9]
        reco = home_advice(top[0] if top else None, None, _env(snap))
        cross = _safe(lambda: cross_system(db, prd_snapshot_id=snap.id), {"rows": []}, "control entre sistemas") \
            if _env(snap) == "PRD" else {"rows": []}
        prev = changes.previous_of(db, snap)
        delta = _safe(lambda: changes.alert_delta(db, prev, snap), None, "cambios") if prev is not None else None
        return render(request, "dashboard.html", user, db, active="dashboard", snap=snap, stats=stats, top=top,
                      first=top[0] if top else None, nxt=top[1:], reco=reco, summ=tasks_summary(tasks),
                      meta=snapshot_meta(snap), cross=cross, prev=prev, delta=delta)

    # ------------------------------------------------------------------ plan de acción
    @app.get("/acciones", response_class=HTMLResponse)
    def plan(request: Request, q: str = "", gravedad: str = "", tipo: str = "", estado: str = "pendientes",
             limite: int = 100, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        tasks = build_tasks(db, snap, get_rules())
        sel = [t for t in tasks
               if (estado == "todas" or (estado == "resueltas") != t.pending)
               and (not gravedad or t.severity == gravedad) and (not tipo or t.kind == tipo)
               and (not q.strip() or matches(q, t.title, t.subtitle, *t.roles, *t.users,
                                             *[p.title for p in t.problems]))]
        from urllib.parse import urlencode
        more = urlencode({"q": q, "gravedad": gravedad, "tipo": tipo, "estado": estado, "limite": limite + 200})
        return render(request, "plan.html", user, db, active="plan", shown=sel[:limite], total=len(sel),
                      more_qs=more, f={"q": q, "gravedad": gravedad, "tipo": tipo, "estado": estado})

    @app.get("/acciones/{key}", response_class=HTMLResponse)
    def task_detail(key: str, request: Request, user: CurrentUser = Depends(require("ver")),
                    db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        t = get_task(db, snap, get_rules(), key)
        if t is None:
            raise HTTPException(404, "La tarea no existe en el snapshot seleccionado (puede estar resuelta en uno más "
                                     "nuevo o pertenecer a otro sistema).")
        data = data_for(snap)
        today = date.today()
        users = []
        for uname in t.users[:300]:
            u = data.users.get(uname)
            if u is None:
                continue
            mine = sorted({a.role for a in data.user_assignments(uname) if a.state(today) == "vigente"} & set(t.roles))
            users.append({"username": uname, "full_name": u.full_name, "type": u.type_label, "lock": u.lock_label,
                          "last_logon": u.last_logon, "roles": mine, "locked": u.is_locked})
        users.sort(key=lambda x: (x["locked"], x["username"]))  # primero quienes hoy pueden ingresar
        emer = emergency.record_for(db, snap)
        audit(db, user.username, "consulta_tarea", t.title)
        return render(request, "task.html", user, db, active="plan", t=t, users=users, emer=emer,
                      emer_label=emergency.STATE_LABEL, reco=task_advice(t, data, _env(snap)))

    @app.post("/acciones/{key}/gestionar")
    async def task_manage(key: str, request: Request, user: CurrentUser = Depends(require("hallazgos_gestionar")),
                          db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        snap = _need_snap(request, db)
        t = get_task(db, snap, get_rules(), key) or _404()
        form = await request.form()
        status = str(form.get("status", ""))
        if status not in ("en_revision", "excepcion", "mitigado", "falso_positivo"):
            raise HTTPException(400, "Decisión inválida")
        just = str(form.get("exception_justification") or "").strip()
        exp = str(form.get("exception_expires") or "")
        if status in ("excepcion", "falso_positivo") and not just:
            raise HTTPException(400, "Una excepción o un falso positivo requiere justificación.")
        if status == "excepcion" and not exp:
            raise HTTPException(400, "Una excepción requiere fecha de vencimiento.")
        owner = str(form.get("owner") or "").strip() or None
        n = 0
        for f in db.scalars(select(Finding).where(Finding.id.in_(t.open_ids))):
            f.status = status
            f.owner = owner or f.owner
            if just:
                f.exception_justification = just
            if exp:
                f.exception_expires = datetime.fromisoformat(exp)
            n += 1
        audit(db, user.username, "tarea_gestionada", t.title, {"estado": status, "hallazgos": n})
        return RedirectResponse(f"/acciones/{key}", status_code=303)

    # ------------------------------------------------------------------ conexiones
    @app.get("/conexiones", response_class=HTMLResponse)
    def connections(request: Request, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        conns = db.scalars(select(SapConnection).order_by(SapConnection.id)).all()
        snaps = db.scalars(select(Snapshot).order_by(Snapshot.id.desc()).limit(50)).all()
        counts = dict(db.execute(select(Snapshot.connection_id, func.count()).group_by(Snapshot.connection_id)).all())
        landscapes = sorted({(c.system.landscape or "") for c in conns} - {""})
        return render(request, "connections.html", user, db, active="conexiones", conns=conns, snaps_all=snaps,
                      snap_counts=counts, deleted=request.query_params.get("borrado", ""), landscapes=landscapes,
                      updated=request.query_params.get("actualizado", ""))

    @app.post("/conexiones")
    async def connection_create(request: Request, user: CurrentUser = Depends(require("conexiones")),
                                db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        f = await request.form()
        sid = str(f.get("sid", "")).strip().upper()
        if not sid or not str(f.get("client", "")).strip():
            raise HTTPException(400, "SID y mandante son obligatorios")
        sys_name = str(f.get("system_name") or "").strip() or sid
        system = db.scalars(select(SapSystem).where(func.lower(SapSystem.name) == sys_name.lower())).first()
        if system is None and sys_name == sid:  # compatibilidad: sistemas creados sin nombre
            system = db.scalars(select(SapSystem).where(SapSystem.sid == sid, SapSystem.name == "")).first()
        if system is not None and system.sid != sid:
            raise HTTPException(400, f"Ya existe un sistema llamado «{system.label}» con SID {system.sid}. "
                                     "Use otro nombre para este sistema.")
        if system is None:
            env = str(f.get("environment", "DEV"))
            system = SapSystem(sid=sid, name=sys_name, description=str(f.get("description", "")), environment=env,
                               productive=env == "PRD", landscape=str(f.get("landscape") or "").strip()[:100],
                               sensitivity=float(f.get("sensitivity") or {"PRD": 1.0, "QA": 0.6, "DEV": 0.5}.get(env, 0.7)))
            db.add(system)
            db.flush()
        backend = str(f.get("backend", "nwrfc"))
        conn = SapConnection(
            system_id=system.id, client=str(f["client"]).strip(), name=str(f.get("name") or f"{sid}/{f['client']}"),
            backend=backend, ashost=str(f.get("ashost") or "") or None, sysnr=str(f.get("sysnr") or "") or None,
            mshost=str(f.get("mshost") or "") or None, msserv=str(f.get("msserv") or "") or None,
            logon_group=str(f.get("logon_group") or "") or None, saprouter=str(f.get("saprouter") or "") or None,
            rfc_user=str(f.get("rfc_user", "")).strip().upper(), lang=str(f.get("lang") or "ES"),
            snc_mode=f.get("snc_mode") == "on", snc_qop=str(f.get("snc_qop") or "") or None,
            snc_myname=str(f.get("snc_myname") or "") or None,
            snc_partnername=str(f.get("snc_partnername") or "") or None, snc_lib=str(f.get("snc_lib") or "") or None,
            fixture_path=str(f.get("fixture_path") or "") or None,
            user_logon_source=str(f.get("user_logon_source") or "usr02_restricted"),
            limits={"max_rows_per_call": int(f.get("max_rows_per_call") or 20000),
                    "max_calls_per_minute": int(f.get("max_calls_per_minute") or 120),
                    "batch_size_in_list": int(f.get("batch_size_in_list") or 150)})
        db.add(conn)
        db.flush()
        pw = str(f.get("password") or "")
        if pw and backend != "fixture":
            ref = f"{sid}-{conn.client}-{conn.rfc_user}-{conn.id}"
            store_password(ref, pw)
            conn.credential_ref = ref
        audit(db, user.username, "conexion_creada", f"{sid}/{conn.client}", {"backend": backend})
        return RedirectResponse("/conexiones", status_code=303)

    @app.post("/conexiones/{cid}/probar")
    async def connection_test(cid: int, request: Request, user: CurrentUser = Depends(require("extraer")),
                              db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        conn = db.get(SapConnection, cid) or _404()
        res = test_connection(conn)
        conn.last_test_at, conn.last_test_result = utcnow(), res
        audit(db, user.username, "conexion_probada", conn.name, {"ok": res.get("ok")})
        return RedirectResponse(f"/conexiones#c{cid}", status_code=303)

    @app.post("/conexiones/{cid}/extraer")
    async def connection_extract(cid: int, request: Request, user: CurrentUser = Depends(require("extraer")),
                                 db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        conn = db.get(SapConnection, cid) or _404()
        audit(db, user.username, "extraccion_solicitada", conn.label)
        _enqueue(cid, conn.label, user.username)
        return RedirectResponse(f"/conexiones/{cid}/progreso", status_code=303)

    @app.get("/conexiones/{cid}/progreso", response_class=HTMLResponse)
    def connection_progress(cid: int, request: Request, user: CurrentUser = Depends(require("ver")),
                            db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        job = _job_state(cid)
        if job is None:
            return RedirectResponse("/conexiones", status_code=303)
        elapsed = int((datetime.now() - job["inicio"]).total_seconds())
        return render(request, "progress.html", user, db, active="sistemas", job=job, cid=cid,
                      position=_queue_position(cid), running=_running_label(),
                      elapsed=f"{elapsed // 60} min {elapsed % 60:02d} s")

    @app.get("/sistemas", response_class=HTMLResponse)
    def systems_overview(request: Request, user: CurrentUser = Depends(require("ver")),
                         db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        rows = system_overview(db)
        for r in rows:
            j = _job_state(r["conn"].id)
            r["job"] = j["estado"] if j else ""
        envs = sorted({r["env"] for r in rows}, key=lambda e: {"PRD": 0, "QA": 1, "DEV": 2}.get(e, 3))
        return render(request, "systems.html", user, db, active="sistemas", rows=rows, envs=envs,
                      queue=[(JOBS[c]["conexion"]) for c, _ in QUEUE if c in JOBS], running=_running_label(),
                      keep=get_settings().snapshots_to_keep)

    @app.post("/sistemas/extraer")
    async def systems_extract(request: Request, user: CurrentUser = Depends(require("extraer")),
                              db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        env = str((await request.form()).get("ambiente", "")).upper()
        n = 0
        for c in db.scalars(select(SapConnection).where(SapConnection.active.is_(True)).order_by(SapConnection.id)):
            if env and env != "TODOS" and (c.system.environment or "").upper() != env:
                continue
            _enqueue(c.id, c.label, user.username)
            n += 1
        audit(db, user.username, "extraccion_masiva", env or "TODOS", {"sistemas": n})
        return RedirectResponse("/sistemas", status_code=303)

    # ------------------------------------------------------------------ extracciones programadas
    @app.get("/programacion", response_class=HTMLResponse)
    def schedules_page(request: Request, user: CurrentUser = Depends(require("ver")),
                       db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..scheduler import describe_what, describe_when, is_running, next_run, when_label
        from ..storage.orm import ExtractionSchedule
        now = datetime.now()
        rows = [{"s": x, "when": describe_when(x), "what": describe_what(db, x),
                 "next": when_label(next_run(x, now), now) if x.enabled else "pausada",
                 "last": when_label(x.finished_at, now) if x.finished_at else "",
                 "running": is_running(x, now)}
                for x in db.scalars(select(ExtractionSchedule).order_by(ExtractionSchedule.id))]
        conns = db.scalars(select(SapConnection).order_by(SapConnection.id)).all()
        return render(request, "schedules.html", user, db, active="programacion", rows=rows, conns=conns,
                      win_task=_windows_task_state(), is_windows=sys.platform == "win32", now=now)

    @app.post("/programacion")
    async def schedule_create(request: Request, user: CurrentUser = Depends(require("conexiones")),
                              db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..scheduler import parse_time
        from ..storage.orm import ExtractionSchedule
        await check_csrf(request)
        form = await request.form()
        hhmm = str(form.get("time_hhmm") or "03:00")[:5]
        try:
            parse_time(hhmm)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        days = sorted({int(d) for d in form.getlist("days") if str(d).isdigit() and 0 <= int(d) <= 6})
        if not days:
            raise HTTPException(400, "Elija al menos un día.")
        env = str(form.get("environment") or "TODOS").upper()
        ids = [int(x) for x in form.getlist("connection_ids") if str(x).isdigit()]
        sch = ExtractionSchedule(name=str(form.get("name") or f"Extracción {env} {hhmm}").strip()[:100],
                                 time_hhmm=hhmm, days=",".join(map(str, days)), environment=env,
                                 connection_ids=ids, created_by=user.username)
        # La franja de hoy, si ya pasó, no se ejecuta al crear la programación: empieza en la próxima.
        from ..scheduler import slot_for
        today_slot = slot_for(sch, datetime.now())
        if today_slot <= datetime.now():
            sch.last_slot = today_slot
        db.add(sch)
        audit(db, user.username, "programacion_creada", sch.name, {"hora": hhmm, "dias": days, "ambiente": env})
        return RedirectResponse("/programacion", status_code=303)

    @app.post("/programacion/{sid}/{accion}")
    async def schedule_action(sid: int, accion: str, request: Request, user: CurrentUser = Depends(require("extraer")),
                              db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..scheduler import is_running
        from ..storage.orm import ExtractionSchedule
        await check_csrf(request)
        sch = db.get(ExtractionSchedule, sid) or _404()
        if accion == "ejecutar":
            if is_running(sch):
                raise HTTPException(409, "Esta programación ya se está ejecutando.")
            _spawn_schedule(sid, "manual")
        elif accion in ("activar", "pausar", "eliminar"):
            if not user.can("conexiones"):
                raise HTTPException(403, "Permiso 'conexiones' requerido")
            if accion == "eliminar":
                db.delete(sch)
            else:
                sch.enabled = accion == "activar"
        else:
            raise HTTPException(400, "Acción desconocida")
        audit(db, user.username, f"programacion_{accion}", sch.name)
        return RedirectResponse("/programacion", status_code=303)

    @app.get("/sistemas/{cid}", response_class=HTMLResponse)
    def system_history(cid: int, request: Request, user: CurrentUser = Depends(require("ver")),
                       db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        conn = db.get(SapConnection, cid) or _404()
        snaps = db.scalars(select(Snapshot).where(Snapshot.connection_id == cid).order_by(Snapshot.id.desc())).all()
        counts = {sid_: n for sid_, n in db.execute(
            select(Finding.snapshot_id, func.count()).where(Finding.snapshot_id.in_([x.id for x in snaps]),
                                                            Finding.status.not_in(["corregido", "falso_positivo"]))
            .group_by(Finding.snapshot_id)).all()} if snaps else {}
        latest = next((x for x in snaps if x.analyzed_at is not None), None)
        return render(request, "system_history.html", user, db, active="sistemas", conn=conn, snaps_all=snaps,
                      counts=counts, latest=latest, keep=get_settings().snapshots_to_keep)

    @app.get("/entre-sistemas", response_class=HTMLResponse)
    def cross_page(request: Request, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..advice import cross_advice
        data = cross_system(db)
        audit(db, user.username, "consulta_entre_sistemas", f"{len(data['rows'])} casos")
        landscapes = sorted({(c.system.landscape or "") for c in db.scalars(select(SapConnection))} - {""})
        return render(request, "cross_system.html", user, db, active="entre", x=data, reco=cross_advice(data),
                      landscapes=landscapes)

    @app.post("/sistemas/{system_id}/datos")
    async def system_update(system_id: int, request: Request, user: CurrentUser = Depends(require("conexiones")),
                            db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        f = await request.form()
        system = db.get(SapSystem, system_id) or _404()
        before = {"landscape": system.landscape, "ambiente": system.environment}
        system.landscape = str(f.get("landscape") or "").strip()[:100]
        env = str(f.get("environment") or system.environment).upper()
        if env not in ("PRD", "QA", "DEV", "OTRO"):
            raise HTTPException(400, "Ambiente inválido")
        if env != system.environment:
            system.environment, system.productive = env, env == "PRD"
            system.sensitivity = {"PRD": 1.0, "QA": 0.6, "DEV": 0.5}.get(env, 0.7)  # factor de riesgo del ambiente
        audit(db, user.username, "sistema_actualizado", system.label,
              {"antes": before, "despues": {"landscape": system.landscape, "ambiente": system.environment}})
        return RedirectResponse("/conexiones?actualizado=" + str(system_id), status_code=303)

    @app.post("/conexiones/{cid}/huella")
    async def connection_reset_fingerprint(cid: int, request: Request,
                                           user: CurrentUser = Depends(require("conexiones")),
                                           db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        conn = db.get(SapConnection, cid) or _404()
        before = conn.fingerprint
        conn.fingerprint = ""
        audit(db, user.username, "huella_restablecida", conn.label, {"anterior": before})
        return RedirectResponse(f"/conexiones#c{cid}", status_code=303)

    @app.post("/conexiones/{cid}/eliminar")
    async def connection_delete(cid: int, request: Request, user: CurrentUser = Depends(require("conexiones")),
                                db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        job = _job_state(cid)
        if job and job["estado"] == "en_curso":
            raise HTTPException(409, "Hay una extracción en curso para esta conexión; espere a que termine.")
        try:
            res = delete_connection(db, cid)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc
        JOBS.pop(cid, None)
        if request.session.get("conn") == cid:
            request.session.pop("conn", None)
            request.session.pop("snap_pin", None)
        audit(db, user.username, "conexion_eliminada", res["sistema"], res)
        return RedirectResponse("/conexiones?borrado=" + res["sistema"], status_code=303)

    @app.post("/snapshots/{sid}/eliminar")
    async def snapshot_delete(sid: int, request: Request, user: CurrentUser = Depends(require("conexiones")),
                              db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        if _job_running():
            raise HTTPException(409, "Hay una extracción en curso; espere a que termine para borrar snapshots.")
        snap = db.get(Snapshot, sid) or _404()
        label = f"#{snap.id} {snap.sid}/{snap.client}"
        try:
            counts = delete_snapshot(db, sid)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        if request.session.get("snap_pin") == sid:
            request.session.pop("snap_pin", None)
        audit(db, user.username, "snapshot_eliminado", label, {"filas": sum(counts.values())})
        return RedirectResponse("/conexiones?borrado=snapshot " + label, status_code=303)

    @app.post("/configuracion/borrar-datos-sap")
    async def reset_all(request: Request, user: CurrentUser = Depends(require("conexiones")),
                        db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        form = await request.form()
        if str(form.get("confirmar", "")).strip().upper() != "BORRAR":
            raise HTTPException(400, "Para confirmar escriba BORRAR en el campo de confirmación.")
        if _job_running():
            raise HTTPException(409, "Hay una extracción en curso; espere a que termine.")
        res = reset_sap_data(db)
        JOBS.clear()
        QUEUE.clear()
        request.session.pop("snap_pin", None)
        request.session.pop("conn", None)
        audit(db, user.username, "datos_sap_borrados", "todos",
              {"conexiones": [c["sistema"] for c in res["conexiones"]]})
        return RedirectResponse("/conexiones?borrado=todo", status_code=303)

    @app.get("/snapshots/{sid}", response_class=HTMLResponse)
    def snapshot_view(sid: int, request: Request, user: CurrentUser = Depends(require("ver")),
                      db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = db.get(Snapshot, sid) or _404()
        return render(request, "snapshot.html", user, db, active="conexiones", s=snap)

    # ------------------------------------------------------------------ usuarios
    @app.get("/usuarios", response_class=HTMLResponse)
    def users(request: Request, q: str = "", tipo: str = "", estado: str = "", rol: str = "", perfil: str = "",
              riesgo: str = "", user: CurrentUser = Depends(require("ver")),
              db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        data = data_for(snap)
        today = date.today()
        levels: dict[str, str] = {}
        for f in db.scalars(select(Finding).where(Finding.snapshot_id == snap.id, Finding.subject_user.is_not(None),
                                                  Finding.status.not_in(["corregido", "falso_positivo"]))):
            if SEV_ORDER[f.severity] > SEV_ORDER.get(levels.get(f.subject_user, "informativo"), 0):
                levels[f.subject_user] = f.severity  # type: ignore[index]
        inactivity = get_settings().analysis.inactivity_days
        rows = []
        for u in sorted(data.users.values(), key=lambda x: x.username):
            if q and not matches(q, u.username, u.full_name):
                continue
            if tipo and u.user_type != tipo:
                continue
            inactive = u.last_logon is None or (today - u.last_logon).days > inactivity
            if (estado == "bloqueado" and not u.is_locked or estado == "activo" and u.is_locked
                    or estado == "inactivo" and not (inactive and not u.is_locked)):
                continue
            nivel = levels.get(u.username, "informativo")
            if riesgo and SEV_ORDER.get(nivel, 0) < SEV_ORDER.get(riesgo, 0):
                continue
            roles = [a for a in data.user_assignments(u.username)]
            vig = [a.role for a in roles if a.state(today) == "vigente"]
            profs = data.user_profiles.get(u.username, [])
            if rol and not matches(rol, *vig):
                continue
            if perfil and not matches(perfil, *profs):
                continue
            rows.append({"u": u, "roles": len(vig), "vencidos": sum(1 for a in roles if a.state(today) == "vencida"),
                         "perfiles": len(profs), "nivel": nivel, "inactivo": inactive,
                         "sap_all": any("SAP_ALL" in data.profile_tree(p) for p in profs)})
        return render(request, "users.html", user, db, active="usuarios", rows=rows, q=q, tipo=tipo, estado=estado,
                      rol=rol, perfil=perfil, riesgo=riesgo)

    @app.get("/usuarios/{username}", response_class=HTMLResponse)
    def user_detail(username: str, request: Request, user: CurrentUser = Depends(require("ver")),
                    db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        data = data_for(snap)
        if username not in data.users:
            raise HTTPException(404, f"El usuario {username} no existe en {snap.connection.label}. "
                                     "Puede que exista en otro sistema: cambie el sistema en el selector superior.")
        ctx = context_for(db, snap)
        a = analyze_user(ctx, data, username)
        audit(db, user.username, "consulta_usuario", f"{snap.sid}/{snap.client}/{username}")
        objects = sorted(a.eff.instances.values(), key=lambda e: e.instance.key)
        expiring = [x for x in a.eff.assignments if x.valid_to and 0 <= (x.valid_to - ctx.as_of).days
                    <= get_settings().analysis.expiring_role_days]
        redundant = _safe(lambda: _redundant_roles(a), [], "roles redundantes")
        forbidden = None
        if role_function_map_if_ready(ctx.rules, data, ctx.as_of) is not None:
            forbidden = _safe(lambda: forbidden_for_user(ctx.rules, data, a.eff, ctx.as_of,
                                                         environment=ctx.environment), [], "roles a no asignar")
        else:
            _start_precompute(snap.id)
        fixes = user_fix_items(ctx.rules, a)
        su = a.eff.user
        idle = (ctx.as_of - su.last_logon).days if getattr(su, "last_logon", None) else None
        emer = emergency.record_for(db, snap).get(username)
        if emer:  # usuario de emergencia declarado: todo lo suyo se gestiona en su propia tarea
            for f in fixes:
                f["task"] = task_key("emergencia")
                f["change"] = "lo tiene a propósito: se controla manteniéndolo bloqueado"
            reco = emergency_user_advice(username, emer)
        else:
            reco = user_advice(username, su, fixes, sorted(getattr(a.eff, "_direct", set()) or []), idle,
                               get_settings().analysis.inactivity_days)
        return render(request, "user_detail.html", user, db, active="usuarios", a=a, objects=objects,
                      expiring=expiring, redundant=redundant, data=data, snap=snap, as_of=ctx.as_of,
                      forbidden=forbidden, fixes=fixes, reco=reco, fiori_services=_fiori_services(a.eff, data),
                      emer=emer, emer_label=emergency.STATE_LABEL)

    # ------------------------------------------------------------------ roles
    @app.get("/roles", response_class=HTMLResponse)
    def roles(request: Request, q: str = "", tipo: str = "", user: CurrentUser = Depends(require("ver")),
              db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        data = data_for(snap)
        flagged: dict[str, list[str]] = {}
        for f in db.scalars(select(Finding).where(Finding.snapshot_id == snap.id, Finding.subject_role.is_not(None))):
            flagged.setdefault(f.subject_role, []).append(f.rule_id)  # type: ignore[arg-type]
        rows = []
        for r in sorted(data.role_names):
            if q and not matches(q, r, data.role_text.get(r, "")):
                continue
            rt = data.role_type(r)
            if tipo and rt != tipo:
                continue
            rows.append({"name": r, "text": data.role_text.get(r, ""), "type": rt,
                         "users": len(data.role_users_raw.get(r, [])), "z": r.startswith(("Z", "Y")),
                         "flags": flagged.get(r, []), "generated": bool(data.role_profiles.get(r))})
        return render(request, "roles.html", user, db, active="roles", rows=rows, q=q, tipo=tipo)

    @app.get("/roles/{role}", response_class=HTMLResponse)
    def role_detail(role: str, request: Request, user: CurrentUser = Depends(require("ver")),
                    db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        data = data_for(snap)
        if role not in data.role_names:
            raise HTTPException(404, f"El rol {role} no existe en {snap.connection.label}. "
                                     "Puede que exista en otro sistema: cambie el sistema en el selector superior.")
        ctx = context_for(db, snap)
        ra = analyze_role(ctx, data, role)
        similar = _safe(lambda: _similar_roles(data, role, ra), [], "roles similares")
        incompat, intra = None, []
        if role_function_map_if_ready(ctx.rules, data, ctx.as_of) is not None:
            incompat, intra = _safe(lambda: incompatible_with_role(ctx.rules, data, role, ctx.as_of,
                                                                   environment=ctx.environment), ([], []),
                                    "incompatibilidades")
        else:
            _start_precompute(snap.id)
        audit(db, user.username, "consulta_rol", f"{snap.sid}/{snap.client}/{role}")
        fixes = role_fix_items(ctx.rules, ra)
        tkey = task_key("rol", role)
        has_task = get_task(db, snap, ctx.rules, tkey) is not None
        reco = role_advice(role, ra.role_type, fixes, data.role_parent.get(role, ""), len(ra.users), _env(snap),
                           tkey if has_task else None)
        return render(request, "role_detail.html", user, db, active="roles", ra=ra, data=data, similar=similar,
                      incompat=incompat, intra=intra, fixes=fixes, task_key=tkey if has_task else None, reco=reco,
                      fiori_services=_fiori_services(ra.eff, data),
                      objects=sorted(ra.eff.instances.values(), key=lambda e: e.instance.key))

    # ------------------------------------------------------------------ búsqueda inversa
    @app.get("/objetos", response_class=HTMLResponse)
    def reverse(request: Request, objeto: str = "", campo: str = "", valor: str = "", comodin: str = "",
                tcode: str = "", rol: str = "", perfil: str = "", gravedad: str = "",
                user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        data = data_for(snap)
        ctx = context_for(db, snap)
        searched = any([objeto, tcode, rol, perfil, gravedad])
        results = []
        if searched:
            objeto, campo, valor = objeto.strip().upper(), campo.strip().upper(), valor.strip()
            sev_users: dict[str, int] = {}
            if gravedad:
                for f in db.scalars(select(Finding).where(Finding.snapshot_id == snap.id,
                                                          Finding.subject_user.is_not(None))):
                    sev_users[f.subject_user] = max(sev_users.get(f.subject_user, -1), SEV_ORDER[f.severity])  # type: ignore[index]
            cache = _eff_cache(data, ctx)
            # Comodines como en SAP: S_TABU* = todos los objetos que empiezan así; SE* = esas transacciones
            objs = filter_values(objeto, sorted(data.object_fields), exact_without_wildcards=True) if objeto else []
            tcodes = (filter_values(tcode.strip(), sorted(data.tcode_program), exact_without_wildcards=True)[:50]
                      if tcode and has_wildcards(tcode) else [tcode.strip().upper()] if tcode else [])
            for uname in sorted(data.users):
                if gravedad and sev_users.get(uname, -1) < SEV_ORDER[gravedad]:
                    continue
                if perfil and not matches(perfil, *data.user_profiles.get(uname, [])):
                    continue
                eff = cache.get(uname) or cache.setdefault(uname, compute_effective(data, uname, ctx.as_of))
                if rol and not matches(rol, *eff.valid_roles()):
                    continue
                evidence = []
                if objeto:
                    for e in [x for o in objs for x in eff.by_object(o)]:
                        if campo:
                            if comodin and not e.instance.field_is_full_wildcard(campo):
                                continue
                            if valor and not e.instance.field_covers(campo, valor):
                                continue
                            if not valor and not comodin and not e.instance.values(campo):
                                continue
                        evidence.append(e)
                    if not evidence:
                        continue
                if tcode:
                    found = next(((t, ev) for t in tcodes for ok, ev, _ in [tcode_executable(eff, data, t)] if ok), None)
                    if found is None:
                        continue
                    evidence += found[1]
                results.append({"user": data.users[uname], "evidence": evidence[:5]})
            audit(db, user.username, "busqueda_inversa", f"{snap.sid}/{snap.client}",
                  {"objeto": objeto, "campo": campo, "valor": valor, "tcode": tcode})
        fields = data.object_fields.get(objeto.upper(), []) if objeto and not has_wildcards(objeto) else []
        return render(request, "reverse.html", user, db, active="objetos", results=results, searched=searched,
                      p={"objeto": objeto, "campo": campo, "valor": valor, "comodin": comodin, "tcode": tcode,
                         "rol": rol, "perfil": perfil, "gravedad": gravedad}, fields=fields,
                      objects=sorted(data.object_fields), data=data)

    # ------------------------------------------------------------------ hallazgos
    def _findings_page(request: Request, user: CurrentUser, db: Session, kinds: list[str], template: str,
                       active: str, title: str):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        sev = request.query_params.get("gravedad", "")
        st = request.query_params.get("estado", "")
        regla = request.query_params.get("regla", "")
        q = request.query_params.get("q", "")
        stmt = select(Finding).where(Finding.snapshot_id == snap.id, Finding.kind.in_(kinds))
        if regla:
            stmt = stmt.where(Finding.rule_id == regla)
        rows = [f for f in db.scalars(stmt) if (not sev or f.severity == sev) and (not st or f.status == st)
                and (not q.strip() or matches(q, f.subject_user, f.subject_role, f.rule_id, f.title,
                                              *(f.roles_responsible or [])))]
        rows.sort(key=lambda f: (-SEV_ORDER[f.severity], f.rule_id, f.subject_user or "", f.subject_role or ""))
        return render(request, template, user, db, active=active, rows=rows, title=title, sev=sev, st=st,
                      kinds=kinds, q=q)

    def _grouped_page(request: Request, user: CurrentUser, db: Session, kinds: list[str], active: str,
                      title: str, intro: str):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        groups: dict[str, dict] = {}
        for rid, sev, ttl, uname, role, roles, st in db.execute(select(
                Finding.rule_id, Finding.severity, Finding.title, Finding.subject_user, Finding.subject_role,
                Finding.roles_responsible, Finding.status).where(Finding.snapshot_id == snap.id,
                                                                  Finding.kind.in_(kinds),
                                                                  Finding.status != "corregido",
                                                                  Finding.severity != "informativo")):
            g = groups.setdefault(rid, {"rule_id": rid, "severity": sev, "title": ttl, "users": set(),
                                        "roles": {}, "open": 0, "total": 0})
            if SEV_ORDER[sev] > SEV_ORDER[g["severity"]]:
                g["severity"] = sev
            if uname:
                g["users"].add(uname)
            for r in (roles or []) + ([role] if role else []):
                g["roles"][r] = g["roles"].get(r, 0) + 1
            g["total"] += 1
            g["open"] += st not in ("corregido", "falso_positivo", "excepcion", "mitigado")
        rows = sorted(groups.values(), key=lambda g: (-SEV_ORDER[g["severity"]], -len(g["users"]), g["rule_id"]))
        for g in rows:
            g["top_roles"] = sorted(g["roles"].items(), key=lambda kv: -kv[1])[:4]
            g["more_roles"] = max(len(g["roles"]) - 4, 0)
        return render(request, "findings_grouped.html", user, db, active=active, rows=rows, title=title, intro=intro)

    @app.get("/criticas", response_class=HTMLResponse)
    def criticals(request: Request, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        return _grouped_page(request, user, db, ["critica"], "criticas", "Permisos críticos",
                             "Qué permisos peligrosos existen, a cuántos usuarios alcanzan y qué roles los otorgan.")

    @app.get("/sod", response_class=HTMLResponse)
    def sod(request: Request, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        return _grouped_page(request, user, db, ["sod", "sod_rol"], "sod", "Conflictos de funciones (SoD)",
                             "Qué combinaciones incompatibles existen (por ejemplo, crear y aprobar una compra) y qué "
                             "roles las producen.")

    @app.get("/hallazgos", response_class=HTMLResponse)
    def findings_all(request: Request, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        return _findings_page(request, user, db, ["critica", "sod", "sod_rol", "calidad"], "findings.html",
                              "auditorias", "Gestión de hallazgos")

    @app.get("/hallazgos/{fid}", response_class=HTMLResponse)
    def finding_detail(fid: int, request: Request, user: CurrentUser = Depends(require("ver")),
                       db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        f = db.get(Finding, fid) or _404()
        history = db.scalars(select(Finding).where(Finding.fingerprint == f.fingerprint).order_by(Finding.id)).all()
        mits = db.scalars(select(Mitigation).where(Mitigation.rule_id == f.rule_id)).all()
        return render(request, "finding_detail.html", user, db, active="auditorias", f=f, history=history, mits=mits)

    @app.post("/hallazgos/{fid}")
    async def finding_update(fid: int, request: Request, user: CurrentUser = Depends(require("hallazgos_gestionar")),
                             db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        f = db.get(Finding, fid) or _404()
        form = await request.form()
        status = str(form.get("status", f.status))
        if status not in ("abierto", "en_revision", "mitigado", "excepcion", "corregido", "falso_positivo"):
            raise HTTPException(400, "Estado inválido")
        just = str(form.get("exception_justification") or "").strip()
        if status in ("excepcion", "falso_positivo") and not just:
            raise HTTPException(400, "Una excepción o falso positivo requiere justificación")
        exp = str(form.get("exception_expires") or "")
        if status == "excepcion" and not exp:
            raise HTTPException(400, "Una excepción requiere fecha de vencimiento")
        before = {"status": f.status, "owner": f.owner}
        f.status, f.owner = status, str(form.get("owner") or f.owner or "") or None
        f.auto_status = ""  # la decisión de una persona prevalece sobre la automática
        f.exception_justification = just or f.exception_justification
        f.exception_expires = datetime.fromisoformat(exp) if exp else f.exception_expires
        mid = form.get("mitigation_id")
        f.mitigation_id = int(mid) if mid else f.mitigation_id
        audit(db, user.username, "hallazgo_actualizado", f.code, {"antes": before, "despues": {"status": status}})
        return RedirectResponse(f"/hallazgos/{fid}", status_code=303)

    @app.post("/mitigaciones")
    async def mitigation_create(request: Request, user: CurrentUser = Depends(require("mitigaciones")),
                                db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        form = await request.form()
        eff = float(form.get("effectiveness") or 0.5)
        if not 0 <= eff <= 0.9:
            raise HTTPException(400, "La eficacia debe estar entre 0 y 0,9 (un control nunca elimina el riesgo)")
        m = Mitigation(code=str(form["code"]).strip().upper(), description=str(form["description"]),
                       rule_id=str(form["rule_id"]), scope_user=str(form.get("scope_user") or "") or None,
                       scope_role=str(form.get("scope_role") or "") or None, sid=str(form.get("sid") or "") or None,
                       owner=str(form["owner"]), approved_by=str(form["approved_by"]), effectiveness=eff,
                       valid_to=datetime.fromisoformat(str(form["valid_to"])))
        db.add(m)
        audit(db, user.username, "mitigacion_creada", m.code, {"regla": m.rule_id})
        back = str(form.get("back") or "/hallazgos")
        return RedirectResponse(back if back.startswith("/") else "/hallazgos", status_code=303)

    # ------------------------------------------------------------------ simulador
    @app.get("/simulador", response_class=HTMLResponse)
    def simulator_form(request: Request, user: CurrentUser = Depends(require("simular")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        data = data_for(snap)
        qp = request.query_params
        return render(request, "simulator.html", user, db, active="simulador", data=data, result=None,
                      form={k: qp.get(k, "") for k in ("usuario", "agregar", "quitar", "sust_old", "sust_new")})

    @app.post("/simulador", response_class=HTMLResponse)
    async def simulator_run(request: Request, user: CurrentUser = Depends(require("simular")),
                            db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        snap = _need_snap(request, db)
        data = data_for(snap)
        form = await request.form()
        scenario, username = _scenario_from_form(form)
        if username not in data.users:
            raise HTTPException(400, f"El usuario {username} no existe en {snap.sid}/{snap.client}")
        ctx = context_for(db, snap)
        result = simulate(ctx, data, username, scenario, snapshot_meta(snap))
        from ..storage.orm import Simulation
        sim = Simulation(created_by=user.username, snapshot_id=snap.id, username=username,
                         scenario={"agregar": scenario.add_roles, "quitar": scenario.remove_roles,
                                   "sustituir": scenario.replace,
                                   "modificaciones": [vars(o) for o in scenario.overrides]},
                         recommendation=result.recommendation,
                         result={"motivos": result.reasons, "medidas": result.measures,
                                 "riesgo_antes": result.before.risk.inherent_score,
                                 "riesgo_despues": result.after.risk.inherent_score})
        db.add(sim)
        db.flush()
        audit(db, user.username, "simulacion", f"{snap.sid}/{snap.client}/{username}",
              {"simulacion": sim.id, "resultado": result.recommendation})
        return render(request, "simulator.html", user, db, active="simulador", data=data, result=result, sim=sim,
                      form=dict(form), labels=LABELS, evaluated=datetime.now().strftime("%Y-%m-%d %H:%M"), snap=snap,
                      reco=simulation_advice(result))

    @app.get("/simulaciones/{sim_id}/reporte")
    def simulation_download(sim_id: int, formato: str = "pdf", tipo: str = "tecnico",
                            user: CurrentUser = Depends(require("reportes")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..storage.orm import Simulation
        sim = db.get(Simulation, sim_id) or _404()
        snap = db.get(Snapshot, sim.snapshot_id)
        sc = sim.scenario
        scenario = Scenario(sc.get("agregar", []), sc.get("quitar", []), [tuple(x) for x in sc.get("sustituir", [])],
                            [ValueOverride(**o) for o in sc.get("modificaciones", [])])
        result = simulate(context_for(db, snap), data_for(snap), sim.username, scenario, snapshot_meta(snap))  # type: ignore[arg-type]
        doc = simulation_report(snap, result, sim.created_at.strftime("%Y-%m-%d %H:%M"), executive=tipo == "ejecutivo")  # type: ignore[arg-type]
        audit(db, user.username, "reporte_simulacion", str(sim_id), {"formato": formato})
        return _download(doc, formato, f"simulacion_{sim.username}_{sim_id}_{tipo}")

    # ------------------------------------------------------------------ qué cambió entre dos fechas
    def _changes_pair(request: Request, db: Session, desde: int | None, hasta: int | None):  # type: ignore[no-untyped-def]
        b = db.get(Snapshot, hasta) if hasta else _need_snap(request, db)
        if b is None:
            raise HTTPException(404, "La extracción indicada no existe (puede haberse borrado por la retención).")
        a = db.get(Snapshot, desde) if desde else changes.previous_of(db, b)
        if desde and a is None:
            raise HTTPException(404, "La extracción indicada no existe (puede haberse borrado por la retención).")
        if a is not None:
            if a.analyzed_at is None or b.analyzed_at is None:
                raise HTTPException(409, "Una de las dos extracciones todavía no se analizó: vuelva en unos minutos.")
            try:
                a, b = changes.ordered(a, b)
            except changes.ChangesError as exc:
                raise HTTPException(400, str(exc)) from exc
        return a, b

    @app.get("/cambios", response_class=HTMLResponse)
    def changes_page(request: Request, desde: int | None = None, hasta: int | None = None,
                     user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..advice import changes_advice
        a, b = _changes_pair(request, db, desde, hasta)
        snaps = db.scalars(select(Snapshot).where(Snapshot.connection_id == b.connection_id,
                                                  Snapshot.analyzed_at.is_not(None),
                                                  Snapshot.status.in_(["completo", "incompleto"]))
                           .order_by(Snapshot.id.desc())).all()
        x = changes.compare(db, a, b) if a is not None and a.id != b.id else None
        audit(db, user.username, "consulta_cambios", f"{b.connection.label}: #{a.id if a else '-'} → #{b.id}")
        return render(request, "changes.html", user, db, active="cambios", snap=b, a=a, b=b, x=x, snaps_all=snaps,
                      reco=changes_advice(x) if x else None, keep=get_settings().snapshots_to_keep)

    @app.get("/cambios/descargar")
    def changes_download(request: Request, desde: int | None = None, hasta: int | None = None, formato: str = "xlsx",
                         user: CurrentUser = Depends(require("reportes")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..advice import changes_advice
        from ..reports.builders import changes_report
        if formato not in EXPORTERS:
            raise HTTPException(400, "Formato inválido")
        a, b = _changes_pair(request, db, desde, hasta)
        if a is None or a.id == b.id:
            raise HTTPException(400, "Hacen falta dos extracciones distintas del mismo sistema.")
        x = changes.compare(db, a, b)
        audit(db, user.username, "reporte", f"cambios #{a.id} → #{b.id}", {"formato": formato})
        return _download(changes_report(x, changes_advice(x)), formato,
                         f"cambios_{b.sid}_{b.client}_{a.started_at:%Y%m%d}_{b.started_at:%Y%m%d}")

    # ------------------------------------------------------------------ usuarios de emergencia
    @app.get("/emergencia", response_class=HTMLResponse)
    def emergency_page(request: Request, usuario: str = "", conexion: str = "", ok: str = "",
                       user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..advice import emergency_page_advice
        rows = emergency.overview(db)
        conns = db.scalars(select(SapConnection).order_by(SapConnection.id)).all()
        snap = current_snapshot(request, db)
        pre_conn = int(conexion) if conexion.isdigit() else (snap.connection_id if snap else None)
        candidates = emergency.sap_all_candidates(db)
        return render(request, "emergency.html", user, db, active="emergencia", rows=rows, conns=conns,
                      candidates=candidates, labels=emergency.STATE_LABEL, reco=emergency_page_advice(rows, candidates),
                      pre_user=usuario.strip().upper()[:12], pre_conn=pre_conn, ok=ok,
                      default_review=(date.today() + timedelta(days=emergency.DEFAULT_REVIEW_DAYS)).isoformat(),
                      max_review=(date.today() + timedelta(days=emergency.MAX_REVIEW_DAYS)).isoformat(),
                      today=date.today().isoformat(), task_key=task_key("emergencia"))

    @app.post("/emergencia")
    async def emergency_declare(request: Request, user: CurrentUser = Depends(require("hallazgos_gestionar")),
                                db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        f = await request.form()
        scope = str(f.get("conexion") or "")
        cid = int(scope) if scope.isdigit() else None
        if cid is not None and db.get(SapConnection, cid) is None:
            raise HTTPException(400, "El sistema elegido no existe.")
        try:
            name = emergency.normalize_user(str(f.get("usuario") or ""))
            review = emergency.parse_review(str(f.get("revisar") or ""))
            d, created = emergency.declare(db, cid, name, str(f.get("responsable") or ""),
                                           str(f.get("procedimiento") or ""), review, user.username)
        except emergency.DeclarationError as exc:
            raise HTTPException(400, str(exc)) from exc
        where = d.connection.label if d.connection is not None else "todos los sistemas"
        audit(db, user.username, "emergencia_declarada" if created else "emergencia_modificada", f"{name} en {where}",
              {"responsable": d.responsible, "revisar": review.isoformat()}, ip=_ip(request))
        emergency.apply_latest(db, cid)
        return RedirectResponse(f"/emergencia?ok={'declarado' if created else 'modificado'}", status_code=303)

    @app.post("/emergencia/{eid}/{accion}")
    async def emergency_change(eid: int, accion: str, request: Request,
                               user: CurrentUser = Depends(require("hallazgos_gestionar")),
                               db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        f = await request.form()
        d = db.get(EmergencyUser, eid) or _404()
        cid, name = d.connection_id, d.username
        where = d.connection.label if d.connection is not None else "todos los sistemas"
        if accion == "renovar":
            try:
                review = emergency.parse_review(str(f.get("revisar") or ""))
            except emergency.DeclarationError as exc:
                raise HTTPException(400, str(exc)) from exc
            before = d.review_by.isoformat()
            d.review_by, d.updated_by, d.updated_at = review, user.username, utcnow()
            db.commit()
            audit(db, user.username, "emergencia_renovada", f"{name} en {where}",
                  {"antes": before, "despues": review.isoformat()}, ip=_ip(request))
        elif accion == "quitar":
            db.delete(d)
            db.commit()
            audit(db, user.username, "emergencia_quitada", f"{name} en {where}", ip=_ip(request))
        else:
            raise HTTPException(400, "Acción desconocida")
        emergency.apply_latest(db, cid)
        return RedirectResponse(f"/emergencia?ok={'renovado' if accion == 'renovar' else 'quitado'}", status_code=303)

    # ------------------------------------------------------------------ comparadores
    @app.get("/comparador-roles", response_class=HTMLResponse)
    def role_compare(request: Request, a: str = "", b: str = "", snap_a: int | None = None, snap_b: int | None = None,
                     user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        sa = db.get(Snapshot, snap_a) if snap_a else snap
        sb = db.get(Snapshot, snap_b) if snap_b else snap
        diff = None
        if a and b and sa and sb:
            diff = _compare_roles(data_for(sa), a.upper(), data_for(sb), b.upper())
        all_snaps = db.scalars(select(Snapshot).where(Snapshot.status.in_(["completo", "incompleto"]))
                               .order_by(Snapshot.id.desc())).all()
        return render(request, "compare.html", user, db, active="comparador_roles", diff=diff, a=a, b=b, sa=sa, sb=sb,
                      all_snaps=all_snaps, mode="roles")

    @app.get("/comparador-sistemas", response_class=HTMLResponse)
    def system_compare(request: Request, snap_a: int | None = None, snap_b: int | None = None,
                       user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        all_snaps = db.scalars(select(Snapshot).where(Snapshot.status.in_(["completo", "incompleto"]))
                               .order_by(Snapshot.id.desc())).all()
        result = None
        if snap_a and snap_b:
            sa, sb = db.get(Snapshot, snap_a), db.get(Snapshot, snap_b)
            if sa and sb:
                result = _compare_snapshots(data_for(sa), data_for(sb))
                result["sa"], result["sb"] = sa, sb
        return render(request, "compare_systems.html", user, db, active="comparador_sistemas", all_snaps=all_snaps,
                      result=result, snap_a=snap_a, snap_b=snap_b)

    # ------------------------------------------------------------------ recomendaciones
    @app.get("/recomendaciones", response_class=HTMLResponse)
    def recommendations(request: Request, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        ctx = context_for(db, snap)
        recs = load_recommendations(snap, ctx.rules.hash)
        if recs is None:
            _start_precompute(snap.id)
        return render(request, "recommendations.html", user, db, active="recomendaciones", recs=recs)


    # ------------------------------------------------------------------ reportes
    @app.get("/reportes", response_class=HTMLResponse)
    def reports(request: Request, user: CurrentUser = Depends(require("reportes")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        _need_snap(request, db)
        return render(request, "reports.html", user, db, active="reportes")

    @app.get("/reportes/descargar")
    def report_download(request: Request, tipo: str, formato: str = "xlsx", usuario: str = "",
                        user: CurrentUser = Depends(require("reportes")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        fs = list(db.scalars(select(Finding).where(Finding.snapshot_id == snap.id,
                                                   Finding.status.not_in(["corregido", "falso_positivo"]))))
        fs.sort(key=lambda f: (-SEV_ORDER[f.severity], f.code))
        ctx_data = data_for(snap)
        if tipo == "criticos":
            doc = findings_report(snap, [f for f in fs if f.kind == "critica"], "Usuarios con autorizaciones críticas",
                                  "Autorizaciones críticas de todos los usuarios")
        elif tipo == "sap_all":
            doc = findings_report(snap, [f for f in fs if f.rule_id in ("CRIT-PRF-001", "CRIT-EQV-001")],
                                  "Usuarios con SAP_ALL o equivalentes", "Perfil SAP_ALL y equivalencias")
        elif tipo == "admin":
            doc = findings_report(snap, [f for f in fs if f.kind == "critica" and any(
                k in f.rule_id for k in ("USR", "ADM", "DEV", "CTS", "TAB"))], "Usuarios con privilegios administrativos",
                "Reglas de administración")
        elif tipo == "sod_usuario":
            doc = findings_report(snap, [f for f in fs if f.kind == "sod"], "Conflictos SoD por usuario", "SoD usuarios")
        elif tipo == "sod_rol":
            doc = findings_report(snap, [f for f in fs if f.kind == "sod_rol"], "Conflictos SoD por rol", "SoD roles")
        elif tipo == "auditor":
            doc = findings_report(snap, fs, "Informe técnico detallado para auditores", "Todos los hallazgos")
        elif tipo == "ejecutivo":
            doc = executive_report(snap, dashboard_stats(db, snap), fs[:25])
        elif tipo == "plan":
            from ..reports.builders import plan_report
            tasks = build_tasks(db, snap, get_rules())
            env = _env(snap)
            doc = plan_report(snap, [t for t in tasks if t.pending] + [t for t in tasks if not t.pending],
                              lambda t: task_advice(t, ctx_data, env))
        elif tipo == "usuario" and usuario:
            doc = user_report(snap, analyze_user(context_for(db, snap), ctx_data, usuario.upper()))
        else:
            raise HTTPException(400, "Tipo de reporte desconocido")
        audit(db, user.username, "reporte", tipo, {"formato": formato, "snapshot": snap.id})
        return _download(doc, formato, f"{tipo}_{snap.sid}_{snap.client}_{snap.id}")

    # ------------------------------------------------------------------ reglas / configuración / auditoría
    @app.get("/reglas", response_class=HTMLResponse)
    def rules_page(request: Request, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        rules = get_rules()
        snap = current_snapshot(request, db)
        checks, hits = [], {}
        if snap is not None:
            checks = check_rules(rules, data_for(snap))
            for f in db.scalars(select(Finding).where(Finding.snapshot_id == snap.id, Finding.kind == "sod")):
                hits[f.rule_id] = hits.get(f.rule_id, 0) + 1
        return render(request, "rules.html", user, db, active="reglas", rules=rules,
                      rules_dir=get_settings().rules_dir, checks=checks, check_summary=summarize(checks),
                      sod_hits=hits, current_env=_env(snap) if snap is not None else "")

    @app.get("/configuracion", response_class=HTMLResponse)
    def config_page(request: Request, user: CurrentUser = Depends(require("ver")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        from ..security.network import serve_info
        app_users = db.scalars(select(AppUser).order_by(AppUser.username)).all() if user.can("usuarios_app") else []
        s = get_settings()
        locked = {u.id for u in app_users if _is_locked(u, s.security.max_failed_logins, s.security.lockout_minutes)}
        return render(request, "config.html", user, db, active="configuracion", settings=s, app_users=app_users,
                      roles=[r.value for r in AppRole], db_url=s.database_url.split("@")[-1], locked=locked,
                      net=serve_info(), client_ip=_ip(request))

    @app.post("/configuracion/usuarios")
    async def app_user_create(request: Request, user: CurrentUser = Depends(require("usuarios_app")),
                              db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        form = await request.form()
        role = str(form.get("role", ""))
        try:
            AppRole(role)
            pw_hash = hash_password(str(form.get("password", "")))
        except ValueError as exc:
            raise HTTPException(400, "Rol inválido" if "AppRole" in str(exc) else str(exc)) from exc
        uname = str(form.get("username", "")).strip()
        if not uname or db.scalars(select(AppUser).where(AppUser.username == uname)).first():
            raise HTTPException(400, f"El usuario «{uname}» ya existe o no es válido.")
        db.add(AppUser(username=uname, password_hash=pw_hash, role=role))
        audit(db, user.username, "usuario_app_creado", uname, {"rol": role}, ip=_ip(request))
        return RedirectResponse("/configuracion#usuarios", status_code=303)

    @app.post("/configuracion/usuarios/{uid}/{accion}")
    async def app_user_action(uid: int, accion: str, request: Request,
                              user: CurrentUser = Depends(require("usuarios_app")), db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        await check_csrf(request)
        form = await request.form()
        target = db.get(AppUser, uid) or _404()
        admins = db.scalar(select(func.count()).select_from(AppUser).where(
            AppUser.role == AppRole.ADMINISTRADOR.value, AppUser.active.is_(True))) or 0
        last_admin = target.role == AppRole.ADMINISTRADOR.value and target.active and admins <= 1
        details: dict[str, Any] = {}
        if accion == "desbloquear":
            target.failed_logins, target.last_failed_at = 0, None
        elif accion == "contrasena":
            try:
                target.password_hash = hash_password(str(form.get("password", "")))
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
            target.failed_logins, target.last_failed_at = 0, None
        elif accion in ("activar", "desactivar"):
            if accion == "desactivar" and (target.username == user.username or last_admin):
                raise HTTPException(400, "No puede desactivarse a sí mismo ni desactivar al último administrador.")
            target.active = accion == "activar"
        elif accion == "rol":
            try:
                new_role = AppRole(str(form.get("role", ""))).value
            except ValueError as exc:
                raise HTTPException(400, "Rol inválido") from exc
            if new_role != target.role and (target.username == user.username or last_admin):
                raise HTTPException(400, "No puede cambiar su propio rol ni dejar la aplicación sin administrador.")
            details["rol"] = f"{target.role} → {new_role}"
            target.role = new_role
        else:
            raise HTTPException(404, "Acción desconocida")
        audit(db, user.username, f"usuario_app_{accion}", target.username, details, ip=_ip(request))
        return RedirectResponse("/configuracion#usuarios", status_code=303)

    @app.get("/auditoria", response_class=HTMLResponse)
    def audit_page(request: Request, user: CurrentUser = Depends(require("auditoria_app")),
                   db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        logs = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(500)).all()
        snaps = db.scalars(select(Snapshot).order_by(Snapshot.id.desc()).limit(100)).all()
        from ..storage.orm import Simulation
        sims = db.scalars(select(Simulation).order_by(Simulation.id.desc()).limit(100)).all()
        return render(request, "audit.html", user, db, active="auditorias", logs=logs, snaps_all=snaps, sims=sims)

    # ------------------------------------------------------------------ API JSON (base para frontend React futuro)
    @app.get("/api/v1/salud")
    def health():  # type: ignore[no-untyped-def]
        return {"estado": "ok", "version": __version__}

    @app.get("/api/v1/usuarios/{username}")
    def api_user(username: str, request: Request, user: CurrentUser = Depends(require("ver")),
                 db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        snap = _need_snap(request, db)
        a = analyze_user(context_for(db, snap), data_for(snap), username.upper())
        audit(db, user.username, "api_usuario", username)
        return {"snapshot": snap.id, "sistema": snap.sid, "mandante": snap.client, "usuario": username.upper(),
                "roles_vigentes": a.eff.valid_roles(), "perfiles": a.eff.profiles,
                "riesgo": {"inherente": a.risk.inherent_score, "actual": a.risk.current_score,
                           "residual": a.risk.residual_score, "nivel": a.risk.inherent_level.value},
                "criticas": [{"regla": h.rule_id, "gravedad": h.severity.value, "roles": h.roles,
                              "certeza": h.certainty.value} for h in a.critical],
                "sod": [{"riesgo": h.risk_id, "gravedad": h.severity.value, "roles": h.roles, "alcance": h.scope,
                         "explicacion": h.explanation} for h in a.sod],
                "observaciones": [{"codigo": i.code, "mensaje": i.message} for i in a.issues]}

    @app.post("/api/v1/simular")
    async def api_simulate(request: Request, user: CurrentUser = Depends(require("simular")),
                           db: Session = Depends(get_session)):  # type: ignore[no-untyped-def]
        if request.headers.get("x-csrf-token") != request.session.get("csrf"):
            raise HTTPException(403, "Token CSRF inválido")
        body = await request.json()
        snap = _need_snap(request, db)
        sc = Scenario(body.get("agregar", []), body.get("quitar", []), [tuple(x) for x in body.get("sustituir", [])],
                      [ValueOverride(**o) for o in body.get("modificaciones", [])])
        r = simulate(context_for(db, snap), data_for(snap), body["usuario"].upper(), sc, snapshot_meta(snap))
        audit(db, user.username, "api_simulacion", body["usuario"], {"resultado": r.recommendation})
        return {"resultado": r.recommendation, "etiqueta": r.recommendation_label, "motivos": r.reasons,
                "medidas": r.measures, "riesgo_antes": r.before.risk.inherent_score,
                "riesgo_despues": r.after.risk.inherent_score,
                "nuevos_sod": [h.risk_id for h in r.new_sod], "nuevas_criticas": [h.rule_id for h in r.new_critical]}


# ---------------------------------------------------------------------------------- tareas en segundo plano
JOBS: dict[int, dict[str, Any]] = {}


PRECOMPUTE: dict[int, Any] = {}


def _subprocess_env() -> dict[str, str]:
    env = dict(os.environ)
    src_dir = str(Path(__file__).resolve().parents[2])
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _start_precompute(snapshot_id: int) -> None:
    """Lanza «sapsec precompute» en un proceso aparte (una sola vez por snapshot)."""
    import subprocess
    import sys
    proc = PRECOMPUTE.get(snapshot_id)
    if proc is not None and proc.poll() is None:
        return
    if proc is not None and proc.returncode == 0:
        return  # ya terminó; los archivos están en disco
    if _job_running():
        return  # la extracción en curso ya precalcula al terminar
    PRECOMPUTE[snapshot_id] = subprocess.Popen(
        [sys.executable, "-m", "sapsec.cli", "precompute", str(snapshot_id)], env=_subprocess_env(),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _spawn_schedule(schedule_id: int, trigger: str) -> None:
    """Ejecuta una programación en un proceso aparte (no frena la interfaz)."""
    import subprocess
    import sys as _sys
    from ..config import get_settings as _gs
    pdir = Path(_gs().log_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    logf = open(pdir / f"programada_{schedule_id}.log", "w", encoding="utf-8")  # noqa: SIM115
    subprocess.Popen([_sys.executable, "-m", "sapsec.cli", "run-schedule", str(schedule_id), "--trigger", trigger],
                     stdout=logf, stderr=subprocess.STDOUT, env=_subprocess_env(),
                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _scheduler_tick() -> None:
    """Revisión periódica (cada minuto) de programaciones vencidas mientras la aplicación está abierta."""
    from ..scheduler import claim, due_slot, is_running
    from ..storage.db import session_scope as _ss
    from ..storage.orm import ExtractionSchedule
    with _ss() as db:
        for sch in db.scalars(select(ExtractionSchedule)).all():
            slot = due_slot(sch)
            if slot is not None and not is_running(sch) and claim(db, sch.id, slot):
                log.info("Extracción programada «%s» (%s): iniciando", sch.name, slot)
                _spawn_schedule(sch.id, "aplicación")


WIN_TASK_NAME = "SAP Security Analyzer - extracciones programadas"


def _windows_task_state() -> str:
    """'instalada' | 'no instalada' | 'no aplica' (solo Windows; consulta de solo lectura)."""
    import subprocess
    import sys as _sys
    if _sys.platform != "win32":
        return "no aplica"
    try:
        r = subprocess.run(["schtasks", "/Query", "/TN", WIN_TASK_NAME], capture_output=True, timeout=10,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return "instalada" if r.returncode == 0 else "no instalada"
    except (OSError, subprocess.SubprocessError):
        return "desconocido"


QUEUE: list[tuple[int, str]] = []
_QLOCK = threading.RLock()


def _enqueue(cid: int, label: str, username: str) -> None:
    """Agrega un sistema a la cola. Se extrae UN sistema por vez (protege a SAP y a la base local)."""
    with _QLOCK:
        job = _job_state(cid)
        if job and job["estado"] in ("en_curso", "en_cola"):
            return
        JOBS[cid] = {"estado": "en_cola", "fase": "En cola", "inicio": datetime.now(), "snapshot": None,
                     "error": None, "conexion": label}
        QUEUE.append((cid, username))
    _dispatch()


def _dispatch() -> None:
    with _QLOCK:
        for c in list(JOBS):
            _job_state(c)  # actualiza el estado de los procesos en curso
        if any(j.get("estado") == "en_curso" for j in JOBS.values()):
            return
        while QUEUE:
            cid, username = QUEUE.pop(0)
            job = JOBS.get(cid)
            if job is None or job.get("estado") != "en_cola":
                continue
            _start_job(cid, job["conexion"], username)
            return


def _queue_position(cid: int) -> int:
    return next((i + 1 for i, (c, _) in enumerate(QUEUE) if c == cid), 0)


def _running_label() -> str:
    return next((j["conexion"] for j in JOBS.values() if j.get("estado") == "en_curso"), "")


def _queue_worker() -> None:
    import time as _time
    ticks = 0
    while True:
        _time.sleep(3)
        ticks += 1
        try:
            _dispatch()
        except Exception:  # noqa: BLE001
            log.exception("Error en la cola de extracciones")
        if ticks % 20 == 1:  # ~ cada minuto
            try:
                _scheduler_tick()
            except Exception:  # noqa: BLE001
                log.exception("Error revisando extracciones programadas")


def _start_job(cid: int, conn_name: str, username: str) -> None:
    """Ejecuta extracción + análisis en un PROCESO separado (no compite con la interfaz web)."""
    import subprocess
    import sys
    from ..config import get_settings as _gs
    pdir = Path(_gs().log_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    pfile = pdir / f"extraccion_{cid}.json"
    pfile.unlink(missing_ok=True)
    logf = open(pdir / f"extraccion_{cid}.log", "w", encoding="utf-8")  # noqa: SIM115
    env = _subprocess_env()
    proc = subprocess.Popen([sys.executable, "-m", "sapsec.cli", "extract", str(cid), "--progress-file", str(pfile),
                             "--user", username], stdout=logf, stderr=subprocess.STDOUT, env=env,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    JOBS[cid] = {"estado": "en_curso", "fase": "Iniciando…", "inicio": datetime.now(), "snapshot": None,
                 "error": None, "conexion": conn_name, "proc": proc, "pfile": pfile, "logf": logf}


def _job_state(cid: int) -> dict[str, Any] | None:
    import json as _json
    job = JOBS.get(cid)
    if job is None:
        return None
    if job.get("estado") == "en_cola" or "pfile" not in job:
        return job
    try:
        job.update(_json.loads(job["pfile"].read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    proc = job.get("proc")
    if proc is not None and proc.poll() is not None and job["estado"] == "en_curso":
        job["estado"] = "error"
        job["error"] = job.get("error") or f"El proceso terminó inesperadamente (código {proc.returncode}). " \
            f"Ver data\\logs\\extraccion_{cid}.log"
    if job["estado"] != "en_curso" and job.get("logf"):
        job["logf"].close()
        job["logf"] = None
        if job.get("snapshot"):
            _warm_up_async(job["snapshot"])
    return job


def _job_running() -> bool:
    return any((_job_state(c) or {}).get("estado") == "en_curso" for c in list(JOBS))


def _warm_up_async(snapshot_id: int | None = None) -> None:
    """Precarga en segundo plano el snapshot y los cálculos pesados (primera apertura rápida)."""
    def work() -> None:
        try:
            from ..storage.db import session_scope as _ss
            with _ss() as db:
                snap = db.get(Snapshot, snapshot_id) if snapshot_id else db.scalars(
                    select(Snapshot).where(Snapshot.status.in_(["completo", "incompleto"]),
                                           Snapshot.analyzed_at.is_not(None)).order_by(Snapshot.id.desc())).first()
                if snap is None or snap.analyzed_at is None:
                    return
                data_for(snap)
                log.info("Snapshot #%s cargado en memoria", snap.id)
        except Exception:  # noqa: BLE001
            log.exception("Falló la precarga del snapshot")
    threading.Thread(target=work, daemon=True).start()


# ---------------------------------------------------------------------------------- utilidades
def _safe(fn, default, what: str):  # type: ignore[no-untyped-def]
    """Calcula una sección opcional; si falla se registra y la página se muestra igual."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        log.exception("Falló el cálculo de la sección '%s'", what)
        return default


def _login_ctx(request: Request) -> dict[str, bool]:
    from ..security.network import is_loopback_host, local_ca
    https = request.url.scheme == "https" or os.environ.get("SAPSEC_SERVE_HTTPS") == "1"
    host = request.client.host if request.client else "127.0.0.1"
    return {"insecure": not https and not is_loopback_host(host),
            "show_cert": https and local_ca() is not None}


def _fiori_services(eff: Any, data: Any) -> list[dict[str, Any]]:
    """Servicios Fiori/OData (S_SERVICE con SRV_TYPE HT) con su nombre real según USOBHASH."""
    out: dict[str, dict[str, Any]] = {}
    for e in eff.by_object("S_SERVICE"):
        if not e.instance.field_covers("SRV_TYPE", "HT"):
            continue
        for v in e.instance.values("SRV_NAME"):
            key = str(v)
            if key in out or v.is_unresolved_variable:
                continue
            name = "TODOS los servicios (*)" if v.is_full_wildcard else (
                "servicios que empiezan con " + v.low[:-1] if v.low.endswith("*") else data.service_label(v.low))
            out[key] = {"hash": key, "name": name, "roles": e.roles}
    return sorted(out.values(), key=lambda x: (not x["name"], x["name"], x["hash"]))


def _env(snap: Snapshot) -> str:
    try:
        return (snap.connection.system.environment or "").upper()
    except AttributeError:
        return ""


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _is_locked(u: AppUser, max_failed: int, lockout_minutes: int) -> bool:
    """Bloqueo por intentos fallidos: temporal (lockout_minutes) o hasta que un administrador lo desbloquee (0)."""
    if u.failed_logins < max_failed:
        return False
    if lockout_minutes <= 0 or u.last_failed_at is None:
        return True
    from datetime import timedelta
    return utcnow() - u.last_failed_at < timedelta(minutes=lockout_minutes)


def _404():  # type: ignore[no-untyped-def]
    raise HTTPException(404, "No encontrado")


def _download(doc: ReportDoc, fmt: str, name: str) -> Response:
    if fmt not in EXPORTERS:
        raise HTTPException(400, "Formato no soportado")
    fn, mime = EXPORTERS[fmt]
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    return Response(fn(doc), media_type=mime,
                    headers={"Content-Disposition": f'attachment; filename="{safe}.{fmt}"',
                             "Cache-Control": "no-store"})


def _scenario_from_form(form: Any) -> tuple[Scenario, str]:
    def lst(key: str) -> list[str]:
        raw = str(form.get(key) or "")
        return [x.strip().upper() for x in raw.replace(";", ",").replace("\n", ",").split(",") if x.strip()]
    username = str(form.get("usuario", "")).strip().upper()
    replace = []
    if form.get("sust_old") and form.get("sust_new"):
        replace.append((str(form["sust_old"]).strip().upper(), str(form["sust_new"]).strip().upper()))
    overrides = []
    if form.get("ov_role") and form.get("ov_object") and form.get("ov_field"):
        overrides.append(ValueOverride(str(form["ov_role"]).strip().upper(), str(form["ov_object"]).strip().upper(),
                                       str(form["ov_field"]).strip().upper(),
                                       [v.strip() for v in str(form.get("ov_values", "")).split(",") if v.strip()]))
    return Scenario(lst("agregar"), lst("quitar"), replace, overrides), username


def _role_signature(data: Any, role: str) -> dict[str, dict[str, set[str]]]:
    from ..engine.effective import role_as_effective
    eff = role_as_effective(data, role, date.today())
    sig: dict[str, dict[str, set[str]]] = {}
    for e in eff.instances.values():
        for f, vals in e.instance.fields.items():
            sig.setdefault(e.instance.object, {}).setdefault(f, set()).update(str(v) for v in vals)
    return sig


def _compare_roles(da: Any, a: str, db_: Any, b: str) -> dict:
    if a not in da.role_names or b not in db_.role_names:
        return {"error": f"Rol inexistente: {a if a not in da.role_names else b}"}
    sa, sb = _role_signature(da, a), _role_signature(db_, b)
    rows = []
    for obj in sorted(set(sa) | set(sb)):
        fa, fb = sa.get(obj, {}), sb.get(obj, {})
        for f in sorted(set(fa) | set(fb)):
            va, vb = fa.get(f, set()), fb.get(f, set())
            rows.append({"object": obj, "field": f, "a": sorted(va), "b": sorted(vb),
                         "status": "igual" if va == vb else "solo A" if not vb else "solo B" if not va else "distinto"})
    total = len(rows)
    same = sum(1 for r in rows if r["status"] == "igual")
    return {"rows": rows, "similarity": round(same / total, 2) if total else 1.0,
            "note": "Comparación por unión de valores por objeto y campo (la agrupación en instancias puede "
                    "diferir aunque los valores coincidan)."}


def _compare_snapshots(da: Any, db_: Any) -> dict:
    roles_a, roles_b = da.role_names, db_.role_names
    changed = []
    for r in sorted(roles_a & roles_b):
        if _role_signature(da, r) != _role_signature(db_, r):
            changed.append(r)
    users_a, users_b = set(da.users), set(db_.users)
    assign_a = {(x["uname"], x["agr_name"]) for x in da.rows.get("agr_users", [])}
    assign_b = {(x["uname"], x["agr_name"]) for x in db_.rows.get("agr_users", [])}
    crit_obj = {"S_USER_GRP", "S_USER_AGR", "S_USER_PRO", "S_DEVELOP", "S_TABU_DIS", "S_RFC", "S_CTS_ADMI",
                "S_ADMI_FCD", "S_SERVICE"}
    crit_diff = []
    for r in sorted(roles_a & roles_b):
        oa = set(_role_signature(da, r)) & crit_obj
        ob = set(_role_signature(db_, r)) & crit_obj
        if oa != ob:
            crit_diff.append({"rol": r, "solo_a": sorted(oa - ob), "solo_b": sorted(ob - oa)})
    return {"only_a": sorted(roles_a - roles_b), "only_b": sorted(roles_b - roles_a), "changed": changed,
            "users_only_a": sorted(users_a - users_b), "users_only_b": sorted(users_b - users_a),
            "assign_added": sorted(assign_b - assign_a), "assign_removed": sorted(assign_a - assign_b),
            "crit_diff": crit_diff}


app = None  # se crea en cli.serve o via uvicorn --factory sapsec.api.app:create_app


def _triples(data: Any, role: str) -> set[tuple[str, str, str]]:
    return {(o, f, v) for o, fs in _role_signature(data, role).items() for f, vs in fs.items() for v in vs}


def _similar_roles(data: Any, role: str, ra: Any, limit: int = 5) -> list[dict]:
    """Roles con autorizaciones parecidas (Jaccard sobre objeto/campo/valor) — candidatos a redundancia."""
    if data.is_composite(role):
        return []
    mine = _triples(data, role)
    if not mine:
        return []
    out = []
    for other in data.role_names:
        if other == role or data.is_composite(other):
            continue
        t = _triples(data, other)
        if not t:
            continue
        j = len(mine & t) / len(mine | t)
        if j >= 0.5:
            out.append({"role": other, "similarity": round(j, 2), "contains": mine <= t, "contained": t <= mine})
    return sorted(out, key=lambda x: -x["similarity"])[:limit]
