"""Línea de comandos: ``sapsec <comando>``.

Comandos:
  init-db                    Crea las tablas.
  create-user U ROL          Crea un usuario de la aplicación (pide contraseña).
  generate-key               Genera una clave maestra para SAPSEC_MASTER_KEY.
  demo                       Registra el sistema ficticio DMO y extrae un snapshot de prueba.
  list-connections           Lista conexiones registradas.
  list-snapshots             Lista snapshots.
  delete-snapshot ID         Elimina un snapshot (datos, hallazgos, simulaciones).
  delete-connection ID       Elimina una conexión, sus snapshots y su contraseña guardada.
  reset-sap-data             Borra todos los datos SAP (conserva usuarios de la aplicación y auditoría).
  test-connection ID         Diagnóstico de conectividad y permisos.
  extract ID                 Extrae un snapshot (solo lectura) y lo analiza.
  extract-all [--ambiente X] Extrae todos los sistemas activos, uno por vez (para el Programador de tareas).
  run-due                    Ejecuta las extracciones programadas vencidas (lo llama la tarea de Windows).
  run-schedule ID            Ejecuta ya una extracción programada.
  analyze SNAPSHOT           Recalcula hallazgos de un snapshot.
  rfc-selftest               Prueba el backend nwrfc con parámetros de entorno (SAPSEC_RFC_*).
  reset-password U           Nueva contraseña para un usuario de la aplicación (y lo desbloquea).
  serve [--red] [--port N]   Inicia la interfaz web (--red: accesible desde otras PC, con HTTPS).
  servicio [--red]           Abre la interfaz web y la mantiene funcionando (la reabre si se cae o no responde).
  estado-servicio            Muestra si el servicio está funcionando, desde cuándo y sus reinicios automáticos.
  verificar-credenciales     Indica si este usuario de Windows tiene guardada la contraseña de cada conexión SAP.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path

from .config import PROJECT_ROOT, get_settings


class _IgnoreClientResets(logging.Filter):
    """En Windows, cuando un navegador corta una conexión, asyncio registra «WinError 10054» con toda su traza.
    No es un error de la aplicación: se descarta para que el registro muestre solo lo que importa."""

    def filter(self, record: logging.LogRecord) -> bool:
        exc = record.exc_info[1] if record.exc_info else None
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return False
        return not (isinstance(exc, OSError) and getattr(exc, "winerror", None) in (10053, 10054))


def setup_logging() -> None:
    s = get_settings()
    aio = logging.getLogger("asyncio")
    if not any(isinstance(f, _IgnoreClientResets) for f in aio.filters):
        aio.addFilter(_IgnoreClientResets())
    Path(s.log_dir).mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(s.log_level)
    fh = logging.handlers.RotatingFileHandler(Path(s.log_dir) / "sapsec.log", maxBytes=10_000_000, backupCount=10,
                                              encoding="utf-8")
    fh.setFormatter(fmt)
    root.handlers = [fh]
    if sys.stderr is not None:  # con pythonw (tarea programada sin ventana) no hay consola
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.handlers.append(sh)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sapsec", description="SAP Security Intelligence & Access Risk Analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    cu = sub.add_parser("create-user")
    cu.add_argument("username")
    cu.add_argument("role", choices=["administrador", "auditor", "consultor"])
    sub.add_parser("generate-key")
    dm = sub.add_parser("demo")
    dm.add_argument("--admin-password", default=os.environ.get("SAPSEC_DEMO_ADMIN_PASSWORD"))
    sub.add_parser("list-connections")
    sub.add_parser("list-snapshots")
    ds = sub.add_parser("delete-snapshot")
    ds.add_argument("id", type=int)
    ds.add_argument("--yes", action="store_true", help="No pedir confirmación")
    dc = sub.add_parser("delete-connection")
    dc.add_argument("id", type=int)
    dc.add_argument("--yes", action="store_true", help="No pedir confirmación")
    sub.add_parser("run-due", help="Ejecuta las extracciones programadas vencidas (lo llama la tarea de Windows)")
    rsch = sub.add_parser("run-schedule", help="Ejecuta ya una extracción programada")
    rsch.add_argument("id", type=int)
    rsch.add_argument("--trigger", default="manual")
    ea = sub.add_parser("extract-all", help="Extrae todos los sistemas activos, uno por vez (para programar)")
    ea.add_argument("--ambiente", choices=["PRD", "QA", "DEV", "OTRO"], help="Solo sistemas de este ambiente")
    rs = sub.add_parser("reset-sap-data")
    rs.add_argument("--yes", action="store_true", help="No pedir confirmación")
    tc = sub.add_parser("test-connection")
    tc.add_argument("id", type=int)
    ex = sub.add_parser("extract")
    ex.add_argument("id", type=int)
    ex.add_argument("--progress-file", help="Archivo JSON donde informar el avance (lo usa la interfaz web)")
    ex.add_argument("--user", default="cli", help="Usuario de la aplicación que inició la extracción")
    pc = sub.add_parser("precompute")
    pc.add_argument("snapshot", type=int)
    an = sub.add_parser("analyze")
    an.add_argument("snapshot", type=int)
    sub.add_parser("rfc-selftest")
    rp = sub.add_parser("reset-password", help="Nueva contraseña para un usuario de la aplicación (lo desbloquea)")
    rp.add_argument("username")
    sv = sub.add_parser("serve", help="Inicia la interfaz web")
    sv.add_argument("--red", action="store_true",
                    help="Accesible desde otras PC de la red de la empresa / VPN (HTTPS, puerto 8443)")
    sv.add_argument("--sin-https", action="store_true", help="Solo para pruebas: modo red sin cifrar")
    sv.add_argument("--host", default=None, help="Dirección de escucha (por defecto 127.0.0.1; con --red, todas)")
    sv.add_argument("--port", type=int, default=None, help="Puerto (por defecto 8000; con --red, 8443)")
    svc = sub.add_parser("servicio", help="Abre la interfaz web y la mantiene funcionando: si se cae o deja de "
                                          "responder, la vuelve a abrir (lo usa scripts\\iniciar_con_windows.ps1)")
    svc.add_argument("--red", action="store_true", help="Modo red (HTTPS, puerto 8443) para otras PC de la empresa")
    svc.add_argument("--sin-https", action="store_true", help="Solo para pruebas: modo red sin cifrar")
    svc.add_argument("--port", type=int, default=None, help="Puerto (por defecto 8000; con --red, 8443)")
    sub.add_parser("estado-servicio", help="Muestra si el servicio está funcionando y sus reinicios automáticos")
    sub.add_parser("verificar-credenciales",
                   help="Indica si este usuario de Windows tiene guardada la contraseña SAP de cada conexión")
    args = p.parse_args(argv)
    setup_logging()
    from .connectors.base import RfcError
    try:
        return _run(args)
    except ValueError as exc:  # errores de validación: mensaje simple, sin traza
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except RfcError as exc:
        print(f"Error RFC ({type(exc).__name__}): {exc}", file=sys.stderr)
        logging.getLogger(__name__).debug("Detalle", exc_info=True)
        return 3


def _run(args: argparse.Namespace) -> int:

    from sqlalchemy import select

    from .storage.db import init_db, session_scope
    from .storage.orm import AppUser, SapConnection, SapSystem
    init_db()

    if args.cmd == "init-db":
        print("Base de datos inicializada:", get_settings().database_url.split("@")[-1])
    elif args.cmd == "create-user":
        from .security.auth import hash_password
        pw = ""
        while len(pw) < 12:
            pw = getpass.getpass("Contraseña (mín. 12 caracteres): ")
            if len(pw) < 12:
                print("La contraseña debe tener al menos 12 caracteres. Intente de nuevo.")
        with session_scope() as db:
            db.add(AppUser(username=args.username, password_hash=hash_password(pw), role=args.role))
        print("Usuario creado.")
    elif args.cmd == "generate-key":
        from .security.secrets import generate_key
        print(generate_key())
    elif args.cmd == "demo":
        from .services import run_extraction
        from .security.auth import hash_password
        fixture = PROJECT_ROOT / "tests" / "fixtures" / "demo_system.json"
        if not fixture.exists():
            print("Falta el fixture; ejecute: python scripts/build_demo_fixture.py", file=sys.stderr)
            return 1
        with session_scope() as db:
            if not db.scalars(select(AppUser)).first():
                pw = args.admin_password or ""
                while len(pw) < 12:
                    pw = getpass.getpass("Contraseña para el usuario 'admin' (mín. 12 caracteres): ")
                    if len(pw) < 12:
                        print("La contraseña debe tener al menos 12 caracteres. Intente de nuevo.")
                db.add(AppUser(username="admin", password_hash=hash_password(pw), role="administrador"))
            system = db.scalars(select(SapSystem).where(SapSystem.sid == "DMO")).first()
            if system is None:
                system = SapSystem(sid="DMO", description="Sistema FICTICIO de demostración", environment="PRD",
                                   productive=True, sensitivity=1.0)
                db.add(system)
                db.flush()
            conn = db.scalars(select(SapConnection).where(SapConnection.system_id == system.id)).first()
            if conn is None:
                conn = SapConnection(system_id=system.id, client="100", name="DMO 100 (datos de prueba)",
                                     backend="fixture", rfc_user="SECX_READ", fixture_path=str(fixture))
                db.add(conn)
                db.flush()
            snap = run_extraction(db, conn, "demo")
            print(f"Snapshot #{snap.id} {snap.status} (DATOS DE PRUEBA). Inicie: sapsec serve")
    elif args.cmd == "list-connections":
        with session_scope() as db:
            for c in db.scalars(select(SapConnection)):
                print(f"{c.id:4} {c.system.sid}/{c.client} {c.name} backend={c.backend} usuario={c.rfc_user}")
    elif args.cmd == "list-snapshots":
        from .storage.orm import Snapshot
        with session_scope() as db:
            for sn in db.scalars(select(Snapshot).order_by(Snapshot.id)):
                print(f"{sn.id:4} {sn.sid}/{sn.client} {sn.started_at:%Y-%m-%d %H:%M} {sn.status}"
                      f"{' (prueba)' if sn.is_test_data else ''} conexión={sn.connection_id}")
    elif args.cmd == "delete-snapshot":
        from .services import delete_snapshot
        if not args.yes and input(f"¿Eliminar el snapshot #{args.id}? (s/N): ").strip().lower() != "s":
            print("Cancelado.")
            return 1
        with session_scope() as db:
            counts = delete_snapshot(db, args.id)
            from .security.audit import audit
            audit(db, "cli", "snapshot_eliminado", f"#{args.id}", {"filas": sum(counts.values())})
        print(f"Snapshot #{args.id} eliminado ({sum(counts.values())} filas).")
    elif args.cmd == "delete-connection":
        from .services import delete_connection
        with session_scope() as db:
            c = db.get(SapConnection, args.id)
            if c is None:
                print(f"No existe la conexión {args.id}", file=sys.stderr)
                return 1
            label = f"{c.system.sid}/{c.client} ({c.name})"
        if not args.yes and input(f"¿Eliminar la conexión {label}, sus snapshots y su contraseña guardada? (s/N): "
                                  ).strip().lower() != "s":
            print("Cancelado.")
            return 1
        with session_scope() as db:
            res = delete_connection(db, args.id)
            from .security.audit import audit
            audit(db, "cli", "conexion_eliminada", res["sistema"], res)
        print(f"Eliminada {res['sistema']}: {res['snapshots']} snapshot(s); contraseña guardada "
              f"{'borrada' if res['credencial_borrada'] else 'no había'}.")
    elif args.cmd == "run-due":
        from .scheduler import run_due_inline
        n = run_due_inline(session_scope, "tarea de Windows", progress=lambda m: logging.getLogger("sapsec.programado").info(m))
        logging.getLogger("sapsec.programado").info("run-due: %d programación(es) ejecutada(s)", n)
        print(f"Programaciones ejecutadas: {n}")
    elif args.cmd == "run-schedule":
        from .scheduler import execute
        with session_scope() as db:
            res = execute(db, args.id, args.trigger, progress=lambda m: print(m))
        print(f"Terminado: {sum(1 for r in res if r['estado'] != 'error')} correctos, "
              f"{sum(1 for r in res if r['estado'] == 'error')} con error.")
    elif args.cmd == "extract-all":
        from .security.audit import audit
        from .services import extract_and_prepare
        with session_scope() as db:
            conns = [c for c in db.scalars(select(SapConnection).where(SapConnection.active.is_(True))
                                           .order_by(SapConnection.id))
                     if not args.ambiente or (c.system.environment or "").upper() == args.ambiente]
            ids = [(c.id, c.label) for c in conns]
        failures = 0
        for i, (cid, label) in enumerate(ids, start=1):
            print(f"[{i}/{len(ids)}] {label}")
            try:
                with session_scope() as db:
                    c = db.get(SapConnection, cid)
                    snap = extract_and_prepare(db, c, "programado", progress=lambda m: print("   ", m))  # type: ignore[arg-type]
                    audit(db, "programado", "extraccion", c.name, {"snapshot": snap.id, "estado": snap.status})  # type: ignore[union-attr]
                    print(f"    → snapshot #{snap.id}: {snap.status}")
                    failures += snap.status == "error"
            except Exception as exc:  # noqa: BLE001 - seguir con el próximo sistema
                failures += 1
                print(f"    → ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(f"Terminado: {len(ids) - failures} correctos, {failures} con error.")
        return 1 if failures else 0
    elif args.cmd == "reset-sap-data":
        from .services import reset_sap_data
        if not args.yes and input("Se borrarán TODOS los sistemas, snapshots, hallazgos y contraseñas guardadas.\n"
                                  "Escriba BORRAR para confirmar: ").strip().upper() != "BORRAR":
            print("Cancelado.")
            return 1
        with session_scope() as db:
            res = reset_sap_data(db)
            from .security.audit import audit
            audit(db, "cli", "datos_sap_borrados", "todos", {"conexiones": [c["sistema"] for c in res["conexiones"]]})
        print("Listo. Conexiones eliminadas: " + (", ".join(c["sistema"] for c in res["conexiones"]) or "ninguna"))
    elif args.cmd == "test-connection":
        from .services import test_connection
        with session_scope() as db:
            c = db.get(SapConnection, args.id)
            print(json.dumps(test_connection(c), indent=2, ensure_ascii=False))  # type: ignore[arg-type]
    elif args.cmd == "extract":
        from .services import run_extraction
        pf = Path(args.progress_file) if args.progress_file else None
        state: dict = {"estado": "en_curso", "fase": "Conectando…", "snapshot": None, "error": None}

        def write() -> None:
            if pf:
                tmp = pf.with_suffix(".tmp")
                tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
                os.replace(tmp, pf)

        def progress(msg: str) -> None:
            state["fase"] = msg
            write()

        write()
        try:
            with session_scope() as db:
                c = db.get(SapConnection, args.id)
                from .services import extract_and_prepare
                snap = extract_and_prepare(db, c, args.user, progress=progress)  # type: ignore[arg-type]
                from .security.audit import audit
                audit(db, args.user, "extraccion", c.name, {"snapshot": snap.id, "estado": snap.status})  # type: ignore[union-attr]
                state.update(snapshot=snap.id, estado="error" if snap.status == "error" else "terminado",
                             fase=f"Terminado: snapshot #{snap.id} {snap.status}")
                if snap.status == "error":
                    state["error"] = "; ".join(i.get("message", "") for i in snap.issues)
                write()
                print(f"Snapshot #{snap.id}: {snap.status}")
                for i in snap.issues:
                    print(" -", i["code"], i["message"])
        except Exception as exc:  # noqa: BLE001
            state.update(estado="error", error=f"{type(exc).__name__}: {exc}")
            write()
            raise
    elif args.cmd == "precompute":
        from .services import precompute
        with session_scope() as db:
            precompute(db, args.snapshot, progress=lambda m: print(m))
            print("Precálculo terminado")
    elif args.cmd == "analyze":
        from .services import analyze_snapshot
        with session_scope() as db:
            print("Hallazgos:", analyze_snapshot(db, args.snapshot))
    elif args.cmd == "rfc-selftest":
        from .connectors import ConnectionParams, create_connector
        e = os.environ
        params = ConnectionParams(client=e["SAPSEC_RFC_CLIENT"], user=e["SAPSEC_RFC_USER"],
                                  password=e.get("SAPSEC_RFC_PASSWORD") or getpass.getpass("Contraseña RFC: "),
                                  ashost=e.get("SAPSEC_RFC_ASHOST"), sysnr=e.get("SAPSEC_RFC_SYSNR"),
                                  lang=e.get("SAPSEC_RFC_LANG", "ES"))
        c = create_connector(e.get("SAPSEC_RFC_BACKEND", "nwrfc"), params)
        with c:
            if hasattr(c, "sdk_version"):
                print("SDK:", c.sdk_version())  # type: ignore[attr-defined]
            c.ping()
            print("RFC_PING OK")
            print(json.dumps(c.system_info(), indent=2))
            res = c.call("RFC_READ_TABLE", QUERY_TABLE="TACTT", ROWCOUNT=3, DELIMITER="",
                         FIELDS=[{"FIELDNAME": "ACTVT"}, {"FIELDNAME": "LTEXT"}], OPTIONS=[{"TEXT": "SPRAS = 'S'"}])
            print("RFC_READ_TABLE TACTT:", res.get("DATA"))
    elif args.cmd == "reset-password":
        from .security.auth import hash_password
        with session_scope() as db:
            u = db.scalars(select(AppUser).where(AppUser.username == args.username)).first()
            if u is None:
                raise ValueError(f"No existe el usuario de la aplicación {args.username}")
            pw = ""
            while len(pw) < 12:
                pw = getpass.getpass(f"Nueva contraseña para {u.username} (mín. 12 caracteres): ")
                if len(pw) < 12:
                    print("La contraseña debe tener al menos 12 caracteres. Intente de nuevo.")
                elif getpass.getpass("Repetir: ") != pw:
                    print("No coinciden. Intente de nuevo.")
                    pw = ""
            u.password_hash, u.failed_logins, u.last_failed_at, u.active = hash_password(pw), 0, None, True
            from .security.audit import audit
            audit(db, "cli", "usuario_app_contrasena", u.username, {"desde": "linea de comandos"})
        print(f"Listo: {args.username} tiene contraseña nueva y está desbloqueado.")
    elif args.cmd == "serve":
        from .webserver import serve
        return serve(host=args.host, port=args.port, network=args.red, https=not args.sin_https)
    elif args.cmd == "servicio":
        from .supervisor import run_service
        return run_service(network=args.red, https=not args.sin_https, port=args.port)
    elif args.cmd == "estado-servicio":
        from .config import data_dir
        from .supervisor import describe_status, read_status
        active, lines = describe_status(read_status(data_dir()))
        for line in lines:
            print("  " + line)
        return 0 if active else 1
    elif args.cmd == "verificar-credenciales":
        return _check_credentials()
    return 0


def _check_credentials() -> int:
    """Para el Programador de tareas: el almacén de credenciales de Windows es por usuario. Sin mostrar secretos,
    indica qué conexiones SAP no tienen contraseña guardada para el usuario que ejecuta el comando."""
    from sqlalchemy import select

    from .security.secrets import get_password
    from .storage.db import session_scope
    from .storage.orm import SapConnection
    missing = 0
    with session_scope() as db:
        conns = db.scalars(select(SapConnection).order_by(SapConnection.id)).all()
        for c in conns:
            if c.backend == "fixture" or (c.snc_mode and not c.credential_ref):
                print(f"  -  {c.label}: no usa contraseña")
                continue
            try:
                ok = bool(get_password(c.credential_ref))
            except Exception as exc:  # noqa: BLE001 - se informa sin detener la verificación
                ok = False
                print(f"  !  {c.label}: no se pudo leer el almacén de credenciales ({type(exc).__name__})")
            if ok:
                print(f"  OK {c.label}: contraseña guardada para este usuario de Windows")
            else:
                missing += 1
                print(f"  X  {c.label}: SIN contraseña para este usuario de Windows")
    if not conns:
        print("  Todavía no hay conexiones SAP registradas.")
    return 5 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
