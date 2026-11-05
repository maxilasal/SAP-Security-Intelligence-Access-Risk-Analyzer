"""Pruebas de la interfaz web y la API con el sistema ficticio (base SQLite temporal)."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import ROOT


@pytest.fixture(scope="module")
def client():  # type: ignore[no-untyped-def]
    from sapsec.api.app import create_app
    from sapsec.security.auth import hash_password
    from sapsec.services import run_extraction
    from sapsec.storage.db import init_db, session_scope
    from sapsec.storage.orm import AppUser, SapConnection, SapSystem
    init_db()
    with session_scope() as db:
        if not db.scalars(select(AppUser)).first():
            db.add(AppUser(username="admin", password_hash=hash_password("Clave-de-prueba-123"), role="administrador"))
            db.add(AppUser(username="consulta", password_hash=hash_password("Clave-de-prueba-456"), role="consultor"))
        s = SapSystem(sid="DMO", environment="PRD", productive=True, sensitivity=1.0)
        db.add(s)
        db.flush()
        c = SapConnection(system_id=s.id, client="100", name="demo", backend="fixture", rfc_user="SECX",
                          fixture_path=str(ROOT / "tests" / "fixtures" / "demo_system.json"))
        db.add(c)
        db.flush()
        run_extraction(db, c, "pytest")
    return TestClient(create_app(), client=("127.0.0.1", 50000))


def csrf(c: TestClient, path: str = "/login") -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', c.get(path).text)
    assert m
    return m.group(1)


def login(c: TestClient, user: str = "admin", pw: str = "Clave-de-prueba-123") -> None:
    c.cookies.clear()
    r = c.post("/login", data={"username": user, "password": pw, "csrf": csrf(c)}, follow_redirects=False)
    assert r.status_code == 303


def test_requires_login(client):
    client.cookies.clear()
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/api/v1/usuarios/X").status_code == 401


def test_bad_password_and_csrf(client):
    client.cookies.clear()
    tok = csrf(client)
    assert "Credenciales inválidas" in client.post("/login", data={"username": "admin", "password": "x", "csrf": tok}).text
    r = client.post("/login", data={"username": "admin", "password": "x", "csrf": "malo"}, follow_redirects=False)
    assert r.status_code == 303 and "expirado" in r.headers["location"]  # formulario vencido: se pide reingresar
    assert "venció" in client.get(r.headers["location"]).text


def test_pages_render(client):
    login(client)
    for path in ["/", "/conexiones", "/usuarios", "/usuarios/USUARIO_TEST", "/roles", "/roles/Z_MM_COMPRADOR_C",
                 "/roles/Z_FI_DESACTUALIZADO", "/objetos?objeto=S_USER_AGR&campo=ACTVT&valor=02", "/objetos?tcode=SU01",
                 "/criticas", "/sod", "/simulador", "/comparador-roles?a=Z_FI_PAGOS&b=Z_FI_PAGOS_CONSULTA",
                 "/comparador-sistemas?snap_a=1&snap_b=1", "/recomendaciones", "/hallazgos", "/hallazgos/1",
                 "/reportes", "/reglas", "/configuracion", "/auditoria", "/snapshots/1"]:
        r = client.get(path)
        assert r.status_code == 200, (path, r.text[:500])
        assert "DATOS DE PRUEBA" in r.text or path.startswith("/snapshots")
    assert "SAP_ALL" in client.get("/usuarios/ADMIN_BASIS").text
    assert "SEG_ADMIN" in client.get("/objetos?objeto=S_USER_AGR&campo=ACTVT&valor=02").text


def test_simulator_flow_and_reports(client):
    login(client)
    tok = csrf(client, "/simulador")
    r = client.post("/simulador", data={"csrf": tok, "usuario": "USUARIO_TEST", "agregar": "Z_FI_PAGOS"})
    assert r.status_code == 200
    assert "NO RECOMENDADO" in r.text and "SOD-FI-001" in r.text and "Z_FI_PROVEEDORES" in r.text
    assert "No asignar Z_FI_PAGOS a USUARIO_TEST." in r.text
    sim = re.search(r"/simulaciones/(\d+)/reporte", r.text).group(1)  # type: ignore[union-attr]
    for fmt, magic in [("pdf", b"%PDF"), ("xlsx", b"PK"), ("html", b"<!doctype"), ("csv", b"\xef\xbb\xbf")]:
        d = client.get(f"/simulaciones/{sim}/reporte?formato={fmt}&tipo=tecnico")
        assert d.status_code == 200 and d.content.startswith(magic), fmt
    assert b"DATOS FICTICIOS" in client.get(f"/simulaciones/{sim}/reporte?formato=html&tipo=ejecutivo").content
    for tipo in ["ejecutivo", "auditor", "criticos", "sap_all", "sod_usuario", "sod_rol", "admin", "plan"]:
        assert client.get(f"/reportes/descargar?tipo={tipo}&formato=xlsx").status_code == 200
    plan_csv = client.get("/reportes/descargar?tipo=plan&formato=csv").content.decode("utf-8-sig")
    assert "Responsable" in plan_csv and "Quitar el perfil SAP_ALL a ADMIN_BASIS" in plan_csv
    assert client.get("/reportes/descargar?tipo=usuario&usuario=SEG_ADMIN&formato=pdf").content.startswith(b"%PDF")


def test_api_simulation(client):
    login(client)
    tok = csrf(client, "/simulador")
    r = client.post("/api/v1/simular", json={"usuario": "SEG_ADMIN", "quitar": ["Z_SEC_USUARIOS"]},
                    headers={"x-csrf-token": tok})
    assert r.status_code == 200 and r.json()["riesgo_despues"] < r.json()["riesgo_antes"]
    assert client.post("/api/v1/simular", json={"usuario": "X"}).status_code == 403


def test_consultant_is_read_only(client):
    login(client, "consulta", "Clave-de-prueba-456")
    tok = csrf(client, "/simulador")
    assert client.post("/conexiones", data={"csrf": tok, "sid": "X", "client": "1", "rfc_user": "U"}).status_code == 403
    assert client.post("/conexiones/1/extraer", data={"csrf": tok}).status_code == 403
    assert client.post("/hallazgos/1", data={"csrf": tok, "status": "corregido"}).status_code == 403
    assert client.get("/usuarios/USUARIO_TEST").status_code == 200


def test_finding_exception_requires_justification_and_is_audited(client):
    login(client)
    tok = csrf(client, "/hallazgos/1")
    assert client.post("/hallazgos/1", data={"csrf": tok, "status": "excepcion"}).status_code == 400
    r = client.post("/hallazgos/1", data={"csrf": tok, "status": "excepcion", "exception_justification": "Acceso de emergencia aprobado",
                                          "exception_expires": "2026-12-31", "owner": "Seguridad"}, follow_redirects=False)
    assert r.status_code == 303
    assert "hallazgo_actualizado" in client.get("/auditoria").text


def test_security_headers(client):
    login(client)
    r = client.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "DENY"


def test_background_extraction_with_progress(client):
    import time
    login(client)
    tok = csrf(client, "/simulador")
    r = client.post("/conexiones/1/extraer", data={"csrf": tok}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/conexiones/1/progreso"
    end = time.time() + 180  # la extracción corre en otro proceso; en Windows puede tardar en arrancar
    while time.time() < end:
        page = client.get("/conexiones/1/progreso").text
        if "Terminada" in page or "Error" in page:
            break
        time.sleep(0.2)
    assert "Terminada" in page and "Ver qué corregir en este sistema" in page


def test_action_plan_groups_by_cause(client):
    login(client)
    home = client.get("/").text
    assert "Qué corregir primero" in home and "Recomendación de hoy" in home and "Ver cómo hacerlo" in home
    plan = client.get("/acciones").text
    # (la alerta de SAP_ALL tiene una excepción registrada en una prueba anterior: figura entre todas las tareas)
    assert "Quitar el perfil SAP_ALL" in client.get("/acciones?estado=todas").text
    assert "Corregir el rol Z_BC_ADMIN_TOTAL" in plan
    assert "Separar los roles Z_FI_PAGOS y Z_FI_PROVEEDORES" in plan
    key = re.search(r'href="/acciones/([0-9a-f]{12})"[^>]*>\s*<div class="t-main">\s*<div class="t-title"><span class="kind">Separar roles</span>Separar los roles Z_FI_PAGOS', plan)
    assert key, "no se encontró la tarea de combinación"
    detail = client.get(f"/acciones/{key.group(1)}").text
    assert "USUARIO_BLOQ" in detail and "Qué hacer" in detail and "SU01 / SU10" in detail
    assert "Simular quitar" in detail
    assert "No dejar los roles Z_FI_PAGOS y Z_FI_PROVEEDORES juntos" in detail  # recomendación en una frase
    # filtros
    assert "Corregir el rol Z_BC_ADMIN_TOTAL" in client.get("/acciones?q=ADMIN_TOTAL").text
    assert "Quitar el perfil SAP_ALL" not in client.get("/acciones?tipo=combinacion").text


def test_bulk_decision_resolves_task(client):
    login(client)
    plan = client.get("/acciones?q=SAP_NEW").text
    key = re.search(r'href="/acciones/([0-9a-f]{12})"', plan).group(1)  # type: ignore[union-attr]
    tok = csrf(client, f"/acciones/{key}")
    r = client.post(f"/acciones/{key}/gestionar", data={"csrf": tok, "status": "excepcion"}, follow_redirects=False)
    assert r.status_code == 400  # sin justificación
    r = client.post(f"/acciones/{key}/gestionar", data={"csrf": tok, "status": "excepcion", "owner": "Basis",
                    "exception_justification": "Usuario técnico en revisión", "exception_expires": "2026-12-31"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert "resuelta / aceptada" in client.get(f"/acciones/{key}").text
    assert "Quitar el perfil SAP_NEW" in client.get("/acciones?estado=resueltas").text


def test_grouped_risk_views_and_user_fix_list(client):
    login(client)
    crit = client.get("/criticas").text
    assert "Modificar todas las tablas" in crit and "Qué hacer" in crit
    u = client.get("/usuarios/USUARIO_BLOQ").text
    assert "Qué corregir" in u and "Mantener datos bancarios de proveedores y ejecutar pagos" in u
    assert "Ver cómo corregirlo" in u and "Recomendación" in u
    r = client.get("/roles/Z_BC_ADMIN_TOTAL").text
    assert "Qué corregir en este rol" in r and "Ver la tarea de corrección" in r and "Recomendación" in r
    sim = client.get("/simulador?usuario=SEG_ADMIN&quitar=Z_SEC_USUARIOS").text
    assert 'value="SEG_ADMIN"' in sim and 'value="Z_SEC_USUARIOS"' in sim


def test_app_user_management_lockout_and_own_password(client):
    """Varias personas: bloqueo temporal, desbloqueo, restablecer, desactivar y cambiar la propia contraseña."""
    from datetime import timedelta

    from sapsec.storage.db import session_scope
    from sapsec.storage.orm import AppUser, utcnow
    login(client)
    tok = csrf(client, "/configuracion")
    assert client.post("/configuracion/usuarios", data={"csrf": tok, "username": "operador", "role": "consultor",
                                                       "password": "Operador-clave-001"}).status_code == 200
    assert client.post("/configuracion/usuarios", data={"csrf": tok, "username": "operador", "role": "consultor",
                                                       "password": "Operador-clave-001"}).status_code == 400
    with session_scope() as db:
        uid = db.scalars(select(AppUser).where(AppUser.username == "operador")).one().id
    client.cookies.clear()
    for _ in range(5):
        client.post("/login", data={"username": "operador", "password": "mal", "csrf": csrf(client)})
    page = client.post("/login", data={"username": "operador", "password": "Operador-clave-001", "csrf": csrf(client)}).text
    assert "bloqueado" in page and "15 minutos" in page          # bloqueado aunque ahora la clave sea correcta
    login(client)
    cfg = client.get("/configuracion").text
    assert "bloqueado (5 intentos)" in cfg and "Acceso desde otras PC" in cfg and "VPN" in cfg
    tok = csrf(client, "/configuracion")
    assert client.post(f"/configuracion/usuarios/{uid}/desbloquear", data={"csrf": tok}, follow_redirects=False).status_code == 303
    login(client, "operador", "Operador-clave-001")
    tok = csrf(client, "/mi-cuenta")
    assert client.post("/mi-cuenta/contrasena", data={"csrf": tok, "actual": "otra", "nueva": "Operador-clave-002",
                                                      "repetir": "Operador-clave-002"}).status_code == 400
    assert client.post("/mi-cuenta/contrasena", data={"csrf": tok, "actual": "Operador-clave-001",
                                                      "nueva": "Operador-clave-002", "repetir": "otra"}).status_code == 400
    r = client.post("/mi-cuenta/contrasena", data={"csrf": tok, "actual": "Operador-clave-001",
                                                   "nueva": "Operador-clave-002", "repetir": "Operador-clave-002"},
                    follow_redirects=False)
    assert r.status_code == 303 and "Contraseña cambiada" in client.get(r.headers["location"]).text
    assert client.post(f"/configuracion/usuarios/{uid}/desbloquear", data={"csrf": tok}).status_code == 403  # no es admin
    login(client, "operador", "Operador-clave-002")
    # bloqueo temporal: pasados los 15 minutos vuelve a poder entrar
    with session_scope() as db:
        u = db.get(AppUser, uid)
        u.failed_logins, u.last_failed_at = 5, utcnow() - timedelta(minutes=16)
    login(client, "operador", "Operador-clave-002")
    # el administrador restablece la contraseña y luego lo desactiva
    login(client)
    tok = csrf(client, "/configuracion")
    client.post(f"/configuracion/usuarios/{uid}/contrasena", data={"csrf": tok, "password": "Reset-por-admin-03"})
    login(client, "operador", "Reset-por-admin-03")
    login(client)
    tok = csrf(client, "/configuracion")
    client.post(f"/configuracion/usuarios/{uid}/desactivar", data={"csrf": tok})
    client.cookies.clear()
    assert "Credenciales inválidas" in client.post("/login", data={"username": "operador", "password": "Reset-por-admin-03",
                                                                   "csrf": csrf(client)}).text
    login(client)
    tok = csrf(client, "/configuracion")
    with session_scope() as db:
        admin_id = db.scalars(select(AppUser).where(AppUser.username == "admin")).one().id
    assert client.post(f"/configuracion/usuarios/{admin_id}/desactivar", data={"csrf": tok}).status_code == 400
    assert "usuario_app_desactivar" in client.get("/auditoria").text


def test_sap_style_wildcard_searches(client):
    """Comodines como en SAP: Z* empieza con Z, *X termina en X, + un carácter, varios separados por coma."""
    login(client)

    def users(qs):  # type: ignore[no-untyped-def]
        return set(re.findall(r'<tr><td><a href="/usuarios/([^"]+)">', client.get(f"/usuarios?{qs}").text))

    assert users("q=ADMIN_*") == {"ADMIN_BASIS", "ADMIN_EQUIV"}            # empieza con
    assert "SEG_ADMIN" in users("q=ADMIN*")  # el patrón vale para el usuario o el nombre («Administrador de…»)
    assert users("q=*ADMIN") == {"SEG_ADMIN"}                              # termina con
    assert users("q=ADMIN") >= {"ADMIN_BASIS", "ADMIN_EQUIV", "SEG_ADMIN"}  # sin comodines: contiene
    assert users("q=DEV_USE%2B") == {"DEV_USER"}                           # + = un carácter
    assert users("q=CONTADOR1,ALMACEN1") == {"CONTADOR1", "ALMACEN1"}      # varios criterios
    assert users("perfil=SAP_ALL") == {"ADMIN_BASIS"}
    assert "chip bad\">SAP_ALL" in client.get("/usuarios?perfil=SAP_ALL").text
    fi = users("rol=Z_FI*")
    assert {"USUARIO_TEST", "CONTADOR1"} <= fi and "SEG_ADMIN" not in fi
    roles = set(re.findall(r'<tr><td><a href="/roles/([^"]+)">', client.get("/roles?q=Z_FI*").text))
    assert "Z_FI_PAGOS" in roles and not any(r.startswith("Z_MM") for r in roles)
    rev = client.get("/objetos?objeto=S_TABU*&campo=ACTVT&valor=02").text
    assert "ADMIN_EQUIV" in rev and "S_TABU_DIS" in rev
    assert "DEV_USER" in client.get("/objetos?tcode=SE3*").text
    plan = client.get("/acciones?q=Z_FI*").text
    assert "Z_FI_PAGOS" in plan and "Corregir el rol Z_BC_ADMIN_TOTAL" not in plan
    found = client.get("/hallazgos?q=SOD-*").text
    assert "SOD-" in found and "CRIT-PRF-001" not in found


def test_delete_requires_admin_and_confirmation(client):
    login(client, "consulta", "Clave-de-prueba-456")
    tok = csrf(client, "/simulador")
    assert client.post("/snapshots/1/eliminar", data={"csrf": tok}).status_code == 403
    assert client.post("/conexiones/1/eliminar", data={"csrf": tok}).status_code == 403
    login(client)
    tok = csrf(client, "/configuracion")
    assert client.post("/configuracion/borrar-datos-sap", data={"csrf": tok, "confirmar": "no"}).status_code == 400


def test_full_reset_from_ui_starts_clean(client):
    """Último test del módulo: deja la base vacía de datos SAP."""
    login(client)
    tok = csrf(client, "/configuracion")
    r = client.post("/configuracion/borrar-datos-sap", data={"csrf": tok, "confirmar": "BORRAR"},
                    follow_redirects=False)
    assert r.status_code == 303
    page = client.get(r.headers["location"]).text
    assert "Se borraron todos los sistemas" in page and "No hay conexiones registradas" in page
    assert "Bienvenido" in client.get("/").text  # sin snapshots: pantalla de inicio vacía
    assert "datos_sap_borrados" in client.get("/auditoria").text  # la auditoría se conserva


def _wait_idle(client, timeout: float = 240.0) -> str:  # type: ignore[no-untyped-def]
    import time
    end = time.time() + timeout
    page = ""
    while time.time() < end:
        page = client.get("/sistemas").text
        if "en cola" not in page and "extrayendo" not in page:
            return page
        time.sleep(0.3)
    return page


def test_multi_system_flow(client):
    """Tras el reinicio: dos sistemas PRD con el MISMO SID, cola de extracción y selector por sistema."""
    login(client)
    fixture = str(ROOT / "tests" / "fixtures" / "demo_system.json")
    for name in ("PRD Uruguay", "PRD Argentina"):
        tok = csrf(client, "/conexiones")
        r = client.post("/conexiones", data={"csrf": tok, "system_name": name, "sid": "DMO", "client": "100",
                                             "environment": "PRD", "backend": "fixture", "rfc_user": "SECX",
                                             "fixture_path": fixture}, follow_redirects=False)
        assert r.status_code == 303
    tok = csrf(client, "/conexiones")
    r = client.post("/conexiones", data={"csrf": tok, "system_name": "PRD Uruguay", "sid": "XYZ", "client": "100",
                                         "rfc_user": "SECX", "backend": "fixture"})
    assert r.status_code == 400 and "Ya existe un sistema" in r.text

    tok = csrf(client, "/sistemas")
    assert client.post("/sistemas/extraer", data={"csrf": tok, "ambiente": "PRD"},
                       follow_redirects=False).status_code == 303
    page = _wait_idle(client)
    assert "PRD Uruguay" in page and "PRD Argentina" in page and page.count(">Qué corregir</a>") == 2
    ids = dict((name, int(cid)) for cid, name in re.findall(r'href="/\?sistema=(\d+)"><b>([^<]+)</b>', page))

    home_uy = client.get(f"/?sistema={ids['PRD Uruguay']}").text
    assert re.search(rf'<option value="{ids["PRD Uruguay"]}" selected>PRD Uruguay', home_uy)
    assert 'class="env env-PRD"' in home_uy
    assert re.search(rf'<option value="{ids["PRD Uruguay"]}" selected>', client.get("/acciones").text)  # se mantiene
    assert re.search(rf'<option value="{ids["PRD Argentina"]}" selected>', client.get(f"/?sistema={ids['PRD Argentina']}").text)

    # Nueva extracción de Uruguay: el snapshot anterior queda en el historial y se avisa si se lo mira
    hist = client.get(f"/sistemas/{ids['PRD Uruguay']}").text
    old = int(re.search(r'href="/\?snap=(\d+)"', hist).group(1))  # type: ignore[union-attr]
    tok = csrf(client, "/sistemas")
    client.post(f"/conexiones/{ids['PRD Uruguay']}/extraer", data={"csrf": tok})
    _wait_idle(client)
    import time
    end = time.time() + 120
    while True:  # el snapshot nuevo pasa a ser «el último» cuando termina su análisis
        pinned = client.get(f"/?snap={old}").text
        if f"snapshot anterior #{old}" in pinned or time.time() > end:
            break
        time.sleep(0.5)
    assert f"snapshot anterior #{old}" in pinned and "ver el último" in pinned
    assert "snapshot anterior" not in client.get(f"/?sistema={ids['PRD Uruguay']}").text


def test_schedule_page_create_and_run_now(client):
    import time
    login(client)
    tok = csrf(client, "/programacion")
    r = client.post("/programacion", data={"csrf": tok, "name": "PRD de madrugada", "time_hhmm": "03:00",
                                           "environment": "PRD", "days": ["0", "1", "2", "3", "4", "5", "6"]},
                    follow_redirects=False)
    assert r.status_code == 303
    page = client.get("/programacion").text
    assert "PRD de madrugada" in page and "Todos los días a las 03:00" in page and "Todos los PRD (2)" in page
    sid = re.search(r'action="/programacion/(\d+)/ejecutar"', page).group(1)  # type: ignore[union-attr]
    tok = csrf(client, "/programacion")
    assert client.post(f"/programacion/{sid}/ejecutar", data={"csrf": tok}, follow_redirects=False).status_code == 303
    end = time.time() + 90
    while time.time() < end:
        page = client.get("/programacion").text
        if "2 correctos" in page:
            break
        time.sleep(0.5)
    assert "2 correctos" in page
    # consultor no puede crear ni borrar programaciones
    login(client, "consulta", "Clave-de-prueba-456")
    tok = csrf(client, "/simulador")
    assert client.post("/programacion", data={"csrf": tok, "time_hhmm": "04:00", "days": ["0"]}).status_code == 403
    assert client.post(f"/programacion/{sid}/eliminar", data={"csrf": tok}).status_code == 403


def test_dev_system_controls_and_dev_vs_prd_page(client):
    """Se agrega un DEV del mismo landscape que «PRD Uruguay»: controles de desarrollo y página DEV vs. PRD."""
    from sapsec.storage.db import session_scope
    from sapsec.storage.orm import SapConnection, SapSystem
    login(client)
    fixture = str(ROOT / "tests" / "fixtures" / "demo_system.json")
    tok = csrf(client, "/conexiones")
    r = client.post("/conexiones", data={"csrf": tok, "system_name": "DEV Uruguay", "sid": "DMO", "client": "100",
                                         "environment": "DEV", "landscape": "Uruguay", "backend": "fixture",
                                         "rfc_user": "SECX", "fixture_path": fixture}, follow_redirects=False)
    assert r.status_code == 303
    with session_scope() as db:
        prd_sys = db.scalars(select(SapSystem).where(SapSystem.name == "PRD Uruguay")).one()
        dev_cid = db.scalars(select(SapConnection).join(SapSystem).where(SapSystem.name == "DEV Uruguay")).one().id
        prd_cid = prd_sys.connections[0].id
        prd_id = prd_sys.id
    tok = csrf(client, "/conexiones")
    r = client.post(f"/sistemas/{prd_id}/datos", data={"csrf": tok, "landscape": "Uruguay", "environment": "PRD"},
                    follow_redirects=False)
    assert r.status_code == 303 and "landscape <b>Uruguay</b>" in client.get("/conexiones").text
    client.post(f"/conexiones/{dev_cid}/extraer", data={"csrf": tok})
    _wait_idle(client)
    dev_home = client.get(f"/?sistema={dev_cid}").text
    assert "Sistema de desarrollo" in dev_home and "SAP S/4HANA (S4CORE 108)" in dev_home
    cross = client.get("/entre-sistemas").text
    assert "Desarrollo vs. producción" in cross and "DEV_USER" in cross and "Quitar en producción" in cross
    prd_home = client.get(f"/?sistema={prd_cid}").text
    assert "de DEV tienen permisos críticos en este sistema" in prd_home
    rules = client.get("/reglas").text
    assert "<th>DEV</th>" in rules and "no aplica" in rules
    # consultor no puede cambiar el landscape
    login(client, "consulta", "Clave-de-prueba-456")
    tok = csrf(client, "/simulador")
    assert client.post(f"/sistemas/{prd_id}/datos", data={"csrf": tok, "landscape": "X"}).status_code == 403
