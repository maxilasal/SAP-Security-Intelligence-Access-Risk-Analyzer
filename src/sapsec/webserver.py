"""Arranque del servidor web: solo esta PC (``127.0.0.1``) o modo red para otras PC (HTTPS).

Modo local (por defecto)  → http://127.0.0.1:8000, inaccesible desde otras PC.
Modo red (``--red``)      → https://NOMBRE-DEL-EQUIPO:8443 para la red de la empresa y la VPN.
                            Solo se atiende a las redes permitidas (``network.allowed_networks``).
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import sys
import urllib.request

from .config import get_settings
from .security.network import ensure_tls, is_loopback_host, local_addresses, machine_names, parse_networks, urls

log = logging.getLogger(__name__)
LOCAL_PORT = 8000


def _port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _our_app_at(url: str) -> bool:
    """¿Responde esta misma aplicación en la URL? (sonda local; no envía datos)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # es el propio equipo: solo se comprueba si está abierta
    try:
        with urllib.request.urlopen(url + "/api/v1/salud", timeout=2, context=ctx) as r:  # noqa: S310
            return json.loads(r.read().decode()).get("estado") == "ok"
    except Exception:  # noqa: BLE001
        return False


def serve(host: str | None = None, port: int | None = None, network: bool = False, https: bool = True) -> int:
    s = get_settings()
    if host is None:
        host = "0.0.0.0" if network else "127.0.0.1"
    network = network or not is_loopback_host(host)
    if port is None:
        port = s.network.port if network else LOCAL_PORT
    use_https = network and https
    parse_networks(s.network.allowed_networks)  # valida la configuración antes de arrancar

    scheme = "https" if use_https else "http"
    if _our_app_at(f"{scheme}://127.0.0.1:{port}"):
        print(f"\n  La aplicación ya está abierta en {scheme}://localhost:{port} (en otra ventana o iniciada con "
              "Windows).\n  Use esa dirección, o cierre la otra antes de abrir esta.\n")
        return 0
    if not network and _our_app_at(f"https://127.0.0.1:{s.network.port}"):
        print(f"\n  La aplicación ya está abierta en MODO RED: https://localhost:{s.network.port}\n"
              "  Use esa dirección (también funciona en esta PC).\n")
        return 0
    if not _port_free(host, port):
        print(f"\n  El puerto {port} está ocupado por otro programa. Elija otro con --port "
              f"(o en run.ps1: -Puerto N).\n", file=sys.stderr)
        return 4

    ssl_kw: dict = {}
    if use_https:
        tls = ensure_tls()
        ssl_kw = {"ssl_certfile": str(tls.cert), "ssl_keyfile": str(tls.key)}
    os.environ["SAPSEC_SERVE_MODE"] = "red" if network else "local"
    os.environ["SAPSEC_SERVE_PORT"] = str(port)
    os.environ["SAPSEC_SERVE_HTTPS"] = "1" if use_https else "0"

    line = "=" * 74
    print(f"\n{line}\n  SAP Security Analyzer")
    print(f"  En esta PC:      {scheme}://localhost:{port}")
    if network:
        names, ips = machine_names(), local_addresses()
        found = urls(port, use_https, names, ips)
        if found:
            print(f"  Desde otras PC:  {found[0]}")
            for u in found[1:4]:
                print(f"                   {u}")
        print("  Redes permitidas: " + ", ".join(s.network.allowed_networks) + " (y esta PC)")
        if use_https and ssl_kw and not s.network.tls_cert_file:
            print("  Certificado: CA local en data\\tls\\ca.crt. Para evitar la advertencia del navegador,")
            print("  instálela una vez en cada PC (ver «Configuración y acceso» en la aplicación).")
        if not use_https:
            print("  ATENCIÓN: sin HTTPS las contraseñas viajan sin cifrar por la red. Úselo solo para pruebas.")
        print("  Desde fuera de la oficina: conectarse primero a la VPN de la empresa.")
        print("  Si otra PC no llega: ejecutar una vez, como administrador, scripts\\habilitar_acceso_red.ps1")
    else:
        print("  Solo esta PC puede entrar. Para otras PC: scripts\\run.ps1 -Red")
    print(f"  Para cerrar: Ctrl+C o cerrar esta ventana.\n{line}\n")

    import uvicorn
    uvicorn.run("sapsec.api.app:create_app", factory=True, host=host, port=port, **ssl_kw, **uvicorn_options())
    return 0


def uvicorn_options(windows: bool | None = None) -> dict:
    """Opciones de uvicorn. En Windows, sin colores: la consola clásica los muestra como «←[32mINFO←[0m»."""
    kw: dict = {"server_header": False}
    if (os.name == "nt") if windows is None else windows:
        kw["use_colors"] = False
    if sys.stdout is None or sys.stderr is None:  # pythonw (inicio automático sin ventana): log solo a archivo
        kw["log_config"] = None
    return kw
