"""Acceso desde otras PC: redes permitidas, certificado HTTPS (CA local restringida) y servidor real."""

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

import pytest

from conftest import ROOT


def test_allowed_networks_block_internet_addresses():
    from sapsec.security.network import client_allowed, parse_networks
    nets = parse_networks(["10.0.0.0/8", "192.168.0.0/16"])
    assert client_allowed("127.0.0.1", nets) and client_allowed("::1", nets)      # esta PC, siempre
    assert client_allowed("10.20.30.40", nets) and client_allowed("192.168.1.5", nets)
    assert client_allowed("::ffff:10.1.2.3", nets)                                 # IPv4 dentro de IPv6
    assert not client_allowed("203.0.113.9", nets) and not client_allowed("8.8.8.8", nets)
    assert not client_allowed("172.16.0.1", nets)                                  # no está en la lista
    assert not client_allowed("no-es-una-ip", nets)
    assert client_allowed("172.20.1.1", parse_networks(["privadas"]))
    with pytest.raises(ValueError, match="allowed_networks"):
        parse_networks(["10.0.0.0/33"])


def test_web_rejects_outside_addresses_with_vpn_hint():
    from fastapi.testclient import TestClient

    from sapsec.api.app import create_app
    app = create_app()
    r = TestClient(app, client=("203.0.113.9", 40000)).get("/login")
    assert r.status_code == 403 and "VPN" in r.text and "203.0.113.9" in r.text
    assert TestClient(app, client=("192.168.10.20", 40000)).get("/login").status_code == 200
    assert TestClient(app, client=("10.8.0.7", 40000)).get("/api/v1/salud").json()["estado"] == "ok"


def test_local_ca_and_server_certificate(tmp_path, monkeypatch):
    from cryptography import x509

    from sapsec.security import network
    monkeypatch.setattr(network, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(network, "machine_names", lambda: ["sapsec01", "sapsec01.empresa.local"])
    monkeypatch.setattr(network, "local_addresses", lambda: ["192.168.1.20"])
    tls = network.ensure_tls()
    ca = x509.load_pem_x509_certificate(tls.ca.read_bytes())
    leaf = x509.load_pem_x509_certificate(tls.cert.read_bytes())
    leaf.verify_directly_issued_by(ca)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert {"sapsec01", "sapsec01.empresa.local", "localhost"} <= set(san.get_values_for_type(x509.DNSName))
    assert {"127.0.0.1", "192.168.1.20"} <= {str(i) for i in san.get_values_for_type(x509.IPAddress)}
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    nc = ca.extensions.get_extension_for_class(x509.NameConstraints)
    assert nc.critical and x509.DNSName("empresa.local") in nc.value.permitted_subtrees  # no sirve para otros sitios
    fp = tls.ca_fingerprint
    # Cambia la IP: se renueva solo el certificado del servidor; la CA instalada en las PC sigue sirviendo.
    monkeypatch.setattr(network, "local_addresses", lambda: ["192.168.1.99"])
    tls2 = network.ensure_tls()
    assert tls2.ca_fingerprint == fp and "192.168.1.99" in tls2.hosts
    # Otro dominio que la CA no cubre: se crea una CA nueva.
    monkeypatch.setattr(network, "machine_names", lambda: ["srv.otra-empresa.com"])
    assert network.ensure_tls().ca_fingerprint != fp


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_network_mode_serves_https_with_verifiable_certificate(tmp_path):
    """Servidor real en modo red: HTTPS válido para la CA local (OpenSSL verifica cadena y restricciones)."""
    port = _free_port()
    cfg = tmp_path / "settings.yaml"
    cfg.write_text(f"database_url: 'sqlite:///{(tmp_path / 'db.sqlite').as_posix()}'\n"
                   f"log_dir: '{(tmp_path / 'logs').as_posix()}'\n", encoding="utf-8")
    env = dict(os.environ, SAPSEC_CONFIG=str(cfg), PYTHONPATH=str(ROOT / "src"))
    env.pop("SAPSEC_DATABASE_URL", None)
    proc = subprocess.Popen([sys.executable, "-m", "sapsec.cli", "serve", "--red", "--host", "127.0.0.1",
                             "--port", str(port)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    try:
        ca = tmp_path / "tls" / "ca.crt"
        ctx = ssl.create_default_context(cafile=None)
        body = None
        for _ in range(100):
            if ca.exists():
                try:
                    ctx = ssl.create_default_context(cafile=str(ca))
                    with urllib.request.urlopen(f"https://localhost:{port}/api/v1/salud", context=ctx,
                                                timeout=2) as r:
                        body = json.loads(r.read())
                        break
                except (OSError, ssl.SSLError):
                    pass
            if proc.poll() is not None:
                break
            time.sleep(0.2)
        assert body == {"estado": "ok", "version": body and body.get("version")}, proc.stdout.read() if proc.poll() is not None else ""
        with urllib.request.urlopen(f"https://127.0.0.1:{port}/login", context=ctx, timeout=5) as r:
            page = r.read().decode()
            assert "Instalar el certificado" in page and r.headers.get("server") is None
        with urllib.request.urlopen(f"https://localhost:{port}/certificado/ca.crt", context=ctx, timeout=5) as r:
            assert r.read() == ca.read_bytes()
        with pytest.raises((ssl.SSLError, OSError)):  # sin la CA, el navegador desconfía (no es un certificado público)
            urllib.request.urlopen(f"https://localhost:{port}/api/v1/salud", context=ssl.create_default_context(),
                                   timeout=5)
    finally:
        proc.terminate()
        try:
            out = proc.communicate(timeout=10)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            out = ""
    assert "Desde otras PC" in out or "En esta PC" in out
