"""Acceso desde otras PC: redes permitidas, direcciones del equipo y certificado HTTPS.

* **Redes permitidas**: solo se atiende a direcciones de la red de la empresa (por defecto, las
  redes privadas, que incluyen la VPN corporativa). Aunque alguien abra un puerto por error en el
  router, las direcciones de internet reciben «acceso no permitido». El propio equipo siempre entra.
* **HTTPS**: si la empresa no entrega un certificado propio, se crea una *CA local* (una sola vez)
  y con ella un certificado del servidor para su nombre y sus IP. Instalando la CA una vez en cada
  PC (o por GPO), el navegador deja de mostrar advertencias, aunque cambie la IP del servidor.
  La CA tiene *restricciones de nombre*: solo puede emitir certificados para este equipo, su dominio
  y direcciones privadas, de modo que no sirve para suplantar otros sitios.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config import PRIVATE_NETWORKS, data_dir, get_settings

log = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
LOOPBACK = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
CA_FILE, CA_KEY, CERT_FILE, KEY_FILE = "ca.crt", "ca.key", "servidor.crt", "servidor.key"


# --------------------------------------------------------------------------------------- redes permitidas
def parse_networks(items: list[str]) -> list[IPNetwork]:
    """Redes permitidas de la configuración (+ el propio equipo). ``privadas`` = todas las redes privadas."""
    nets: list[IPNetwork] = list(LOOPBACK)
    for raw in items or []:
        item = str(raw).strip()
        if not item:
            continue
        if item.lower() in ("privadas", "private"):
            nets += [ipaddress.ip_network(x) for x in PRIVATE_NETWORKS]
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(f"Red permitida inválida en config/settings.yaml (network.allowed_networks): "
                             f"{item!r}. Use el formato 10.20.0.0/16 o una IP sola.") from exc
    return nets


def client_allowed(host: str | None, nets: list[IPNetwork]) -> bool:
    """¿La dirección de origen pertenece a una red permitida? (sin dirección = socket local)."""
    if host is None:
        return True
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])  # quita la zona IPv6 (fe80::1%12)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in nets)


def is_loopback_host(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ------------------------------------------------------------------------------- nombre y direcciones
def _ttl_cache(seconds: float):  # type: ignore[no-untyped-def]
    """Cachea el resultado unos minutos (la resolución de nombres puede tardar en algunas redes)."""
    import functools
    import time

    def deco(fn):  # type: ignore[no-untyped-def]
        state: dict = {}

        @functools.wraps(fn)
        def wrapper():  # type: ignore[no-untyped-def]
            now = time.monotonic()
            if "v" not in state or now - state["t"] > seconds:
                state["v"], state["t"] = fn(), now
            return list(state["v"])
        return wrapper
    return deco


@_ttl_cache(600)
def machine_names() -> list[str]:
    """Nombre corto, nombre completo (con dominio) y alias configurados del equipo, sin repetir."""
    names: list[str] = []
    extra = list(get_settings().network.extra_names or [])
    for n in [socket.gethostname(), socket.getfqdn()] + extra:
        n = (n or "").strip().rstrip(".").lower()
        try:
            n = n.encode("idna").decode("ascii")
        except UnicodeError:
            continue
        if n and n != "localhost" and not _is_ip(n) and n not in names:
            names.append(n)
    return names


@_ttl_cache(600)
def local_addresses() -> list[str]:
    """IPv4 del equipo en redes privadas (las que pueden usar las otras PC)."""
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(str(info[4][0]))
    except OSError:
        pass
    try:  # interfaz de salida principal (un connect UDP no envía paquetes)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.254.254.254", 1))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    private = [ipaddress.ip_network(x) for x in PRIVATE_NETWORKS if ":" not in x]
    out = [ip for ip in ips if any(ipaddress.ip_address(ip) in n for n in private)]
    return sorted(out, key=lambda x: tuple(int(p) for p in x.split(".")))


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def urls(port: int, https: bool, names: list[str] | None = None, ips: list[str] | None = None) -> list[str]:
    scheme = "https" if https else "http"
    hosts = (names if names is not None else machine_names()) + (ips if ips is not None else local_addresses())
    hosts = sorted(dict.fromkeys(hosts), key=lambda h: (_is_ip(h), -h.count("."), h))  # nombre completo primero
    return [f"{scheme}://{h}:{port}" for h in hosts]


# ------------------------------------------------------------------------------------- certificados
@dataclass
class TlsFiles:
    cert: Path
    key: Path
    ca: Path | None          # None = certificado provisto por la empresa
    ca_fingerprint: str = ""
    expires: datetime | None = None
    hosts: tuple[str, ...] = ()


def tls_dir() -> Path:
    d = data_dir() / "tls"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:  # en Windows los permisos los hereda la carpeta
        pass


def fingerprint(cert_pem_path: Path, algo: str = "sha256") -> str:
    """Huella del certificado. SHA-1 en grupos de 8 es la que muestra Windows al instalarlo."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_pem_x509_certificate(cert_pem_path.read_bytes())
    if algo == "sha1":
        h = cert.fingerprint(hashes.SHA1()).hex().upper()  # noqa: S303 - solo para comparar con Windows
        return " ".join(h[i:i + 8] for i in range(0, len(h), 8))
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def _name_constraints(names: list[str]):  # type: ignore[no-untyped-def]
    from cryptography import x509
    dns: list[str] = ["localhost"]
    for n in names:
        dns.append(n)
        if "." in n:
            dns.append(n.split(".", 1)[1])  # dominio de la empresa (ej. empresa.local)
    subtrees: list[x509.GeneralName] = [x509.DNSName(d) for d in dict.fromkeys(dns)]
    subtrees += [x509.IPAddress(n) for n in LOOPBACK]
    subtrees += [x509.IPAddress(ipaddress.ip_network(x)) for x in PRIVATE_NETWORKS]
    return x509.NameConstraints(permitted_subtrees=subtrees, excluded_subtrees=None)


def _create_ca(d: Path, names: list[str]) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    host = (names[0] if names else socket.gethostname()).upper()
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAP Security Analyzer"),
                         x509.NameAttribute(NameOID.COMMON_NAME, f"SAP Security Analyzer CA local ({host})"[:64])])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(_name_constraints(names), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    _write_private(d / CA_KEY, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    (d / CA_FILE).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log.info("Creada la CA local %s", d / CA_FILE)


def _ca_covers(ca_cert, names: list[str]) -> bool:  # type: ignore[no-untyped-def]
    """¿Las restricciones de nombre de la CA permiten los nombres actuales del equipo?"""
    from cryptography import x509
    try:
        nc = ca_cert.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return True
    allowed = [g.value.lower() for g in nc.permitted_subtrees or [] if isinstance(g, x509.DNSName)]
    return all(any(n == a or n.endswith("." + a) for a in allowed) for n in names)


def _create_server_cert(d: Path, names: list[str], ips: list[str]) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    ca_key = serialization.load_pem_private_key((d / CA_KEY).read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((d / CA_FILE).read_bytes())
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = [x509.DNSName(n) for n in names + ["localhost"]]
    sans += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ["127.0.0.1"] + ips]
    cn = (sorted(names, key=lambda n: -n.count(".")) or ["localhost"])[0]
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAP Security Analyzer"),
                                     x509.NameAttribute(NameOID.COMMON_NAME, cn[:64])]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))  # type: ignore[arg-type]
    _write_private(d / KEY_FILE, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    (d / CERT_FILE).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log.info("Emitido el certificado del servidor para %s", ", ".join(names + ips))


def _server_cert_ok(d: Path, names: list[str], ips: list[str]) -> bool:
    from cryptography import x509
    if not (d / CERT_FILE).exists() or not (d / KEY_FILE).exists():
        return False
    try:
        cert = x509.load_pem_x509_certificate((d / CERT_FILE).read_bytes())
        ca = x509.load_pem_x509_certificate((d / CA_FILE).read_bytes())
        cert.verify_directly_issued_by(ca)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except Exception:  # noqa: BLE001 - archivo dañado o de otra CA: se vuelve a emitir
        return False
    have = {n.lower() for n in san.get_values_for_type(x509.DNSName)} | {
        str(i) for i in san.get_values_for_type(x509.IPAddress)}
    want = set(names) | {"localhost", "127.0.0.1"} | set(ips)
    soon = datetime.now(timezone.utc) + timedelta(days=30)
    return want <= have and cert.not_valid_after_utc > soon


def ensure_tls() -> TlsFiles:
    """Certificado para HTTPS: el de la empresa si está configurado; si no, la CA local (se crea o renueva)."""
    net = get_settings().network
    if net.tls_cert_file or net.tls_key_file:
        cert, key = Path(net.tls_cert_file), Path(net.tls_key_file)
        missing = [str(p) for p in (cert, key) if not str(p) or not p.exists()]
        if missing:
            raise ValueError("No se encuentra el certificado configurado en network.tls_cert_file / "
                             f"tls_key_file: {', '.join(missing) or '(vacío)'}")
        return TlsFiles(cert, key, None)
    d = tls_dir()
    names, ips = machine_names(), local_addresses()
    from cryptography import x509
    ca_ok = (d / CA_FILE).exists() and (d / CA_KEY).exists()
    if ca_ok:
        ca_cert = x509.load_pem_x509_certificate((d / CA_FILE).read_bytes())
        ca_ok = _ca_covers(ca_cert, names) and ca_cert.not_valid_after_utc > datetime.now(timezone.utc) + timedelta(days=60)
        if not ca_ok:
            log.warning("La CA local no cubre el nombre actual del equipo o está por vencer: se crea una nueva "
                        "(hay que volver a instalarla en las PC).")
    if not ca_ok:
        _create_ca(d, names)
    if not _server_cert_ok(d, names, ips):
        _create_server_cert(d, names, ips)
    cert = x509.load_pem_x509_certificate((d / CERT_FILE).read_bytes())
    return TlsFiles(d / CERT_FILE, d / KEY_FILE, d / CA_FILE, fingerprint(d / CA_FILE), cert.not_valid_after_utc,
                    tuple(names + ips))


def local_ca() -> Path | None:
    """CA local para descargar e instalar en las PC (None si se usa un certificado de la empresa)."""
    if get_settings().network.tls_cert_file:
        return None
    p = data_dir() / "tls" / CA_FILE
    return p if p.exists() else None


# ------------------------------------------------------------------------------- estado del servidor
def serve_info() -> dict:
    """Cómo está publicada la aplicación (lo informa ``sapsec serve`` en variables de entorno)."""
    mode = os.environ.get("SAPSEC_SERVE_MODE", "")
    https = os.environ.get("SAPSEC_SERVE_HTTPS") == "1"
    port = int(os.environ.get("SAPSEC_SERVE_PORT") or 0)
    net = get_settings().network
    ca = local_ca() if https else None
    info = {"mode": mode or "desconocido", "https": https, "port": port, "urls": [],
            "local_url": f"{'https' if https else 'http'}://localhost:{port}" if port else "",
            "allowed": net.allowed_networks, "company_cert": bool(net.tls_cert_file),
            "ca": bool(ca), "ca_fingerprint": fingerprint(ca) if ca else "",
            "ca_thumbprint": fingerprint(ca, "sha1") if ca else "", "network_port": net.port}
    if mode == "red" and port:
        info["urls"] = urls(port, https)
    return info
