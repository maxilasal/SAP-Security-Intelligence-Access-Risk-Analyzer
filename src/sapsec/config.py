"""Configuración de la aplicación.

Orden de precedencia: variables de entorno ``SAPSEC_*`` > archivo YAML
(``SAPSEC_CONFIG`` o ``config/settings.yaml``) > valores por defecto.
Ningún sistema, mandante ni credencial está escrito en el código.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class AnalysisSettings(BaseModel):
    inactivity_days: int = 90
    expiring_role_days: int = 30
    sap_all_equivalence_threshold: float = 0.8
    stale_snapshot_days: int = 7
    validation_sample_size: int = 20


class SecuritySettings(BaseModel):
    session_secret: str = ""                 # obligatorio fuera de desarrollo
    session_max_age_minutes: int = 480
    max_failed_logins: int = 5
    lockout_minutes: int = 15                # bloqueo temporal tras N intentos fallidos (0 = hasta que un admin desbloquee)
    secure_cookies: bool = False             # True detrás de HTTPS (en modo red con HTTPS se activa solo)
    credential_store: str = "keyring"        # keyring | encrypted_file
    ai_external_allowed: bool = False        # enviar datos a servicios de IA externos


# Redes privadas (RFC 1918 / RFC 4193): oficina y VPN corporativa. Las direcciones de internet quedan fuera.
PRIVATE_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"]


class NetworkSettings(BaseModel):
    """Acceso desde otras PC (``sapsec serve --red``)."""
    port: int = 8443                         # puerto HTTPS en modo red
    allowed_networks: list[str] = Field(default_factory=lambda: list(PRIVATE_NETWORKS))  # desde dónde se puede entrar
    extra_names: list[str] = Field(default_factory=list)  # alias DNS del servidor (ej. sapsec.empresa.local)
    tls_cert_file: str = ""                  # certificado de la empresa (PEM). Vacío = CA local propia en data/tls
    tls_key_file: str = ""


class Settings(BaseModel):
    database_url: str = Field(default_factory=lambda: f"sqlite:///{PROJECT_ROOT / 'data' / 'sapsec.db'}")
    rules_dir: str = str(PROJECT_ROOT / "config" / "rules")
    reports_dir: str = str(PROJECT_ROOT / "data" / "reports")
    log_dir: str = str(PROJECT_ROOT / "data" / "logs")
    log_level: str = "INFO"
    languages: list[str] = ["S", "E"]        # SPRAS: S=español, E=inglés
    data_retention_days: int = 730
    snapshots_to_keep: int = 5               # snapshots que se conservan por sistema (0 = todos)
    include_user_fullname: bool = True
    analysis: AnalysisSettings = AnalysisSettings()
    security: SecuritySettings = SecuritySettings()
    network: NetworkSettings = NetworkSettings()


@lru_cache
def get_settings() -> Settings:
    path = Path(os.environ.get("SAPSEC_CONFIG", PROJECT_ROOT / "config" / "settings.yaml"))
    data: dict = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    env_map = {"SAPSEC_DATABASE_URL": "database_url", "SAPSEC_RULES_DIR": "rules_dir",
               "SAPSEC_LOG_LEVEL": "log_level", "SAPSEC_REPORTS_DIR": "reports_dir"}
    for env, key in env_map.items():
        if os.environ.get(env):
            data[key] = os.environ[env]
    if os.environ.get("SAPSEC_SESSION_SECRET"):
        data.setdefault("security", {})["session_secret"] = os.environ["SAPSEC_SESSION_SECRET"]
    settings = Settings(**data)
    # Rutas relativas → relativas a la carpeta del proyecto (no a la carpeta desde donde se ejecuta).
    # Imprescindible para tareas programadas de Windows, que pueden arrancar en otra carpeta.
    url = settings.database_url
    if url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
        rel = url[len("sqlite:///"):]
        if rel and rel != ":memory:" and not Path(rel).is_absolute():
            settings.database_url = "sqlite:///" + str((PROJECT_ROOT / rel).resolve()).replace("\\", "/")
    for attr in ("rules_dir", "reports_dir", "log_dir"):
        val = getattr(settings, attr)
        if val and not Path(val).is_absolute():
            setattr(settings, attr, str((PROJECT_ROOT / val).resolve()))
    for attr in ("tls_cert_file", "tls_key_file"):
        val = getattr(settings.network, attr)
        if val and not Path(val).is_absolute():
            setattr(settings.network, attr, str((PROJECT_ROOT / val).resolve()))
    return settings


def data_dir() -> Path:
    """Carpeta de datos locales (base SQLite, logs, claves, certificados)."""
    s = get_settings()
    return Path(s.log_dir).parent if s.log_dir else PROJECT_ROOT / "data"
