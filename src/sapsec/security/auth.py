"""Usuarios y roles de la aplicación, hashing de contraseñas y control de permisos."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from enum import Enum


class AppRole(str, Enum):
    ADMINISTRADOR = "administrador"
    AUDITOR = "auditor"
    CONSULTOR = "consultor"


# Permiso → roles que lo poseen (mínimo privilegio).
PERMISSIONS: dict[str, set[AppRole]] = {
    "ver": {AppRole.ADMINISTRADOR, AppRole.AUDITOR, AppRole.CONSULTOR},
    "simular": {AppRole.ADMINISTRADOR, AppRole.AUDITOR, AppRole.CONSULTOR},
    "reportes": {AppRole.ADMINISTRADOR, AppRole.AUDITOR, AppRole.CONSULTOR},
    "extraer": {AppRole.ADMINISTRADOR, AppRole.AUDITOR},
    "hallazgos_gestionar": {AppRole.ADMINISTRADOR, AppRole.AUDITOR},
    "mitigaciones": {AppRole.ADMINISTRADOR, AppRole.AUDITOR},
    "conexiones": {AppRole.ADMINISTRADOR},
    "usuarios_app": {AppRole.ADMINISTRADOR},
    "auditoria_app": {AppRole.ADMINISTRADOR, AppRole.AUDITOR},
}


def has_permission(role: str, permission: str) -> bool:
    try:
        return AppRole(role) in PERMISSIONS.get(permission, set())
    except ValueError:
        return False


_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), n=int(n), r=int(r), p=int(p),
                            dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except (ValueError, TypeError):
        return False
