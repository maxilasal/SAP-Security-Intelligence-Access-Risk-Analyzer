"""Almacenamiento de credenciales SAP fuera del código y de la base de datos.

* ``keyring`` (por defecto): Windows Credential Manager / almacén del SO.
* ``encrypted_file``: archivo cifrado con Fernet (AES-128-CBC + HMAC) usando la
  clave maestra de la variable de entorno ``SAPSEC_MASTER_KEY``.

La base de datos solo guarda una *referencia* (``credential_ref``). Para SNC
con SSO no se almacena contraseña alguna (opción recomendada para PRD).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..config import PROJECT_ROOT, get_settings

SERVICE = "sapsec-rfc"


class CredentialError(RuntimeError):
    pass


def _fernet():  # type: ignore[no-untyped-def]
    from cryptography.fernet import Fernet
    key = os.environ.get("SAPSEC_MASTER_KEY")
    if not key:
        raise CredentialError("Defina SAPSEC_MASTER_KEY (genere una con: sapsec generate-key)")
    return Fernet(key.encode())


def _file() -> Path:
    return Path(os.environ.get("SAPSEC_SECRETS_FILE", PROJECT_ROOT / "data" / "secrets.enc"))


def _load_file() -> dict[str, str]:
    f = _file()
    if not f.exists():
        return {}
    return json.loads(_fernet().decrypt(f.read_bytes()).decode())


def store_password(ref: str, password: str) -> None:
    backend = get_settings().security.credential_store
    if backend == "keyring":
        import keyring
        keyring.set_password(SERVICE, ref, password)
        return
    data = _load_file()
    data[ref] = password
    f = _file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(_fernet().encrypt(json.dumps(data).encode()))


def get_password(ref: str | None) -> str | None:
    if not ref:
        return None
    backend = get_settings().security.credential_store
    if backend == "keyring":
        import keyring
        pw = keyring.get_password(SERVICE, ref)
    else:
        pw = _load_file().get(ref)
    if pw is None:
        raise CredentialError(f"No hay credencial almacenada para la referencia {ref}")
    return pw


def generate_key() -> str:
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()


def delete_password(ref: str | None) -> bool:
    """Elimina la credencial guardada (Administrador de credenciales de Windows o archivo cifrado).
    Devuelve True si existía."""
    if not ref:
        return False
    backend = get_settings().security.credential_store
    if backend == "keyring":
        import keyring
        from keyring.errors import PasswordDeleteError
        try:
            keyring.delete_password(SERVICE, ref)
            return True
        except PasswordDeleteError:
            return False
    data = _load_file()
    if ref not in data:
        return False
    del data[ref]
    _file().write_bytes(_fernet().encrypt(json.dumps(data).encode()))
    return True
