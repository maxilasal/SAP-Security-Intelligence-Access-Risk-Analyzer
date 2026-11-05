"""Abstracción de conectividad RFC.

La aplicación nunca depende de una librería RFC concreta. Todos los backends
implementan :class:`RfcConnector`, que expone únicamente llamadas de LECTURA.

Backends disponibles:

* ``nwrfc``  – binding propio (ctypes) sobre el SAP NetWeaver RFC SDK 7.50, que es
  el componente con soporte oficial de SAP. Sin dependencias de terceros.
* ``pyrfc`` – PyRFC 3.3.1 (proyecto archivado por SAP; solo para entornos que ya lo usan).
* ``fixture`` – datos ficticios en JSON para pruebas sin SAP.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


# Lista permitida de módulos de función. Cualquier otra llamada es rechazada.
# Todas son de lectura. NO se incluye ningún BAPI que modifique datos.
ALLOWED_FUNCTIONS: frozenset[str] = frozenset({
    "RFC_PING",
    "RFC_SYSTEM_INFO",
    "RFC_GET_FUNCTION_INTERFACE",
    "RFC_READ_TABLE",
    "BAPI_USER_GETLIST",
    "BAPI_USER_GET_DETAIL",
    "SUSR_GET_ADMIN_USER_LOGIN_INFO",
    "DDIF_FIELDINFO_GET",
    "Z_SECX_READ",   # extractor Z opcional (ver docs/04_extractor_z_opcional.md)
})

# Funciones con palabras que indican escritura: se bloquean aunque alguien las agregue.
_WRITE_MARKERS = ("_CHANGE", "_CREATE", "_DELETE", "_MODIFY", "_SAVE", "_ASSIGN",
                  "_LOCK", "_UNLOCK", "_SET", "COMMIT", "_UPDATE", "_INSERT", "_ACTGROUPS_")


# Campos de salida que se descartan siempre (p. ej. BAPI_USER_GET_DETAIL-LOGONDATA
# puede devolver hashes según release y autorizaciones). Los backends que permiten
# omitir campos (nwrfc) ni siquiera los leen del contenedor RFC.
SENSITIVE_OUTPUT_FIELDS: frozenset[str] = frozenset({
    "BCODE", "PASSCODE", "PWDSALTEDHASH", "CODVN", "CODVC", "CODVS", "PASSWORD", "PWDHISTORY",
})


def scrub_sensitive(obj: Any) -> Any:
    """Elimina recursivamente campos sensibles de un resultado RFC."""
    if isinstance(obj, dict):
        return {k: scrub_sensitive(v) for k, v in obj.items() if k.upper() not in SENSITIVE_OUTPUT_FIELDS}
    if isinstance(obj, list):
        return [scrub_sensitive(v) for v in obj]
    return obj


class RfcError(Exception):
    """Error genérico de RFC."""

    def __init__(self, message: str, *, code: str = "", key: str = "", group: str = ""):
        super().__init__(message)
        self.code = code
        self.key = key
        self.group = group


class RfcCommunicationError(RfcError):
    pass


class RfcLogonError(RfcError):
    pass


class RfcAuthorizationError(RfcError):
    """El usuario técnico carece de autorización (S_RFC, S_TABU_NAM, S_USER_GRP...)."""


class RfcFunctionNotFound(RfcError):
    pass


class RfcAbapException(RfcError):
    pass


class RfcAbapRuntimeError(RfcError):
    """Error de ejecución (dump) en SAP. SAP cierra la conexión; el conector reconecta en la próxima llamada."""


class RfcForbiddenCall(RfcError):
    """Intento de llamada fuera de la lista permitida."""


@dataclass
class ConnectionParams:
    """Parámetros de conexión. La contraseña nunca se persiste aquí (ver security/secrets.py)."""

    client: str
    user: str
    password: str | None = None
    ashost: str | None = None
    sysnr: str | None = None
    mshost: str | None = None
    msserv: str | None = None
    sysid: str | None = None
    group: str | None = None
    saprouter: str | None = None
    lang: str = "ES"
    snc_mode: bool = False
    snc_qop: str | None = None
    snc_myname: str | None = None
    snc_partnername: str | None = None
    snc_lib: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    def to_rfc_dict(self) -> dict[str, str]:
        # Los usuarios SAP son siempre en mayúsculas; el idioma también.
        p: dict[str, str] = {"client": self.client, "user": self.user.strip().upper(), "lang": self.lang.upper()}
        for k in ("ashost", "sysnr", "mshost", "msserv", "sysid", "group", "saprouter"):
            v = getattr(self, k)
            if v:
                p[k] = v
        if self.password:
            p["passwd"] = self.password
        if self.snc_mode:
            p["snc_mode"] = "1"
            for k in ("snc_qop", "snc_myname", "snc_partnername", "snc_lib"):
                v = getattr(self, k)
                if v:
                    p[k] = v
        p.update(self.extra)
        return p

    def redacted(self) -> dict[str, str]:
        d = self.to_rfc_dict()
        if "passwd" in d:
            d["passwd"] = "********"
        return d


@dataclass
class LoadLimits:
    """Límites de carga por sistema para proteger producción."""

    max_calls_per_minute: int = 120
    max_rows_per_call: int = 20000
    batch_size_in_list: int = 150     # claves por cláusula IN
    pause_between_calls_ms: int = 50
    timeout_seconds: int = 300


class RfcConnector(ABC):
    """Conector de solo lectura con lista permitida y control de carga."""

    backend_name = "abstract"

    def __init__(self, params: ConnectionParams, limits: LoadLimits | None = None):
        self.params = params
        self.limits = limits or LoadLimits()
        self._call_times: list[float] = []
        self.call_count = 0

    # --- API pública -----------------------------------------------------------------
    def call(self, function: str, **kwargs: Any) -> dict[str, Any]:
        self._guard(function)
        self._throttle()
        started = time.monotonic()
        try:
            return scrub_sensitive(self._call(function, **kwargs))
        finally:
            self.call_count += 1
            log.debug("RFC %s (%s) %.0f ms", function, self.backend_name,
                      (time.monotonic() - started) * 1000)

    def ping(self) -> None:
        self.call("RFC_PING")

    def system_info(self) -> dict[str, str]:
        res = self.call("RFC_SYSTEM_INFO")
        info = res.get("RFCSI_EXPORT", {})
        return {k: str(v).strip() for k, v in info.items()}

    @abstractmethod
    def function_exists(self, function: str) -> bool: ...

    @abstractmethod
    def open(self) -> None: ...

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self) -> "RfcConnector":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- internos ----------------------------------------------------------------------
    @abstractmethod
    def _call(self, function: str, **kwargs: Any) -> dict[str, Any]: ...

    def _guard(self, function: str) -> None:
        fn = function.upper()
        if fn not in ALLOWED_FUNCTIONS:
            raise RfcForbiddenCall(f"Función {fn} no permitida (la herramienta es de solo lectura)")
        if fn not in ("RFC_GET_FUNCTION_INTERFACE",) and any(m in fn for m in _WRITE_MARKERS):
            raise RfcForbiddenCall(f"Función {fn} bloqueada por patrón de escritura")

    def _throttle(self) -> None:
        now = time.monotonic()
        self._call_times = [t for t in self._call_times if now - t < 60]
        if len(self._call_times) >= self.limits.max_calls_per_minute:
            wait = 60 - (now - self._call_times[0])
            (log.info if wait >= 5 else log.debug)(
                "Límite de %d llamadas/min alcanzado (protección de carga); pausa de %.1f s",
                self.limits.max_calls_per_minute, wait)
            time.sleep(max(wait, 0))
        if self.limits.pause_between_calls_ms:
            time.sleep(self.limits.pause_between_calls_ms / 1000)
        self._call_times.append(time.monotonic())
