"""Backend PyRFC (heredado).

ATENCIÓN: SAP archivó el proyecto PyRFC (anuncio de diciembre de 2024, repositorio
de solo lectura). Este backend se mantiene para organizaciones que ya lo tienen
homologado; el backend recomendado es ``nwrfc`` (ctypes sobre el NW RFC SDK).
"""

from __future__ import annotations

from typing import Any

from .base import (ConnectionParams, LoadLimits, RfcAbapException, RfcAbapRuntimeError, RfcAuthorizationError,
                   RfcCommunicationError, RfcConnector, RfcError, RfcFunctionNotFound,
                   RfcLogonError)

_AUTH_KEYS = {"NOT_AUTHORIZED", "NO_AUTHORITY", "NOT_AUTHORIZED_FOR_TABLE"}


class PyRfcConnector(RfcConnector):
    backend_name = "pyrfc"

    def __init__(self, params: ConnectionParams, limits: LoadLimits | None = None):
        super().__init__(params, limits)
        try:
            import pyrfc  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - depende del entorno
            raise RfcError("PyRFC no está instalado. Use el backend 'nwrfc' o instale "
                           "'sapsec[pyrfc]' junto con el SAP NW RFC SDK.") from exc
        self._pyrfc = pyrfc
        self._conn: Any = None

    def open(self) -> None:
        try:
            self._conn = self._pyrfc.Connection(**self.params.to_rfc_dict())
        except Exception as exc:  # noqa: BLE001 - se traduce a errores propios
            raise self._translate(exc) from exc

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def function_exists(self, function: str) -> bool:
        try:
            self._conn.get_function_description(function)
            return True
        except Exception as exc:  # noqa: BLE001
            err = self._translate(exc)
            if isinstance(err, (RfcFunctionNotFound, RfcAbapException)):
                return False
            raise err from exc

    def _call(self, function: str, **kwargs: Any) -> dict[str, Any]:
        if self._conn is None:
            self.open()
        try:
            return self._conn.call(function, **kwargs)
        except Exception as exc:  # noqa: BLE001
            raise self._translate(exc) from exc

    def _translate(self, exc: Exception) -> RfcError:
        p = self._pyrfc
        key = getattr(exc, "key", "") or ""
        msg = getattr(exc, "message", "") or str(exc)
        if isinstance(exc, p.LogonError):
            return RfcLogonError(msg, key=key)
        if isinstance(exc, p.CommunicationError):
            return RfcCommunicationError(msg, key=key)
        if isinstance(exc, p.ABAPRuntimeError):
            self._conn = None
            return RfcAbapRuntimeError(msg, key=key)
        if isinstance(exc, p.ABAPApplicationError):
            if key in _AUTH_KEYS:
                return RfcAuthorizationError(msg, key=key)
            return RfcAbapException(msg, key=key)
        if "FU_NOT_FOUND" in key or "not found" in msg.lower():
            return RfcFunctionNotFound(msg, key=key)
        if "authoriz" in msg.lower() or "autoriz" in msg.lower():
            return RfcAuthorizationError(msg, key=key)
        return RfcError(msg, key=key)
