"""Backend ``nwrfc``: binding mínimo vía ctypes sobre el SAP NetWeaver RFC SDK 7.50.

Motivo: PyRFC fue archivado por SAP; el NW RFC SDK 7.50 sigue siendo el componente
con soporte (descarga y plataformas: SAP Note 2573790). Este módulo usa
exclusivamente funciones C documentadas del SDK (sapnwrfc.h):

    RfcOpenConnection, RfcCloseConnection, RfcGetVersion, RfcGetFunctionDesc,
    RfcCreateFunction, RfcDestroyFunction, RfcInvoke, RfcGetParameterCount,
    RfcGetParameterDescByIndex, RfcGetParameterDescByName, RfcGetFieldCount,
    RfcGetFieldDescByIndex, RfcSetString, RfcGetStringLength, RfcGetString,
    RfcGetStructure, RfcGetTable, RfcGetRowCount, RfcMoveTo, RfcGetCurrentRow,
    RfcAppendNewRow

Solo se soportan los tipos necesarios para las funciones de la lista permitida
(campos planos, estructuras y tablas). Los valores se intercambian como texto
(RfcSetString/RfcGetString realizan la conversión de tipos en el SDK).

ESTADO: implementado contra la API documentada del SDK. Debe validarse en su
entorno (``sapsec rfc-selftest``) antes del uso productivo; ver docs/02_conectividad_rfc.md.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import POINTER, Structure, byref, c_int, c_uint, c_ubyte, c_uint16, c_void_p
from typing import Any

from .base import (SENSITIVE_OUTPUT_FIELDS, ConnectionParams, LoadLimits, RfcAbapException, RfcAbapRuntimeError,
                   RfcAuthorizationError, RfcCommunicationError, RfcConnector, RfcError,
                   RfcFunctionNotFound, RfcLogonError)

SAP_UC = c_uint16  # el SDK Unicode usa UTF-16 en todas las plataformas

# RFCTYPE
RFCTYPE_TABLE = 5
RFCTYPE_STRUCTURE = 17
RFCTYPE_STRING = 29
RFCTYPE_XSTRING = 30
RFC_BUFFER_TOO_SMALL = 23
# RFC_DIRECTION
RFC_IMPORT, RFC_EXPORT, RFC_CHANGING, RFC_TABLES = 0x01, 0x02, 0x03, 0x07
# RFC_RC (subconjunto)
RFC_RC = {0: "RFC_OK", 1: "RFC_COMMUNICATION_FAILURE", 2: "RFC_LOGON_FAILURE",
          3: "RFC_ABAP_RUNTIME_FAILURE", 4: "RFC_ABAP_MESSAGE", 5: "RFC_ABAP_EXCEPTION",
          6: "RFC_CLOSED", 7: "RFC_CANCELED", 8: "RFC_TIMEOUT", 9: "RFC_MEMORY_INSUFFICIENT",
          10: "RFC_VERSION_MISMATCH", 11: "RFC_INVALID_PROTOCOL", 12: "RFC_SERIALIZATION_FAILURE",
          13: "RFC_INVALID_HANDLE", 17: "RFC_NOT_FOUND", 18: "RFC_NOT_SUPPORTED",
          19: "RFC_ILLEGAL_STATE", 20: "RFC_INVALID_PARAMETER", 21: "RFC_CODEPAGE_CONVERSION_FAILURE",
          22: "RFC_CONVERSION_FAILURE", 23: "RFC_BUFFER_TOO_SMALL"}


class RFC_ERROR_INFO(Structure):
    _fields_ = [("code", c_int), ("group", c_int), ("key", SAP_UC * 128), ("message", SAP_UC * 512),
                ("abapMsgClass", SAP_UC * 21), ("abapMsgType", SAP_UC * 2),
                ("abapMsgNumber", SAP_UC * 4), ("abapMsgV1", SAP_UC * 51),
                ("abapMsgV2", SAP_UC * 51), ("abapMsgV3", SAP_UC * 51), ("abapMsgV4", SAP_UC * 51)]


class RFC_CONNECTION_PARAMETER(Structure):
    _fields_ = [("name", c_void_p), ("value", c_void_p)]


class RFC_PARAMETER_DESC(Structure):
    _fields_ = [("name", SAP_UC * 31), ("type", c_int), ("direction", c_int),
                ("nucLength", c_uint), ("ucLength", c_uint), ("decimals", c_uint),
                ("typeDescHandle", c_void_p), ("defaultValue", SAP_UC * 31),
                ("parameterText", SAP_UC * 80), ("optional", c_ubyte),
                ("extendedDescription", c_void_p)]


class RFC_FIELD_DESC(Structure):
    _fields_ = [("name", SAP_UC * 31), ("type", c_int), ("nucLength", c_uint),
                ("nucOffset", c_uint), ("ucLength", c_uint), ("ucOffset", c_uint),
                ("decimals", c_uint), ("typeDescHandle", c_void_p),
                ("extendedDescription", c_void_p)]


def _uc(text: str) -> ctypes.Array:
    data = text.encode("utf-16-le")
    buf = (SAP_UC * (len(data) // 2 + 1))()
    ctypes.memmove(buf, data, len(data))
    return buf


def _str(arr: ctypes.Array, length: int | None = None) -> str:
    raw = bytes(arr)
    if length is not None:
        raw = raw[: length * 2]
    return raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]


def _load_library() -> ctypes.CDLL:
    home = os.environ.get("SAPNWRFC_HOME")
    names = ["sapnwrfc.dll"] if sys.platform == "win32" else ["libsapnwrfc.so"]
    candidates: list[str] = []
    if home:
        libdir = os.path.join(home, "lib")
        # En Windows, add_dll_directory falla si la carpeta no existe: se valida antes.
        if sys.platform == "win32" and hasattr(os, "add_dll_directory") and os.path.isdir(libdir):
            os.add_dll_directory(libdir)  # type: ignore[attr-defined]
        candidates += [os.path.join(libdir, n) for n in names]
    candidates += names
    last: Exception | None = None
    for c in candidates:
        try:
            return ctypes.CDLL(c)
        except OSError as exc:
            last = exc
    raise RfcError("No se encontró el SAP NW RFC SDK. Defina SAPNWRFC_HOME (carpeta que contiene "
                   f"lib/{names[0]}) y agregue %SAPNWRFC_HOME%\\lib al PATH. Detalle: {last}")


class _Sdk:
    """Declara firmas de las funciones C utilizadas (una sola vez por proceso)."""

    _instance: "_Sdk | None" = None

    def __init__(self) -> None:
        lib = _load_library()
        E = POINTER(RFC_ERROR_INFO)
        sig = {
            "RfcOpenConnection": (c_void_p, [POINTER(RFC_CONNECTION_PARAMETER), c_uint, E]),
            "RfcCloseConnection": (c_int, [c_void_p, E]),
            "RfcGetVersion": (c_void_p, [POINTER(c_uint), POINTER(c_uint), POINTER(c_uint)]),
            "RfcGetFunctionDesc": (c_void_p, [c_void_p, c_void_p, E]),
            "RfcCreateFunction": (c_void_p, [c_void_p, E]),
            "RfcDestroyFunction": (c_int, [c_void_p, E]),
            "RfcInvoke": (c_int, [c_void_p, c_void_p, E]),
            "RfcGetParameterCount": (c_int, [c_void_p, POINTER(c_uint), E]),
            "RfcGetParameterDescByIndex": (c_int, [c_void_p, c_uint, POINTER(RFC_PARAMETER_DESC), E]),
            "RfcGetParameterDescByName": (c_int, [c_void_p, c_void_p, POINTER(RFC_PARAMETER_DESC), E]),
            "RfcGetFieldCount": (c_int, [c_void_p, POINTER(c_uint), E]),
            "RfcGetFieldDescByIndex": (c_int, [c_void_p, c_uint, POINTER(RFC_FIELD_DESC), E]),
            "RfcSetString": (c_int, [c_void_p, c_void_p, c_void_p, c_uint, E]),
            "RfcGetStringLength": (c_int, [c_void_p, c_void_p, POINTER(c_uint), E]),
            "RfcGetString": (c_int, [c_void_p, c_void_p, c_void_p, c_uint, POINTER(c_uint), E]),
            "RfcGetStructure": (c_int, [c_void_p, c_void_p, POINTER(c_void_p), E]),
            "RfcGetTable": (c_int, [c_void_p, c_void_p, POINTER(c_void_p), E]),
            "RfcGetRowCount": (c_int, [c_void_p, POINTER(c_uint), E]),
            "RfcMoveTo": (c_int, [c_void_p, c_uint, E]),
            "RfcGetCurrentRow": (c_void_p, [c_void_p, E]),
            "RfcAppendNewRow": (c_void_p, [c_void_p, E]),
        }
        for name, (res, args) in sig.items():
            fn = getattr(lib, name)
            fn.restype, fn.argtypes = res, args
            setattr(self, name, fn)
        self.lib = lib

    @classmethod
    def get(cls) -> "_Sdk":
        if cls._instance is None:
            cls._instance = _Sdk()
        return cls._instance

    def version(self) -> str:
        a, b, c = c_uint(), c_uint(), c_uint()
        self.RfcGetVersion(byref(a), byref(b), byref(c))  # type: ignore[attr-defined]
        return f"{a.value}.{b.value}.{c.value}"


def _raise(err: RFC_ERROR_INFO, context: str) -> None:
    code = RFC_RC.get(err.code, str(err.code))
    key, msg = _str(err.key), _str(err.message)
    text = f"{context}: {code} {key} {msg}".strip()
    if err.code == 1:
        raise RfcCommunicationError(text, code=code, key=key)
    if err.code == 2 or "logon" in msg.lower() or "password" in msg.lower():
        raise RfcLogonError(text + " — revise usuario, contraseña, mandante, bloqueo o contraseña vencida/inicial "
                            "(ver SM21/SM20 en SAP para el motivo exacto)", code=code, key=key)
    if key in ("FU_NOT_FOUND",) or err.code == 17:
        raise RfcFunctionNotFound(text, code=code, key=key)
    if key in ("NOT_AUTHORIZED", "NO_AUTHORITY") or "authoriz" in msg.lower():
        raise RfcAuthorizationError(text, code=code, key=key)
    if err.code == 3:
        raise RfcAbapRuntimeError(text, code=code, key=key)
    if err.code in (4, 5):
        raise RfcAbapException(text, code=code, key=key)
    raise RfcError(text, code=code, key=key)


class NwRfcConnector(RfcConnector):
    backend_name = "nwrfc"

    def __init__(self, params: ConnectionParams, limits: LoadLimits | None = None):
        super().__init__(params, limits)
        self.sdk = _Sdk.get()
        self._handle: int | None = None

    # --- conexión ----------------------------------------------------------------------
    def open(self) -> None:
        if self._handle:
            return
        items = list(self.params.to_rfc_dict().items())
        keep: list[ctypes.Array] = []
        arr = (RFC_CONNECTION_PARAMETER * len(items))()
        for i, (k, v) in enumerate(items):
            kn, vv = _uc(k), _uc(str(v))
            keep += [kn, vv]
            arr[i].name = ctypes.cast(kn, c_void_p)
            arr[i].value = ctypes.cast(vv, c_void_p)
        err = RFC_ERROR_INFO()
        h = self.sdk.RfcOpenConnection(arr, len(items), byref(err))  # type: ignore[attr-defined]
        if not h:
            _raise(err, "Apertura de conexión")
        self._handle = h

    def close(self) -> None:
        if self._handle:
            err = RFC_ERROR_INFO()
            self.sdk.RfcCloseConnection(self._handle, byref(err))  # type: ignore[attr-defined]
            self._handle = None

    def sdk_version(self) -> str:
        return self.sdk.version()

    def function_exists(self, function: str) -> bool:
        self.open()
        err = RFC_ERROR_INFO()
        desc = self.sdk.RfcGetFunctionDesc(self._handle, _uc(function), byref(err))  # type: ignore[attr-defined]
        if desc:
            return True
        try:
            _raise(err, f"Metadatos de {function}")
        except (RfcFunctionNotFound, RfcAbapException):
            return False
        return False

    # --- llamada genérica --------------------------------------------------------------
    def _call(self, function: str, **kwargs: Any) -> dict[str, Any]:
        self.open()
        s = self.sdk
        err = RFC_ERROR_INFO()
        desc = s.RfcGetFunctionDesc(self._handle, _uc(function), byref(err))  # type: ignore[attr-defined]
        if not desc:
            _raise(err, f"Metadatos de {function}")
        func = s.RfcCreateFunction(desc, byref(err))  # type: ignore[attr-defined]
        if not func:
            _raise(err, f"Creación de {function}")
        try:
            for name, value in kwargs.items():
                self._set_param(desc, func, name, value)
            rc = s.RfcInvoke(self._handle, func, byref(err))  # type: ignore[attr-defined]
            if rc != 0:
                if rc in (1, 3, 6, 13):  # comunicación, dump, cerrada, handle inválido
                    self._handle = None  # SAP cerró la sesión: la próxima llamada reconecta
                _raise(err, function)
            return self._read_params(desc, func, set(kwargs))
        finally:
            s.RfcDestroyFunction(func, byref(RFC_ERROR_INFO()))  # type: ignore[attr-defined]

    def _check(self, rc: int, err: RFC_ERROR_INFO, ctx: str) -> None:
        if rc != 0:
            _raise(err, ctx)

    def _set_param(self, desc: int, func: int, name: str, value: Any) -> None:
        s, err, pd = self.sdk, RFC_ERROR_INFO(), RFC_PARAMETER_DESC()
        self._check(s.RfcGetParameterDescByName(desc, _uc(name), byref(pd), byref(err)), err,  # type: ignore[attr-defined]
                    f"Parámetro {name}")
        if pd.type == RFCTYPE_TABLE:
            th = c_void_p()
            self._check(s.RfcGetTable(func, _uc(name), byref(th), byref(err)), err, name)  # type: ignore[attr-defined]
            for row in value:
                rh = s.RfcAppendNewRow(th, byref(err))  # type: ignore[attr-defined]
                if not rh:
                    _raise(err, f"Fila de {name}")
                for fname, fval in row.items():
                    self._set_string(rh, fname, fval)
        elif pd.type == RFCTYPE_STRUCTURE:
            sh = c_void_p()
            self._check(s.RfcGetStructure(func, _uc(name), byref(sh), byref(err)), err, name)  # type: ignore[attr-defined]
            for fname, fval in value.items():
                self._set_string(sh, fname, fval)
        else:
            self._set_string(func, name, value)

    def _set_string(self, container: int, name: str, value: Any) -> None:
        err = RFC_ERROR_INFO()
        text = "" if value is None else str(value)
        buf = _uc(text)
        rc = self.sdk.RfcSetString(container, _uc(name), buf, len(text.encode("utf-16-le")) // 2,  # type: ignore[attr-defined]
                                   byref(err))
        self._check(rc, err, f"Asignación {name}")

    def _get_string(self, container: int, name: str, rfctype: int, nuc_length: int) -> str:
        """Lee cualquier campo escalar como texto.

        RfcGetStringLength solo admite STRING/XSTRING; para el resto de tipos el
        tamaño se deduce de la longitud del campo y, si no alcanza, se reintenta con
        la longitud que informa el SDK (RFC_BUFFER_TOO_SMALL).
        """
        s, err = self.sdk, RFC_ERROR_INFO()
        uname = _uc(name)
        if rfctype in (RFCTYPE_STRING, RFCTYPE_XSTRING):
            ln = c_uint()
            self._check(s.RfcGetStringLength(container, uname, byref(ln), byref(err)), err, name)  # type: ignore[attr-defined]
            size = ln.value + 1
        else:
            # CHAR/NUM/DATE/TIME: nucLength caracteres; BCD/FLOAT/INT/BYTE: margen holgado
            size = max(int(nuc_length) * 2 + 64, 128)
        for _ in range(2):
            buf = (SAP_UC * size)()
            out = c_uint()
            err = RFC_ERROR_INFO()
            rc = s.RfcGetString(container, uname, buf, size, byref(out), byref(err))  # type: ignore[attr-defined]
            if rc == 0:
                return _str(buf, out.value)
            if rc == RFC_BUFFER_TOO_SMALL and out.value + 1 > size:
                size = out.value + 1
                continue
            _raise(err, f"Lectura de {name}")
        _raise(err, f"Lectura de {name}")
        return ""

    def _fields(self, type_handle: int) -> list[RFC_FIELD_DESC]:
        s, err, n = self.sdk, RFC_ERROR_INFO(), c_uint()
        self._check(s.RfcGetFieldCount(type_handle, byref(n), byref(err)), err, "Campos")  # type: ignore[attr-defined]
        result = []
        for i in range(n.value):
            fd = RFC_FIELD_DESC()
            self._check(s.RfcGetFieldDescByIndex(type_handle, i, byref(fd), byref(err)), err, "Campo")  # type: ignore[attr-defined]
            result.append(fd)
        return result

    def _read_struct(self, handle: int, type_handle: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        s, err = self.sdk, RFC_ERROR_INFO()
        for fd in self._fields(type_handle):
            fname = _str(fd.name)
            if fname.upper() in SENSITIVE_OUTPUT_FIELDS:
                continue  # nunca se lee del contenedor
            if fd.type == RFCTYPE_STRUCTURE:
                sh = c_void_p()
                self._check(s.RfcGetStructure(handle, _uc(fname), byref(sh), byref(err)), err, fname)  # type: ignore[attr-defined]
                out[fname] = self._read_struct(sh.value, fd.typeDescHandle)
            elif fd.type == RFCTYPE_TABLE:
                th = c_void_p()
                self._check(s.RfcGetTable(handle, _uc(fname), byref(th), byref(err)), err, fname)  # type: ignore[attr-defined]
                out[fname] = self._read_table(th.value, fd.typeDescHandle)
            else:
                out[fname] = self._get_string(handle, fname, fd.type, fd.nucLength)
        return out

    def _read_table(self, th: int, type_handle: int) -> list[dict[str, Any]]:
        s, err, n = self.sdk, RFC_ERROR_INFO(), c_uint()
        self._check(s.RfcGetRowCount(th, byref(n), byref(err)), err, "Filas")  # type: ignore[attr-defined]
        fields = self._fields(type_handle)
        rows = []
        for i in range(n.value):
            self._check(s.RfcMoveTo(th, i, byref(err)), err, "Posición")  # type: ignore[attr-defined]
            rh = s.RfcGetCurrentRow(th, byref(err))  # type: ignore[attr-defined]
            row: dict[str, Any] = {}
            for fd in fields:
                fname = _str(fd.name)
                if fname.upper() in SENSITIVE_OUTPUT_FIELDS or fd.type in (RFCTYPE_TABLE, RFCTYPE_STRUCTURE):
                    continue
                row[fname] = self._get_string(rh, fname, fd.type, fd.nucLength)
            rows.append(row)
        return rows

    def _read_params(self, desc: int, func: int, imported: set[str]) -> dict[str, Any]:
        s, err, n = self.sdk, RFC_ERROR_INFO(), c_uint()
        self._check(s.RfcGetParameterCount(desc, byref(n), byref(err)), err, "Parámetros")  # type: ignore[attr-defined]
        out: dict[str, Any] = {}
        for i in range(n.value):
            pd = RFC_PARAMETER_DESC()
            self._check(s.RfcGetParameterDescByIndex(desc, i, byref(pd), byref(err)), err, "Parámetro")  # type: ignore[attr-defined]
            name = _str(pd.name)
            if pd.direction == RFC_IMPORT:
                continue
            if name.upper() in SENSITIVE_OUTPUT_FIELDS:
                continue
            if pd.type == RFCTYPE_TABLE:
                th = c_void_p()
                self._check(s.RfcGetTable(func, _uc(name), byref(th), byref(err)), err, name)  # type: ignore[attr-defined]
                out[name] = self._read_table(th.value, pd.typeDescHandle)
            elif pd.type == RFCTYPE_STRUCTURE:
                sh = c_void_p()
                self._check(s.RfcGetStructure(func, _uc(name), byref(sh), byref(err)), err, name)  # type: ignore[attr-defined]
                out[name] = self._read_struct(sh.value, pd.typeDescHandle)
            else:
                out[name] = self._get_string(func, name, pd.type, pd.nucLength)
        return out
