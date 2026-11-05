import pytest

from conftest import fixture_data
from sapsec.connectors.base import ConnectionParams, LoadLimits, RfcForbiddenCall
from sapsec.connectors.fixture_connector import FixtureConnector
from sapsec.connectors.table_reader import OPTION_LINE, TableAccessDenied, TableReader, build_where


def _conn(max_rows=1000, batch=3):  # type: ignore[no-untyped-def]
    return FixtureConnector(ConnectionParams(client="100", user="X"),
                            LoadLimits(pause_between_calls_ms=0, max_calls_per_minute=10 ** 6,
                                       max_rows_per_call=max_rows, batch_size_in_list=batch), data=fixture_data())


def test_password_fields_and_unlisted_tables_are_rejected():
    r = TableReader(_conn())
    with pytest.raises(TableAccessDenied):
        r.read("USR02", ["BNAME", "BCODE"])
    with pytest.raises(TableAccessDenied):
        r.read("USR02", ["PWDSALTEDHASH"])
    with pytest.raises(TableAccessDenied):
        r.read("RFCDES", ["RFCDEST"])
    with pytest.raises(TableAccessDenied):
        r.read("BKPF", ["BELNR"])


def test_write_functions_are_blocked():
    c = _conn()
    for fn in ("BAPI_USER_CHANGE", "BAPI_USER_ACTGROUPS_ASSIGN", "PRGN_ROLE_CREATE", "BAPI_TRANSACTION_COMMIT"):
        with pytest.raises(RfcForbiddenCall):
            c.call(fn)


def test_bapi_hashes_are_scrubbed():
    c = _conn()
    res = c.call("BAPI_USER_GET_DETAIL", USERNAME="USUARIO_TEST")
    assert "BCODE" not in res["LOGONDATA"] and "PWDSALTEDHASH" not in res["LOGONDATA"]
    assert res["LOGONDATA"]["USTYP"] == "A"


def test_where_lines_respect_72_chars():
    opts = build_where(["AKTPS = 'A'"], "AGR_NAME", [f"Z_ROLE_MUY_LARGO_{i:04d}" for i in range(40)])
    assert all(len(o["TEXT"]) <= OPTION_LINE for o in opts)
    text = " ".join(o["TEXT"] for o in opts)
    assert text.startswith("AKTPS = 'A' AND AGR_NAME IN (") and "'Z_ROLE_MUY_LARGO_0039'" in text


def test_truncation_is_detected_and_split():
    full = TableReader(_conn(max_rows=10000)).read("UST12", ["OBJCT", "AUTH", "AKTPS", "FIELD", "VON", "BIS"],
                                                   ["AKTPS = 'A'"])
    small = TableReader(_conn(max_rows=7))
    objs = sorted({r["OBJCT"] for r in full})
    rows = [r for chunk in small.read_partitioned("UST12", ["OBJCT", "AUTH", "AKTPS", "FIELD", "VON", "BIS"],
                                                  "OBJCT", objs, ["AKTPS = 'A'"]) for r in chunk]
    key = lambda r: (r["OBJCT"], r["AUTH"], r["FIELD"], r["VON"])  # noqa: E731
    assert sorted(map(key, rows)) == sorted(map(key, full))
    assert small.truncation_events > 0


def test_fixed_width_parsing_keeps_values():
    rows = TableReader(_conn()).read("AGR_TEXTS", ["AGR_NAME", "SPRAS", "LINE", "TEXT"], ["LINE = '00000'"])
    t = {r["AGR_NAME"]: r["TEXT"] for r in rows}
    assert t["Z_FI_PAGOS"] == "FI: ejecución de pagos"


def test_nwrfc_backend_reports_missing_sdk_clearly(monkeypatch):
    from sapsec.connectors import create_connector
    from sapsec.connectors.base import RfcError
    from sapsec.connectors import nwrfc_connector
    monkeypatch.setenv("SAPNWRFC_HOME", "/ruta/inexistente")
    nwrfc_connector._Sdk._instance = None
    with pytest.raises(RfcError, match="SAPNWRFC_HOME"):
        create_connector("nwrfc", ConnectionParams(client="100", user="X"))


def test_nwrfc_structures_match_sdk_layout():
    """Tamaños de estructuras C según sapnwrfc.h (SAP_UC = 2 bytes)."""
    import ctypes
    from sapsec.connectors.nwrfc_connector import RFC_ERROR_INFO
    # code+group (2 int) + 128+512+21+2+4+51*4 SAP_UC, con relleno hasta alineación de int (4)
    raw = 8 + 2 * (128 + 512 + 21 + 2 + 4 + 51 * 4)
    assert ctypes.sizeof(RFC_ERROR_INFO) == (raw + 3) // 4 * 4
