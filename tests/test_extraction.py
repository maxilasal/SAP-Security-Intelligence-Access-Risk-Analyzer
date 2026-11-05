from sqlalchemy import inspect, select, text

from conftest import extract, fixture_data
from sapsec.storage.orm import SAP_TABLES


def test_complete_snapshot(extracted):
    _, _, snap, _ = extracted
    assert snap.status == "completo", snap.issues
    assert snap.is_test_data
    assert snap.stats["ust12"]["status"] == "ok" and snap.stats["ust12"]["calls"] > 1  # particionado
    assert snap.stats["_validacion"]["extra"]["diferencias"] == 0


def test_password_hashes_never_stored(extracted):
    engine, _, _, _ = extracted
    cols = {c["name"] for c in inspect(engine).get_columns("sap_usr02")}
    assert not cols & {"bcode", "passcode", "pwdsaltedhash"}
    with engine.connect() as c:
        dump = " ".join(str(r) for r in c.execute(select(SAP_TABLES["usr02"])))
    assert "DEADBEEF" not in dump and "FICTICIO" not in dump


def test_missing_table_authorization_marks_incomplete():
    d = fixture_data()
    d["unauthorized_tables"] = ["UST12"]
    _, _, snap, _ = extract(d)
    assert snap.status == "incompleto"
    assert snap.stats["ust12"]["status"] == "sin_autorizacion"
    assert "S_TABU_NAM" in snap.stats["ust12"]["message"]


def test_usr02_without_authorization_falls_back_to_user_list():
    d = fixture_data()
    d["unauthorized_tables"] = ["USR02"]
    engine, _, snap, _ = extract(d)
    assert snap.stats["usr02"]["status"] == "sin_autorizacion"
    with engine.connect() as c:
        n = c.execute(text("select count(*) from sap_usr02")).scalar()
    assert n == len(d["tables"]["USR02"])  # nombres desde BAPI_USER_GETLIST


def test_bapi_mode_for_user_master():
    _, _, snap, _ = extract(fixture_data(), logon_source="bapi")
    assert snap.stats["usr02"]["status"] == "ok"
    assert any(i["code"] == "SIN_ULTIMO_ACCESO" for i in snap.issues)


def test_system_identity_mismatch_aborts():
    _, _, snap, _ = extract(fixture_data(), sid="PRD")
    assert snap.status == "error"
    assert "DMO" in snap.issues[0]["message"]


def test_validation_detects_inconsistency_between_tables_and_bapi():
    d = fixture_data()
    # Simula una asignación que la tabla no devuelve (lectura incompleta)
    d["tables"]["AGR_USERS"] = [r for r in d["tables"]["AGR_USERS"]
                                if not (r["UNAME"] == "SEG_ADMIN" and r["AGR_NAME"] == "Z_SEC_ROLES")]
    d["tables"]["UST04"].append({"BNAME": "ZZ_NOEXISTE", "PROFILE": "X"})

    from sapsec.connectors import fixture_connector as fc
    orig = fc.FixtureConnector._user_detail

    def patched(self, username):  # type: ignore[no-untyped-def]
        res = orig(self, username)
        if username == "SEG_ADMIN":
            res["ACTIVITYGROUPS"].append({"AGR_NAME": "Z_SEC_ROLES", "FROM_DAT": "", "TO_DAT": ""})
        return res
    fc.FixtureConnector._user_detail = patched
    try:
        from sapsec.config import get_settings
        get_settings().analysis.validation_sample_size = 100
        _, _, snap, _ = extract(d)
    finally:
        fc.FixtureConnector._user_detail = orig
    assert snap.status == "incompleto"
    assert snap.stats["_validacion"]["extra"]["diferencias"] >= 1


def test_sap_dump_in_one_table_does_not_abort_snapshot():
    d = fixture_data()
    d["dump_tables"] = ["TSTCA", "AGR_1252"]
    _, _, snap, _ = extract(d)
    assert snap.status == "incompleto"            # AGR_1252 es obligatoria
    assert snap.stats["agr_1252"]["status"] == "error"
    assert "ST22" in snap.stats["agr_1252"]["message"]
    assert snap.stats["tstca"]["status"] == "error"
    assert snap.stats["ust12"]["status"] == "ok"  # el resto siguió


def test_usobhash_skipped_on_old_basis_release():
    d = fixture_data()
    d["system"]["RFCSAPRL"] = "731"
    d["dump_tables"] = ["USOBHASH"]
    _, _, snap, _ = extract(d)
    assert snap.stats["usobhash"]["status"] == "omitido"
    assert snap.status == "completo"
