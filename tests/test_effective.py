from conftest import AS_OF
from sapsec.domain.models import SourceKind
from sapsec.engine.effective import compute_effective, role_consistency, tcode_executable


def test_composite_role_children_provide_authorizations(data):
    eff = compute_effective(data, "COMPRADOR1", AS_OF)
    assert {"Z_MM_PEDIDOS", "Z_MM_LIBERADOR"} <= set(eff.valid_roles())
    objs = {k[0] for k in eff.instances}
    assert {"M_BEST_EKO", "M_EINK_FRG"} <= objs
    via = {s.via_composite for e in eff.instances.values() for s in e.sources}
    assert "Z_MM_COMPRADOR_C" in via


def test_direct_profile_sap_all(data):
    eff = compute_effective(data, "ADMIN_BASIS", AS_OF)
    assert "SAP_ALL" in eff._direct
    assert all(s.kind is SourceKind.PERFIL_DIRECTO for e in eff.instances.values() for s in e.sources)
    assert eff.by_object("S_TCODE")[0].instance.field_is_full_wildcard("TCD")


def test_expired_assignment_with_profile_is_residual(data):
    eff = compute_effective(data, "USUARIO_VENC", AS_OF)
    codes = {i.code for i in eff.issues}
    assert {"PERFIL_RESIDUAL", "ROL_VENCIDO", "ROL_FUTURO", "ROL_SIN_PERFIL"} <= codes
    # El perfil residual sigue aportando autorizaciones: no se descartan
    kinds = {s.kind for e in eff.instances.values() for s in e.sources}
    assert SourceKind.PERFIL_RESIDUAL in kinds
    assert "Z_FI_PAGOS" not in eff.valid_roles()


def test_locked_user_keeps_authorizations(data):
    eff = compute_effective(data, "USUARIO_BLOQ", AS_OF)
    assert eff.user.is_locked
    assert eff.by_object("F_REGU_BUK")


def test_role_profile_consistency(data):
    assert role_consistency(data, "Z_FI_PAGOS").consistent
    nog = role_consistency(data, "Z_FI_NO_GENERADO")
    assert not nog.generated and not nog.consistent
    stale = role_consistency(data, "Z_FI_DESACTUALIZADO")
    assert stale.generated and not stale.consistent
    assert any("F_LFA1_APP" in x and "|03|" in x for x in stale.only_in_role)
    assert any("|02|" in x for x in stale.only_in_profile)
    parent = role_consistency(data, "Z_MM_PEDIDOS_PADRE")
    assert parent.unresolved_org  # $EKORG sin valor


def test_derived_and_parent_role_types(data):
    assert data.role_type("Z_MM_DERIVADO_1000") == "derivado"
    assert data.role_type("Z_MM_PEDIDOS_PADRE") == "padre"
    assert data.role_type("Z_MM_COMPRADOR_C") == "compuesto"


def test_tcode_start_authorization_check(data):
    eff = compute_effective(data, "REPORTE1", AS_OF)
    ok, _, notes = tcode_executable(eff, data, "ZFI_REP_PAGOS")
    assert not ok and "TSTCA" in notes[0]  # tiene S_TCODE pero falla el chequeo de inicio
    eff2 = compute_effective(data, "USUARIO_TEST", AS_OF)
    assert tcode_executable(eff2, data, "BP")[0]
    assert not tcode_executable(eff2, data, "F110")[0]
