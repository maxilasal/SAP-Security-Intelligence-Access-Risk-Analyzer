from conftest import AS_OF
from sapsec.engine.effective import compute_effective
from sapsec.engine.incompat import forbidden_for_user, incompatible_with_role, role_function_map
from sapsec.engine.rule_check import check_rules


def test_role_function_map(rules, data):
    fmap = role_function_map(rules, data, AS_OF)
    assert "FN_PO_CREAR" in fmap["Z_MM_PEDIDOS"]
    assert "FN_PO_LIBERAR" in fmap["Z_MM_LIBERADOR"]
    assert "FN_PAGOS" in fmap["Z_FI_PAGOS"]
    assert "Z_MM_CONSULTA" not in fmap  # solo visualización


def test_roles_that_must_not_be_combined(rules, data):
    inc, intra = incompatible_with_role(rules, data, "Z_MM_PEDIDOS", AS_OF)
    by_risk = {x.risk_id: x for x in inc}
    assert {"Z_MM_LIBERADOR", "Z_MM_COMPRAS_APROBADOR"} <= set(by_risk["SOD-MM-001"].roles)
    assert intra == []
    _, intra2 = incompatible_with_role(rules, data, "Z_MM_ALMACEN", AS_OF)
    assert "SOD-MM-004" in intra2


def test_roles_a_user_should_not_receive(rules, data):
    """Ejemplo pedido: quien crea pedidos no debería recibir un rol para aprobarlos."""
    eff = compute_effective(data, "USUARIO_TEST", AS_OF)  # mantiene proveedores
    forb = {x.risk_id: x for x in forbidden_for_user(rules, data, eff, AS_OF)}
    assert "Z_FI_PAGOS" in forb["SOD-FI-001"].roles
    assert "Z_MM_PEDIDOS" in forb["SOD-MM-003"].roles
    eff2 = compute_effective(data, "ALMACEN1", AS_OF)
    forb2 = {x.risk_id for x in forbidden_for_user(rules, data, eff2, AS_OF)}
    assert "SOD-MM-004" not in forb2  # ya existente: es un hallazgo, no una advertencia


def test_rules_are_checked_against_the_system(rules, data):
    checks = {(c.function_id, c.action_id): c for c in check_rules(rules, data)}
    assert checks[("FN_PO_CREAR", "ME21N")].status == "confirmada_su24"
    assert checks[("FN_PO_LIBERAR", "ME29N")].status == "confirmada_su24"
    pagos = checks[("FN_PAGOS", "F110")]
    assert pagos.status == "sin_confirmar" and "F110→F_REGU_BUK" in pagos.su24_unconfirmed
    assert checks[("FN_PEDIDO_VENTA", "VA01")].status == "referencia_inexistente"  # no existe en el fixture
    assert checks[("FN_PROV_MANT", "OBJETOS")].status == "solo_objetos"
