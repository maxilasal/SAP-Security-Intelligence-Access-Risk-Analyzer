from sapsec.domain.models import Severity
from sapsec.engine.simulator import (APROBACION, NO_RECOMENDADO, REVISION, Scenario, ValueOverride, simulate)


def test_new_conflict_is_not_recommended_with_evidence(ctx, data):
    """Ejemplo del requerimiento: USUARIO_TEST (proveedores) + Z_FI_PAGOS."""
    r = simulate(ctx, data, "USUARIO_TEST", Scenario(add_roles=["Z_FI_PAGOS"]))
    assert r.recommendation == NO_RECOMENDADO
    assert r.before.risk.inherent_level.rank < r.after.risk.inherent_level.rank
    assert r.after.risk.inherent_level is Severity.CRITICO
    new = {h.risk_id: h for h in r.new_sod}
    h = new["SOD-FI-001"]
    by_fn = {m.function_id: m.roles for m in h.functions}
    assert by_fn["FN_PROV_MANT"] == ["Z_FI_PROVEEDORES"] and by_fn["FN_PAGOS"] == ["Z_FI_PAGOS"]
    assert "Z_FI_PROVEEDORES" in h.explanation and "Z_FI_PAGOS" in h.explanation
    objs = {e.object for m in h.functions for e in m.evidence}
    assert {"B_BUPA_RLT", "F_REGU_BUK", "S_TCODE"} <= objs
    assert any(p.object == "F_REGU_BUK" for p in r.new_permissions)
    assert r.measures


def test_preexisting_conflict_is_not_reported_as_new(ctx, data):
    r = simulate(ctx, data, "USUARIO_BLOQ", Scenario(add_roles=["Z_MM_CONSULTA"]))
    assert "SOD-FI-001" in {h.risk_id for h in r.preexisting_sod}
    assert not r.new_sod
    assert r.recommendation == APROBACION


def test_simulation_without_new_risks(ctx, data):
    r = simulate(ctx, data, "INACTIVO1", Scenario(add_roles=["Z_FI_PAGOS_CONSULTA"]))
    assert r.recommendation == APROBACION
    assert "No se detectaron riesgos relevantes" in r.reasons[0]


def test_remove_role_resolves_conflict(ctx, data):
    r = simulate(ctx, data, "SEG_ADMIN", Scenario(remove_roles=["Z_SEC_USUARIOS"]))
    assert "SOD-SEG-001" in {h.risk_id for h in r.resolved_sod}
    assert not r.new_sod
    assert r.after.risk.inherent_score < r.before.risk.inherent_score


def test_replace_role(ctx, data):
    r = simulate(ctx, data, "USUARIO_BLOQ", Scenario(replace=[("Z_FI_PAGOS", "Z_FI_PAGOS_CONSULTA")]))
    assert "SOD-FI-001" in {h.risk_id for h in r.resolved_sod}
    assert r.scenario.add_roles == ["Z_FI_PAGOS_CONSULTA"] and r.scenario.remove_roles == ["Z_FI_PAGOS"]


def test_multiple_roles_at_once(ctx, data):
    r = simulate(ctx, data, "INACTIVO1", Scenario(add_roles=["Z_MM_PEDIDOS", "Z_MM_LIBERADOR"]))
    assert "SOD-MM-001" in {h.risk_id for h in r.new_sod}
    assert r.recommendation == REVISION  # riesgo alto: requiere revisión


def test_composite_role_assignment(ctx, data):
    r = simulate(ctx, data, "INACTIVO1", Scenario(add_roles=["Z_MM_COMPRADOR_C"]))
    assert "SOD-MM-001" in {h.risk_id for h in r.new_sod}


def test_hypothetical_value_change(ctx, data):
    # Restringir el rol de pagos a BUKRS 9999 no elimina el conflicto FI-001 (la regla no compara org.)
    # pero sí cambia los valores evaluados y baja la certeza a "definido en rol".
    sc = Scenario(add_roles=["Z_FI_PAGOS"], overrides=[ValueOverride("Z_FI_PAGOS", "F_REGU_BUK", "FBTCH", ["03"])])
    r = simulate(ctx, data, "USUARIO_TEST", sc)
    p = [x for x in r.new_permissions if x.object == "F_REGU_BUK"][0]
    assert "FBTCH=03" in p.values and p.certainty == "definido_en_rol"


def test_role_without_generated_profile_requires_review(ctx, data):
    r = simulate(ctx, data, "INACTIVO1", Scenario(add_roles=["Z_FI_NO_GENERADO"]))
    assert r.recommendation == REVISION
    assert any(i.code == "ROL_PERFIL_INCONSISTENTE" for i in r.issues)


def test_nonexistent_role(ctx, data):
    r = simulate(ctx, data, "INACTIVO1", Scenario(add_roles=["Z_NO_EXISTE"]))
    assert r.recommendation == REVISION
    assert any(i.code == "ROL_INEXISTENTE" for i in r.issues)


def test_incomplete_or_stale_data_prevents_approval(ctx, data):
    r = simulate(ctx, data, "INACTIVO1", Scenario(add_roles=["Z_FI_PAGOS_CONSULTA"]),
                 snapshot_meta={"status": "incompleto", "stale": True, "age_days": 30})
    assert r.recommendation == REVISION
    assert any("incompleto" in x for x in r.reasons) and any("30 días" in x for x in r.reasons)


def test_alternatives_are_offered_with_caveats(ctx, data):
    r = simulate(ctx, data, "USUARIO_TEST", Scenario(add_roles=["Z_FI_PAGOS"]))
    alt = {a.role: a for a in r.alternatives}
    assert "Z_FI_PAGOS_CONSULTA" in alt
    a = alt["Z_FI_PAGOS_CONSULTA"]
    assert a.new_sod == 0 and a.confidence in ("baja", "media") and "F-53" in a.missing_tcodes
    assert r.alternatives[0].new_critical + r.alternatives[0].new_sod == 0


def test_simulation_never_mutates_snapshot(ctx, data):
    before = (len(data.user_profiles["USUARIO_TEST"]), len(data.user_roles_raw["USUARIO_TEST"]))
    simulate(ctx, data, "USUARIO_TEST", Scenario(add_roles=["Z_FI_PAGOS"], remove_roles=["Z_MM_CONSULTA"]))
    assert (len(data.user_profiles["USUARIO_TEST"]), len(data.user_roles_raw["USUARIO_TEST"])) == before
