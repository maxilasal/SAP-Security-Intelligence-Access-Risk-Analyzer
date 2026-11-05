from dataclasses import replace

from sapsec.domain.models import Severity
from sapsec.engine.analysis import analyze_role, analyze_user


def ids(a):  # type: ignore[no-untyped-def]
    return {h.rule_id for h in a.critical}, {h.risk_id: h for h in a.sod}


def test_sap_all_and_sap_new(ctx, data):
    crit, _ = ids(analyze_user(ctx, data, "ADMIN_BASIS"))
    assert "CRIT-PRF-001" in crit
    assert "CRIT-EQV-001" not in crit  # tiene SAP_ALL literal: no se duplica como equivalencia
    crit_ddic, _ = ids(analyze_user(ctx, data, "DDIC"))
    assert {"CRIT-PRF-002", "CRIT-STD-001"} <= crit_ddic


def test_sap_all_equivalence_without_literal_profile(ctx, data):
    a = analyze_user(ctx, data, "ADMIN_EQUIV")
    crit, _ = ids(a)
    assert "CRIT-EQV-001" in crit
    h = next(h for h in a.critical if h.rule_id == "CRIT-EQV-001")
    assert h.metrics["ratio"] >= 0.8
    assert h.roles == ["Z_BC_ADMIN_TOTAL"]


def test_environment_specific_rule(ctx, data):
    assert "CRIT-DEV-001" in ids(analyze_user(ctx, data, "DEV_USER"))[0]
    dev_ctx = replace(ctx, environment="DEV")
    assert "CRIT-DEV-001" not in ids(analyze_user(dev_ctx, data, "DEV_USER"))[0]


def test_wildcard_rfc_for_technical_user(ctx, data):
    a = analyze_user(ctx, data, "RFC_TECH")
    assert {"CRIT-RFC-001", "CRIT-FIO-001"} <= ids(a)[0]
    assert a.eff.user.user_type == "B"


def test_inactive_user_rule(ctx, data):
    assert "CRIT-USR-INA-001" in ids(analyze_user(ctx, data, "INACTIVO1"))[0]
    assert "CRIT-USR-INA-001" not in ids(analyze_user(ctx, data, "USUARIO_TEST"))[0]


def test_sod_between_roles_identifies_contributing_roles(ctx, data):
    _, sod = ids(analyze_user(ctx, data, "SEG_ADMIN"))
    h = sod["SOD-SEG-001"]
    assert h.scope == "entre roles"
    by_fn = {m.function_id: m.roles for m in h.functions}
    assert by_fn["FN_ROL_MANT"] == ["Z_SEC_ROLES"] and by_fn["FN_ROL_ASIGNAR"] == ["Z_SEC_USUARIOS"]
    assert "Z_SEC_ROLES" in h.explanation and "Z_SEC_USUARIOS" in h.explanation


def test_sod_intra_role_and_direct_profile(ctx, data):
    _, sod = ids(analyze_user(ctx, data, "ALMACEN1"))
    assert sod["SOD-MM-004"].scope.startswith("intra-rol")
    _, sod2 = ids(analyze_user(ctx, data, "ADMIN_BASIS"))
    assert sod2["SOD-FI-001"].scope == "incluye perfil directo"


def test_apparent_org_restriction_is_not_trusted(ctx, data):
    """CONTADOR1: facturas en BUKRS 1000 (Z_FI_FACTURAS) y pagos en 2000 (Z_FI_PAGOS_2000).
    Pero S_TCODE F-53 + F_BKPF_BUK 01/1000 + F_BKPF_KOA K permiten pagar también en 1000:
    el motor debe detectar el solapamiento real en lugar de confiar en el diseño de los roles."""
    _, sod = ids(analyze_user(ctx, data, "CONTADOR1"))
    h = sod["SOD-FI-002"]
    assert any("se solapan" in o for o in h.org_analysis)
    pagos = next(m for m in h.functions if m.function_id == "FN_PAGOS")
    assert "1000" in pagos.org_values["BUKRS"]


def test_disjoint_org_values_are_flagged_not_hidden(rules):
    from sapsec.engine.sod import FunctionMatch, _org_analysis
    risk = next(r for r in rules.risks if r.id == "SOD-FI-002")
    m1 = FunctionMatch("FN_FACT_PROV", "Facturas", "FB60", [], [], ["R1"], [], {"BUKRS": ["1000"]})
    m2 = FunctionMatch("FN_PAGOS", "Pagos", "MANUAL", [], [], ["R2"], [], {"BUKRS": ["2000"]})
    out = _org_analysis(risk, [m1, m2])
    assert "SIN solapamiento" in out[0] and "NO se descarta" in out[0]
    m3 = FunctionMatch("FN_PAGOS", "Pagos", "MANUAL", [], [], ["R2"], [], {"BUKRS": ["1*"]})
    assert "se solapan" in _org_analysis(risk, [m1, m3])[0]


def test_sod_inside_composite_role(ctx, data):
    ra = analyze_role(ctx, data, "Z_MM_COMPRADOR_C")
    assert {h.risk_id for h in ra.sod} == {"SOD-MM-001"}
    assert ra.quality.score < 100


def test_locked_user_current_vs_potential_risk(ctx, data):
    a = analyze_user(ctx, data, "USUARIO_BLOQ")
    assert a.risk.inherent_level is Severity.CRITICO
    assert a.risk.current_score < a.risk.inherent_score
    assert a.risk.notes and "reactivación" in a.risk.notes[0]


def test_mitigation_reduces_residual_only(ctx, data):
    m_ctx = replace(ctx, mitigations={"SOD-FI-001|USUARIO_BLOQ": ("CM-01", 0.5)})
    a = analyze_user(m_ctx, data, "USUARIO_BLOQ")
    assert a.risk.residual_score == a.risk.inherent_score * 0.5
    assert a.risk.inherent_level is Severity.CRITICO


def test_rules_are_marked_as_examples(rules):
    assert all(r.status.value == "ejemplo" for r in rules.risks)
    assert len(rules.hash) == 64


def test_role_quality_flags(ctx, data):
    q = analyze_role(ctx, data, "Z_SIN_USUARIOS").quality
    failed = {c.id for c in q.criteria if not c.passed}
    assert {"descripcion", "uso"} <= failed
    assert {c.id for c in analyze_role(ctx, data, "Z_FI_NO_GENERADO").quality.criteria if not c.passed} >= {"perfil"}


def test_sap_all_inside_composite_profile_is_detected(rules):
    from datetime import date
    from conftest import extract, fixture_data
    from sapsec.engine.analysis import AnalysisContext, analyze_user
    from sapsec.storage.snapshot_data import SnapshotData, load_snapshot_rows
    d = fixture_data()
    d["tables"]["UST10C"].append({"PROFN": "Z_SUPER", "AKTPS": "A", "SUBPROF": "SAP_ALL"})
    d["tables"]["UST04"].append({"BNAME": "INACTIVO1", "PROFILE": "Z_SUPER"})
    engine, _, snap, _ = extract(d)
    data = SnapshotData(load_snapshot_rows(engine, snap.id), snap.id)
    a = analyze_user(AnalysisContext(rules, "PRD", 1.0, date(2026, 11, 4)), data, "INACTIVO1")
    h = next(h for h in a.critical if h.rule_id == "CRIT-PRF-001")
    assert "dentro del perfil compuesto Z_SUPER" in h.notes[0]
