"""Análisis integral de usuarios y roles (independiente de la interfaz y de la base de datos)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from ..domain.models import Issue, Severity
from ..storage.snapshot_data import SnapshotData
from .critical import RuleHit, evaluate_critical
from .effective import (EffectiveAuthorizations, RoleConsistency, compute_effective, role_as_effective,
                        role_consistency)
from .risk import RiskProfile, RiskScorer
from .rules import RuleSet
from .sod import SodHit, evaluate_sod


@dataclass
class AnalysisContext:
    rules: RuleSet
    environment: str            # DEV | QA | PRD | OTRO
    system_factor: float
    as_of: date
    sap_all_threshold: float = 0.8
    inactivity_days: int = 90
    mitigations: dict[str, tuple[str, float]] = field(default_factory=dict)  # fingerprint → (código, eficacia)

    @property
    def scorer(self) -> RiskScorer:
        return RiskScorer(self.rules.scoring)


@dataclass
class UserAnalysis:
    username: str
    eff: EffectiveAuthorizations
    critical: list[RuleHit]
    sod: list[SodHit]
    risk: RiskProfile
    issues: list[Issue]

    def finding_refs(self) -> set[str]:
        return {h.rule_id for h in self.critical} | {h.risk_id for h in self.sod}


def _findings_for_scoring(critical: list[RuleHit], sod: list[SodHit], subject: str) -> list[dict]:
    out = [{"ref": f"{h.rule_id}|{subject}", "title": h.title, "severity": h.severity.value,
            "certainty": h.certainty.value} for h in critical]
    out += [{"ref": f"{h.risk_id}|{subject}", "title": h.title, "severity": h.severity.value,
             "certainty": "capacidad_potencial"} for h in sod]
    return out


def analyze_effective(ctx: AnalysisContext, data: SnapshotData, eff: EffectiveAuthorizations,
                      subject: str | None = None) -> UserAnalysis:
    crit = evaluate_critical(ctx.rules, data, eff, ctx.environment, ctx.as_of, ctx.sap_all_threshold,
                             ctx.inactivity_days)
    sod = evaluate_sod(ctx.rules, data, eff, ctx.environment, subject)
    risk = ctx.scorer.score(_findings_for_scoring(crit, sod, eff.username), eff.user, ctx.system_factor,
                            ctx.as_of, ctx.mitigations)
    return UserAnalysis(eff.username, eff, crit, sod, risk, list(eff.issues))


def analyze_user(ctx: AnalysisContext, data: SnapshotData, username: str) -> UserAnalysis:
    return analyze_effective(ctx, data, compute_effective(data, username, ctx.as_of))


@dataclass
class RoleAnalysis:
    role: str
    role_type: str
    description: str
    eff: EffectiveAuthorizations
    consistency: RoleConsistency | None
    critical: list[RuleHit]
    sod: list[SodHit]
    users: list[dict]
    related: dict[str, list[str]]
    tcodes: list[str]
    menu: list[dict]
    org_levels: list[dict]
    generic: list[dict]
    quality: "RoleQuality"
    issues: list[Issue]


@dataclass
class QualityCriterion:
    id: str
    label: str
    passed: bool
    weight: int
    detail: str


@dataclass
class RoleQuality:
    score: int
    criteria: list[QualityCriterion]

    @property
    def label(self) -> str:
        return "Buena" if self.score >= 80 else "Mejorable" if self.score >= 50 else "Deficiente"


def role_quality(data: SnapshotData, role: str, eff: EffectiveAuthorizations, crit: list[RuleHit],
                 sod: list[SodHit], cons: RoleConsistency | None, generic: list[dict]) -> RoleQuality:
    """Indicador transparente: 100 − Σ pesos de criterios incumplidos (pesos documentados)."""
    admin_objs = {"S_USER_GRP", "S_USER_AGR", "S_USER_PRO", "S_USER_AUT", "S_DEVELOP", "S_TABU_DIS",
                  "S_TABU_NAM", "S_ADMI_FCD", "S_CTS_ADMI", "S_TRANSPRT", "S_RFCACL"}
    objs = {k[0] for k in eff.instances}
    # Objetos de aplicación (F_, M_, V_, C_, B_, P_...) frente a objetos de Basis (S_*)
    functional = [o for o in objs if not o.startswith("S_")]
    has_admin = bool(objs & admin_objs)
    users = data.role_users_raw.get(role, [])
    c = [
        QualityCriterion("descripcion", "Tiene descripción", bool(data.role_text.get(role)), 5,
                         data.role_text.get(role) or "Sin texto en AGR_TEXTS"),
        QualityCriterion("perfil", "Perfil generado y consistente con PFCG",
                         data.is_composite(role) or bool(cons and cons.consistent), 20,
                         "Rol compuesto (sin perfil propio)" if data.is_composite(role) else
                         ("Consistente" if cons and cons.consistent else "Perfil ausente o desactualizado")),
        QualityCriterion("criticos", "Sin autorizaciones críticas", not any(h.severity.rank >= 3 for h in crit), 25,
                         ", ".join(h.rule_id for h in crit) or "—"),
        QualityCriterion("sod", "Sin conflictos SoD internos", not sod, 25, ", ".join(h.risk_id for h in sod) or "—"),
        QualityCriterion("genericos", "Sin comodines en campos organizativos o S_TCODE",
                         not generic, 10, f"{len(generic)} campos genéricos" if generic else "—"),
        QualityCriterion("mezcla", "No mezcla administración técnica y funciones de negocio",
                         not (has_admin and functional), 10,
                         "Mezcla objetos administrativos y funcionales" if has_admin and functional else "—"),
        QualityCriterion("uso", "Tiene usuarios asignados", bool(users) or data.role_type(role) == "padre", 5,
                         f"{len(users)} asignaciones"),
    ]
    score = 100 - sum(x.weight for x in c if not x.passed)
    return RoleQuality(max(score, 0), c)


ORG_FIELDS = {"BUKRS", "WERKS", "EKORG", "VKORG", "GSBER", "KOKRS", "BRGRU", "LGORT", "VTWEG", "SPART",
              "EKGRP", "PERSA", "BEGRU", "KOART"}


def generic_values(eff: EffectiveAuthorizations) -> list[dict]:
    out = []
    for e in eff.instances.values():
        for f, vals in e.instance.fields.items():
            if f in ORG_FIELDS | {"TCD", "ACTVT"} and any(v.is_full_wildcard for v in vals):
                out.append({"object": e.instance.object, "auth": e.instance.auth, "field": f,
                            "values": ", ".join(str(v) for v in vals), "roles": e.roles})
    return out


def analyze_role(ctx: AnalysisContext, data: SnapshotData, role: str) -> RoleAnalysis:
    eff = role_as_effective(data, role, ctx.as_of)
    crit = [h for h in evaluate_critical(ctx.rules, data, eff, ctx.environment, ctx.as_of,
                                         ctx.sap_all_threshold, ctx.inactivity_days) if h.kind == "critica"]
    crit = [h for h in crit if ctx.rules.critical_by_id(h.rule_id).type != "user_attributes"]  # type: ignore[union-attr]
    sod = evaluate_sod(ctx.rules, data, eff, ctx.environment, subject=f"El rol {role}")
    cons = None if data.is_composite(role) else role_consistency(data, role)
    gen = generic_values(eff)
    users = [{"usuario": x["uname"], "desde": x.get("from_dat", ""), "hasta": x.get("to_dat", ""),
              "heredado": x.get("col_flag") == "X"} for x in data.role_users_raw.get(role, [])]
    related = {
        "padre": [data.role_parent[role]] if data.role_parent.get(role) else [],
        "derivados": sorted(r for r, p in data.role_parent.items() if p == role),
        "componentes": sorted(data.composite_children.get(role, [])),
        "compuestos_que_lo_contienen": sorted(c for c, ch in data.composite_children.items() if role in ch),
    }
    tcodes = sorted({str(v) for e in eff.by_object("S_TCODE") for v in e.instance.values("TCD")})
    menu = [{"tipo": m.get("type", ""), "objeto": m.get("tcode", ""),
             "texto": data.tcode_text.get(m.get("tcode", ""), "")} for m in data.role_menu.get(role, [])]
    org = [{"variable": o["varbl"], "desde": o.get("low", ""), "hasta": o.get("high", "")}
           for o in data.role_org.get(role, [])]
    quality = role_quality(data, role, eff, crit, sod, cons, gen)
    issues = list(eff.issues)
    if cons and cons.unresolved_org:
        issues.append(Issue("ORG_SIN_MANTENER", "Niveles organizativos sin mantener: " +
                            ", ".join(cons.unresolved_org[:10]), Severity.BAJO))
    return RoleAnalysis(role, data.role_type(role), data.role_text.get(role, ""), eff, cons, crit, sod,
                        users, related, tcodes, menu, org, gen, quality, issues)
