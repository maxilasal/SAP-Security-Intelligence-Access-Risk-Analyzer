"""Simulador de asignaciones (sin escribir nada en SAP).

Escenarios soportados: agregar uno o varios roles, quitar roles, sustituir un
rol por otro y modificar hipotéticamente valores de un rol. El resultado compara
el estado actual con el estado simulado y emite una recomendación orientativa:

* ``APROBACION_RECOMENDADA`` – sin riesgos relevantes nuevos según las reglas evaluadas.
* ``REQUIERE_REVISION``      – riesgos nuevos de gravedad media/alta o datos con certeza reducida.
* ``NO_RECOMENDADO``         – nuevos riesgos críticos (SoD o privilegios excesivos).

La recomendación nunca sustituye la decisión del responsable de seguridad.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import date

from ..domain.models import Certainty, Issue, RoleAssignment, Severity, Source, SourceKind
from ..storage.snapshot_data import SnapshotData
from .analysis import AnalysisContext, UserAnalysis, analyze_effective, analyze_user
from .critical import RuleHit
from .effective import EffectiveInstance, compute_effective, role_instances_for_simulation
from .sod import SodHit
from .values import AuthInstance, FieldValue

APROBACION = "APROBACION_RECOMENDADA"
REVISION = "REQUIERE_REVISION"
NO_RECOMENDADO = "NO_RECOMENDADO"

LABELS = {APROBACION: "APROBACIÓN RECOMENDADA", REVISION: "REQUIERE REVISIÓN", NO_RECOMENDADO: "NO RECOMENDADO"}


@dataclass
class ValueOverride:
    role: str
    object: str
    field: str
    values: list[str]
    auth: str | None = None   # None = todas las instancias del objeto en el rol


@dataclass
class Scenario:
    add_roles: list[str] = field(default_factory=list)
    remove_roles: list[str] = field(default_factory=list)
    replace: list[tuple[str, str]] = field(default_factory=list)   # (rol actual, rol nuevo)
    overrides: list[ValueOverride] = field(default_factory=list)

    def normalized(self) -> "Scenario":
        add = [r.strip().upper() for r in self.add_roles if r.strip()]
        rem = [r.strip().upper() for r in self.remove_roles if r.strip()]
        for old, new in self.replace:
            rem.append(old.strip().upper())
            add.append(new.strip().upper())
        return Scenario(sorted(set(add)), sorted(set(rem)), [], self.overrides)

    def describe(self) -> str:
        n = self.normalized()
        parts = []
        if n.add_roles:
            parts.append("Agregar: " + ", ".join(n.add_roles))
        if n.remove_roles:
            parts.append("Quitar: " + ", ".join(n.remove_roles))
        if n.overrides:
            parts.append(f"{len(n.overrides)} modificación(es) hipotética(s) de valores")
        return "; ".join(parts) or "Sin cambios"


@dataclass
class NewPermission:
    object: str
    auth: str
    values: str
    role: str
    certainty: str
    already_covered: bool
    critical_object: bool


@dataclass
class Alternative:
    role: str
    description: str
    tcode_coverage: float
    missing_tcodes: list[str]
    new_critical: int
    new_sod: int
    max_new_severity: str
    confidence: str


@dataclass
class SimulationResult:
    username: str
    scenario: Scenario
    before: UserAnalysis
    after: UserAnalysis
    new_permissions: list[NewPermission]
    removed_instances: int
    new_critical: list[RuleHit]
    resolved_critical: list[RuleHit]
    new_sod: list[SodHit]
    preexisting_sod: list[SodHit]
    resolved_sod: list[SodHit]
    recommendation: str
    reasons: list[str]
    measures: list[str]
    issues: list[Issue]
    alternatives: list[Alternative]
    added_role_summary: list[dict]

    @property
    def recommendation_label(self) -> str:
        return LABELS[self.recommendation]


CRITICAL_OBJECTS = {"S_USER_GRP", "S_USER_AGR", "S_USER_PRO", "S_USER_AUT", "S_DEVELOP", "S_TABU_DIS",
                    "S_TABU_NAM", "S_RFC", "S_RFCACL", "S_PROGRAM", "S_DATASET", "S_ADMI_FCD", "S_BTCH_ADM",
                    "S_BTCH_NAM", "S_TRANSPRT", "S_CTS_ADMI", "S_SERVICE", "S_ICF", "S_LOG_COM", "S_TABU_CLI",
                    "S_START"}


def _apply_overrides(instances: list[tuple[AuthInstance, Certainty, str]], overrides: list[ValueOverride]
                     ) -> list[tuple[AuthInstance, Certainty, str]]:
    out = []
    for inst, cert, role in instances:
        ovs = [o for o in overrides if o.role == role and o.object == inst.object
               and (o.auth is None or o.auth == inst.auth)]
        if ovs:
            inst = copy.deepcopy(inst)
            for o in ovs:
                inst.fields[o.field] = [FieldValue(*(v.split("-", 1) + [""])[:2]) if "-" in v and not v.startswith("$")
                                        else FieldValue(v) for v in o.values]
            cert = Certainty.DEFINIDO_EN_ROL
        out.append((inst, cert, role))
    return out


def build_after(data: SnapshotData, username: str, as_of: date, scenario: Scenario):  # noqa: ANN201
    sc = scenario.normalized()
    issues: list[Issue] = []
    current_assign = data.user_assignments(username)
    current_roles = {a.role for a in current_assign if a.state(as_of) == "vigente"}
    removed = set(sc.remove_roles)
    # quitar un rol compuesto quita también sus componentes heredados
    for r in list(removed):
        removed |= set(data.composite_children.get(r, []))
    for r in sc.remove_roles:
        if r not in current_roles:
            issues.append(Issue("ROL_NO_ASIGNADO", f"El rol a quitar {r} no está asignado vigente al usuario",
                                Severity.INFORMATIVO))
    overridden_roles = {o.role for o in sc.overrides}
    removed_profiles = {p for r in removed | overridden_roles for p in data.role_profiles.get(r, [])}
    # Un perfil se conserva si otro rol vigente no quitado lo aporta (no ocurre con perfiles generados)
    profiles = [p for p in data.user_profiles.get(username, []) if p not in removed_profiles]
    assignments = [a for a in current_assign if a.role not in removed]
    extra: list[tuple[AuthInstance, Source, Certainty]] = []
    roles_to_add = list(sc.add_roles) + [r for r in overridden_roles if r in current_roles and r not in removed]
    for role in roles_to_add:
        if role in current_roles and role in sc.add_roles:
            issues.append(Issue("ROL_YA_ASIGNADO", f"El usuario ya tiene el rol {role} vigente", Severity.INFORMATIVO))
        if role not in data.role_names:
            issues.append(Issue("ROL_INEXISTENTE", f"El rol {role} no existe en el snapshot de este sistema/mandante",
                                Severity.ALTO, {"rol": role}))
            continue
        items, iss = role_instances_for_simulation(data, role)
        issues += iss
        items = _apply_overrides(items, sc.overrides)
        for inst, cert, child in items:
            extra.append((inst, Source(SourceKind.SIMULADO, "(simulado)", child, role if child != role else None),
                          cert))
        if role in sc.add_roles:
            assignments.append(RoleAssignment(role, as_of, None))
            for child in data.composite_children.get(role, []):
                assignments.append(RoleAssignment(child, as_of, None, via_composite=role))
    eff = compute_effective(data, username, as_of, profiles_override=profiles,
                            assignments_override=assignments, extra_instances=extra)
    return eff, issues, sc


def _new_permissions(before: dict, after: dict, data: SnapshotData) -> list[NewPermission]:
    out = []
    before_list = list(before.values())
    for key, e in after.items():
        if key in before:
            continue
        if not any(s.kind is SourceKind.SIMULADO for s in e.sources):
            continue
        covered = any(b.instance.subsumes(e.instance) for b in before_list if b.instance.object == e.instance.object)
        role = next((s.role for s in e.sources if s.kind is SourceKind.SIMULADO), "") or ""
        out.append(NewPermission(e.instance.object, e.instance.auth, e.instance.as_text(), role, e.certainty.value,
                                 covered, e.instance.object in CRITICAL_OBJECTS))
    return sorted(out, key=lambda p: (p.already_covered, not p.critical_object, p.object))


def simulate(ctx: AnalysisContext, data: SnapshotData, username: str, scenario: Scenario,
             snapshot_meta: dict | None = None, with_alternatives: bool = True) -> SimulationResult:
    before = analyze_user(ctx, data, username)
    eff_after, sim_issues, sc = build_after(data, username, ctx.as_of, scenario)
    after = analyze_effective(ctx, data, eff_after)

    # Lo informativo (p. ej. «desarrollador» en DEV) no es un riesgo nuevo ni uno resuelto.
    b_crit = {h.rule_id: h for h in before.critical if h.severity is not Severity.INFORMATIVO}
    a_crit = {h.rule_id: h for h in after.critical if h.severity is not Severity.INFORMATIVO}
    b_sod = {h.risk_id: h for h in before.sod}
    a_sod = {h.risk_id: h for h in after.sod}
    new_crit = [h for k, h in a_crit.items() if k not in b_crit]
    resolved_crit = [h for k, h in b_crit.items() if k not in a_crit]
    new_sod = [h for k, h in a_sod.items() if k not in b_sod]
    pre_sod = [h for k, h in a_sod.items() if k in b_sod]
    resolved_sod = [h for k, h in b_sod.items() if k not in a_sod]
    new_perms = _new_permissions(before.eff.instances, eff_after.instances, data)
    removed_n = len(set(before.eff.instances) - set(eff_after.instances))

    reasons: list[str] = []
    measures: list[str] = []
    rec = APROBACION
    for h in new_sod:
        reasons.append(f"[{h.severity.label}] Nuevo conflicto SoD {h.risk_id}: {h.explanation}")
        if h.recommendation:
            measures.append(f"{h.risk_id}: {h.recommendation}")
    for h in new_crit:
        reasons.append(f"[{h.severity.label}] Nueva autorización crítica {h.rule_id}: {h.title}. Roles: "
                       f"{', '.join(h.roles) or 'n/d'}")
        if h.recommendation:
            measures.append(f"{h.rule_id}: {h.recommendation}")
    new_sev = [h.severity for h in new_crit] + [h.severity for h in new_sod]
    if any(s is Severity.CRITICO for s in new_sev):
        rec = NO_RECOMENDADO
    elif any(s.rank >= Severity.MEDIO.rank for s in new_sev):
        rec = REVISION
    elif after.risk.inherent_level.rank > before.risk.inherent_level.rank:
        rec = REVISION
        reasons.append(f"El nivel de riesgo inherente aumenta de {before.risk.inherent_level.label} a "
                       f"{after.risk.inherent_level.label}.")

    quality = [i for i in sim_issues if i.code in ("ROL_PERFIL_INCONSISTENTE", "ROL_INEXISTENTE")]
    meta = snapshot_meta or {}
    if meta.get("status") and meta["status"] != "completo":
        quality.append(Issue("SNAPSHOT_INCOMPLETO", "El snapshot utilizado está incompleto: la evaluación "
                             "puede omitir riesgos.", Severity.MEDIO))
    if meta.get("stale"):
        quality.append(Issue("SNAPSHOT_ANTIGUO", f"Los datos tienen {meta.get('age_days')} días: actualice "
                             "el snapshot antes de decidir.", Severity.MEDIO))
    if quality and rec == APROBACION:
        rec = REVISION
    for q in quality:
        reasons.append(f"[Calidad de datos] {q.message}")
    if any(i.code == "ROL_INEXISTENTE" for i in sim_issues) and rec != NO_RECOMENDADO:
        rec = REVISION
    if all(r.status.value == "ejemplo" for r in ctx.rules.risks):
        reasons.append("Aviso: todas las reglas SoD están en estado 'ejemplo' (no validadas ni aprobadas "
                       "por la organización).")
    if rec == APROBACION:
        reasons.insert(0, f"No se detectaron riesgos relevantes nuevos conforme a las {len(ctx.rules.critical)} "
                          f"reglas críticas y {len(ctx.rules.risks)} reglas SoD evaluadas.")
    if new_sod:
        measures += ["Verificar la necesidad funcional con el responsable del proceso.",
                     "Evaluar un rol alternativo con menos privilegios (ver alternativas).",
                     "Separar responsabilidades entre distintas personas cuando sea posible.",
                     "Si el acceso es indispensable, documentar y aprobar un control mitigante con vencimiento."]
    if any(p.critical_object and not p.already_covered for p in new_perms):
        measures.append("Revisar los objetos de Basis críticos que incorpora el rol y restringir valores si corresponde.")

    added_summary = []
    for role in sc.add_roles:
        if role not in data.role_names:
            continue
        perms = [p for p in new_perms if p.role in ([role] + data.composite_children.get(role, []))]
        added_summary.append({
            "rol": role, "tipo": data.role_type(role), "descripcion": data.role_text.get(role, ""),
            "instancias_nuevas": len(perms), "ya_cubiertas": sum(p.already_covered for p in perms),
            "objetos_criticos": sorted({p.object for p in perms if p.critical_object}),
        })

    alternatives = []
    if with_alternatives and len(sc.add_roles) == 1 and rec != APROBACION:
        alternatives = find_alternatives(ctx, data, username, sc.add_roles[0], before)

    return SimulationResult(username, sc, before, after, new_perms, removed_n, new_crit, resolved_crit,
                            new_sod, pre_sod, resolved_sod, rec, reasons, list(dict.fromkeys(measures)),
                            sim_issues + [q for q in quality if q not in sim_issues], alternatives, added_summary)


def _role_tcodes(data: SnapshotData, role: str) -> set[str]:
    items, _ = role_instances_for_simulation(data, role)
    return {v.low for inst, _, _ in items if inst.object == "S_TCODE"
            for v in inst.values("TCD") if not v.is_generic}


def find_alternatives(ctx: AnalysisContext, data: SnapshotData, username: str, role: str,
                      before: UserAnalysis, limit: int = 10) -> list[Alternative]:
    """Roles existentes que cubren las transacciones del rol solicitado con menos riesgo.

    Confianza BAJA/MEDIA: la cobertura de transacciones no garantiza que el rol
    alternativo permita cumplir la función (valores de objetos, org. levels).
    """
    wanted = _role_tcodes(data, role)
    if not wanted:
        return []
    scored = []
    for cand in data.role_names:
        if cand == role or data.is_composite(cand) or not data.role_profiles.get(cand):
            continue
        tc = _role_tcodes(data, cand)
        cov = len(wanted & tc) / len(wanted)
        if cov >= 0.5:
            scored.append((cov, cand, tc))
    scored.sort(key=lambda x: -x[0])
    b_refs = before.finding_refs()
    out = []
    for cov, cand, tc in scored[: limit * 2]:
        res = simulate(ctx, data, username, Scenario(add_roles=[cand]), with_alternatives=False)
        new_c = [h for h in res.new_critical if h.rule_id not in b_refs]
        new_s = [h for h in res.new_sod if h.risk_id not in b_refs]
        sev = Severity.max([h.severity for h in new_c] + [h.severity for h in new_s])
        out.append(Alternative(cand, data.role_text.get(cand, ""), round(cov, 2), sorted(wanted - tc),
                               len(new_c), len(new_s), sev.label if (new_c or new_s) else "—",
                               "media" if cov == 1 else "baja"))
    out.sort(key=lambda a: (a.new_critical + a.new_sod, -a.tcode_coverage))
    return out[:limit]
