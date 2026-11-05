"""Motor de segregación de funciones (SoD).

Modelo (inspirado conceptualmente en matrices función/riesgo, no en el
contenido de ninguna matriz oficial):

* **Función**: capacidad de negocio (p. ej. "Ejecutar pagos"), definida por una
  o más **acciones** alternativas. Cada acción = transacciones (opcionales) +
  requisitos de objetos de autorización. Cada requisito se evalúa sobre UNA
  instancia (no se mezclan campos de instancias distintas).
* **Riesgo**: combinación de ≥ 2 funciones incompatibles.

Las restricciones organizativas se analizan y se informan, pero NUNCA ocultan
un conflicto (requisito 12): si no hay solapamiento se indica "posible
acotamiento organizativo — requiere verificación".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..domain.models import Severity, SourceKind
from ..storage.snapshot_data import SnapshotData
from .critical import Evidence
from .effective import EffectiveAuthorizations, EffectiveInstance, tcode_executable
from .rules import RuleSet, SodAction, SodFunction, SodRisk
from .values import FieldValue


@dataclass
class FunctionMatch:
    function_id: str
    title: str
    action_id: str
    tcodes: list[str]
    evidence: list[Evidence]
    roles: list[str]
    direct_profiles: list[str]
    org_values: dict[str, list[str]]
    notes: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)   # vía Fiori/OData: servicios que lo permiten


@dataclass
class SodHit:
    risk_id: str
    title: str
    severity: Severity
    rule_status: str
    rule_version: str
    process: str
    description: str
    recommendation: str
    functions: list[FunctionMatch]
    scope: str                      # intra-rol | entre roles | incluye perfil directo
    roles: list[str]
    org_analysis: list[str]
    explanation: str
    mitigation_hint: str = ""


def _instances_of(eff: EffectiveAuthorizations, only_role: str | None) -> list[EffectiveInstance]:
    if only_role is None:
        return list(eff.instances.values())
    return [e for e in eff.instances.values() if only_role in e.roles]


def _service_index(eff: EffectiveAuthorizations, pool: list[EffectiveInstance], only_role: str | None
                   ) -> tuple[dict[str, EffectiveInstance], list[tuple[FieldValue, EffectiveInstance]]]:
    """Servicios OData (S_SERVICE, SRV_TYPE = HT) que el usuario o el rol puede iniciar: exactos y genéricos."""
    cache = eff.__dict__.setdefault("_srv_idx", {})
    if only_role in cache:
        return cache[only_role]
    base = eff.by_object("S_SERVICE") if only_role is None else [e for e in pool if e.instance.object == "S_SERVICE"]
    exact: dict[str, EffectiveInstance] = {}
    generic: list[tuple[FieldValue, EffectiveInstance]] = []
    for e in base:
        if not e.instance.field_covers("SRV_TYPE", "HT"):
            continue
        for v in e.instance.values("SRV_NAME"):
            if v.is_unresolved_variable:
                continue
            if v.is_generic:
                generic.append((v, e))
            else:
                exact.setdefault(v.low, e)
    cache[only_role] = (exact, generic)
    return exact, generic


def _fiori_entry(action: SodAction, eff: EffectiveAuthorizations, data: SnapshotData,
                 pool: list[EffectiveInstance], only_role: str | None) -> tuple[str, EffectiveInstance] | None:
    """¿Puede iniciar la acción desde Fiori? Un servicio OData que el usuario tiene (S_SERVICE) y que, según la
    SU24 del propio sistema, verifica el objeto principal de la acción con la actividad requerida."""
    checks = getattr(data, "fiori_checks", None)
    if not checks or not action.requirements:
        return None
    main = action.requirements[0]
    services = checks.get(main.object)
    if not services:
        return None
    cond = dict(main.conditions).get("ACTVT")
    wanted = set(cond.values) if cond is not None and cond.mode in ("any_of", "all_of") else set()
    exact, generic = _service_index(eff, pool, only_role)
    if not exact and not generic:
        return None
    for h in sorted(services):
        acts = services[h]
        if wanted and acts is not None and not any(a.covers(w) for a in acts for w in wanted):
            continue  # el servicio verifica el objeto, pero no para esa actividad (p. ej. solo visualizar)
        inst = exact.get(h) or next((e for v, e in generic if v.covers(h)), None)
        if inst is not None:
            return h, inst
    return None


def match_function(fn: SodFunction, eff: EffectiveAuthorizations, data: SnapshotData,
                   only_role: str | None = None) -> FunctionMatch | None:
    pool = _instances_of(eff, only_role)
    for action in fn.actions:
        notes: list[str] = []
        startable: list[str] = []
        fiori: tuple[str, EffectiveInstance] | None = None
        if action.tcodes:
            sub = eff if only_role is None else _restricted(eff, pool)
            for t in action.tcodes:
                ok, _, n = tcode_executable(sub, data, t)
                notes += n
                if ok:
                    startable.append(t)
            if not startable:
                fiori = _fiori_entry(action, eff, data, pool, only_role)
                if fiori is None:
                    continue
                notes = []
        evidence: list[Evidence] = []
        matched: list[EffectiveInstance] = []
        satisfied = True
        for req in action.requirements:
            cand = eff.by_object(req.object) if only_role is None else [e for e in pool if e.instance.object == req.object]
            ms = [e for e in cand if req.matching_instances([e.instance])]
            if not ms:
                satisfied = False
                break
            matched += ms
            evidence += [Evidence.from_instance(req.describe(), m) for m in ms[:5]]
        if not satisfied:
            continue
        if startable:
            # Se prefiere la instancia S_TCODE de un rol que también aporta los objetos (explicación mínima)
            obj_roles = {r for m in matched for r in m.roles}
            base = eff.by_object("S_TCODE") if only_role is None else [e for e in pool if e.instance.object == "S_TCODE"]
            cands = [e for e in base if any(e.instance.field_covers("TCD", t) for t in startable)]
            cands.sort(key=lambda e: 0 if set(e.roles) & obj_roles else 1)
            if cands:
                evidence.insert(0, Evidence.from_instance(f"S_TCODE (TCD = {', '.join(startable)})", cands[0]))
                matched.append(cands[0])
        services: list[str] = []
        if fiori is not None:
            h, inst = fiori
            name = data.service_label(h) if hasattr(data, "service_label") else ""
            services.append(name or h)
            evidence.insert(0, Evidence.from_instance(
                f"S_SERVICE (servicio Fiori/OData {name or h}; según SU24 verifica {action.requirements[0].object})",
                inst))
            matched.append(inst)
            notes.append(f"Vía Fiori/OData: {name or 'servicio ' + h} (sin la transacción "
                         f"{', '.join(action.tcodes[:3])}).")
        org: dict[str, list[str]] = {}
        for of in fn.org_fields:
            vals = sorted({str(v) for m in matched for v in m.instance.values(of)})
            if vals:
                org[of] = vals
        roles = sorted({r for m in matched for r in m.roles})
        direct = sorted({s.profile for m in matched for s in m.sources if s.kind is SourceKind.PERFIL_DIRECTO})
        return FunctionMatch(fn.id, fn.title, action.id, startable, evidence, roles, direct, org, notes, services)
    return None


def _restricted(eff: EffectiveAuthorizations, pool: list[EffectiveInstance]) -> EffectiveAuthorizations:
    return EffectiveAuthorizations(eff.username, eff.as_of, eff.user, eff.assignments, eff.profiles,
                                   {e.instance.key: e for e in pool}, [])


def _overlap(a: list[str], b: list[str]) -> bool:
    fa = [FieldValue(*(v.split("–") + [""])[:2]) for v in a]
    fb = [FieldValue(*(v.split("–") + [""])[:2]) for v in b]
    return any(x.covers(y.low) or y.covers(x.low) for x in fa for y in fb)


def _org_analysis(risk: SodRisk, matches: list[FunctionMatch]) -> list[str]:
    out = []
    for of in risk.compare_org_fields:
        sets = [m.org_values.get(of) for m in matches]
        if any(s is None for s in sets):
            out.append(f"{of}: no evaluable en todas las funciones (sin valores en la evidencia).")
            continue
        overlap = all(_overlap(sets[0], s) for s in sets[1:])  # type: ignore[arg-type]
        desc = " / ".join(f"{m.function_id}: {', '.join(m.org_values[of])}" for m in matches)
        if overlap:
            out.append(f"{of}: los valores se solapan ({desc}) — el conflicto aplica a la misma unidad organizativa.")
        else:
            out.append(f"{of}: SIN solapamiento detectado ({desc}). Posible acotamiento organizativo; "
                       "requiere verificación funcional. El conflicto NO se descarta automáticamente.")
    return out


def _explain(risk: SodRisk, matches: list[FunctionMatch], subject: str) -> str:
    parts = []
    for m in matches:
        via = ", ".join(m.roles) if m.roles else ""
        if m.direct_profiles:
            via += (" y " if via else "") + "perfil(es) directo(s) " + ", ".join(m.direct_profiles)
        tc = (f" (transacción {', '.join(m.tcodes)})" if m.tcodes else
              f" (app Fiori / servicio OData {', '.join(m.services)})" if m.services else "")
        parts.append(f"«{m.title}»{tc} mediante {via or 'origen no determinado'}")
    return (f"{subject} reúne {len(matches)} funciones incompatibles: " + "; ".join(parts) +
            f". Esta combinación incumple la regla {risk.id} «{risk.title}»: {risk.description}")


def evaluate_sod(rules: RuleSet, data: SnapshotData, eff: EffectiveAuthorizations,
                 environment: str | None = None, subject: str | None = None) -> list[SodHit]:
    hits: list[SodHit] = []
    cache: dict[str, FunctionMatch | None] = {}
    for risk in rules.risks:
        severity = risk.severity_in(environment)
        if severity is None:  # el riesgo no aplica en este ambiente (p. ej. procesos de negocio en DEV)
            continue
        matches = []
        for fid in risk.functions:
            if fid not in cache:
                cache[fid] = match_function(rules.functions[fid], eff, data)
            m = cache[fid]
            if m is None:
                break
            matches.append(m)
        if len(matches) != len(risk.functions):
            continue
        roles = sorted({r for m in matches for r in m.roles})
        if any(m.direct_profiles for m in matches):
            scope = "incluye perfil directo"
        else:
            common = set.intersection(*(set(m.roles) for m in matches)) if matches else set()
            intra = [r for r in sorted(common)
                     if all(match_function(rules.functions[f], eff, data, only_role=r) for f in risk.functions)]
            scope = f"intra-rol ({', '.join(intra)})" if intra else "entre roles"
        hits.append(SodHit(risk.id, risk.title, severity, risk.status.value, risk.version, risk.process,
                           risk.description, risk.recommendation, matches, scope, roles,
                           _org_analysis(risk, matches),
                           _explain(risk, matches, subject or f"El usuario {eff.username}"),
                           risk.mitigation_hint))
    return sorted(hits, key=lambda h: -h.severity.rank)
