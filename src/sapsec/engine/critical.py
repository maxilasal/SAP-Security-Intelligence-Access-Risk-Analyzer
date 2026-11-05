"""Motor de detección de autorizaciones críticas."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from ..domain.models import Certainty, Severity
from ..storage.snapshot_data import SnapshotData
from .effective import EffectiveAuthorizations, EffectiveInstance, tcode_executable
from .rules import CriticalRule, RuleSet


@dataclass
class Evidence:
    requirement: str
    object: str
    auth: str
    values: str
    roles: list[str]
    provenance: str
    certainty: str

    @classmethod
    def from_instance(cls, req: str, e: EffectiveInstance) -> "Evidence":
        return cls(req, e.instance.object, e.instance.auth, e.instance.as_text(), e.roles,
                   e.provenance(), e.certainty.value)


@dataclass
class RuleHit:
    rule_id: str
    title: str
    kind: str
    severity: Severity
    rule_status: str
    rule_version: str
    category: str
    description: str
    recommendation: str
    certainty: Certainty
    evidence: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    @property
    def fingerprint_part(self) -> str:
        return self.rule_id


def _applies(rule_envs: list[str], environment: str | None) -> bool:
    return not rule_envs or (environment or "").upper() in [e.upper() for e in rule_envs]


def _instances(eff: EffectiveAuthorizations) -> list[EffectiveInstance]:
    return list(eff.instances.values())


def _wildcard_coverage(data: SnapshotData, eff: EffectiveAuthorizations, objects: list[str]
                       ) -> dict[str, EffectiveInstance]:
    """Objetos para los que existe UNA instancia con '*' en todos sus campos (TOBJ o la propia instancia)."""
    covered: dict[str, EffectiveInstance] = {}
    for obj in objects:
        fields = data.object_fields.get(obj)
        for e in eff.by_object(obj):
            fs = fields or list(e.instance.fields)
            if fs and all(e.instance.field_is_full_wildcard(f) for f in fs):
                covered[obj] = e
                break
    return covered


def sap_all_coverage(data: SnapshotData, eff: EffectiveAuthorizations, reference: list[str]
                     ) -> tuple[float, int, int, dict[str, EffectiveInstance], str]:
    """Cobertura con comodín total de la lista de objetos críticos de referencia.

    La comparación contra el perfil SAP_ALL completo del sistema se informa como
    métrica adicional (incluye miles de objetos de aplicación, por lo que no es un
    buen criterio único para detectar superusuarios técnicos).
    """
    objects = sorted(set(reference))
    covered = _wildcard_coverage(data, eff, objects)
    total = len(objects)
    sap_all_objs = data.sap_all_objects()
    extra = ""
    if sap_all_objs:
        c2 = _wildcard_coverage(data, eff, sorted(sap_all_objs & eff.objects()))
        extra = f"; frente al perfil SAP_ALL del sistema: {len(c2)}/{len(sap_all_objs)} objetos"
    return (len(covered) / total if total else 0.0), len(covered), total, covered, \
        "lista de objetos críticos de referencia" + extra


def evaluate_rule(rule: CriticalRule, data: SnapshotData, eff: EffectiveAuthorizations,
                  environment: str | None, as_of: date, threshold: float,
                  inactivity_days: int) -> RuleHit | None:
    severity = rule.severity_in(environment)
    if severity is None:  # la regla no aplica en este ambiente (p. ej. desarrollo en DEV)
        return None

    def hit(evidence: list[Evidence], certainty: Certainty, notes: list[str] | None = None,
            metrics: dict | None = None) -> RuleHit:
        roles = sorted({r for ev in evidence for r in ev.roles})
        return RuleHit(rule.id, rule.title, "critica", severity, rule.status.value, rule.version,
                       rule.category, rule.description, rule.recommendation, certainty, evidence,
                       notes or [], roles, metrics or {})

    if rule.type == "profile":
        # El perfil puede estar asignado directamente o dentro de un perfil compuesto (UST10C).
        found: dict[str, str] = {}
        for top in eff.profiles:
            for name in data.profile_tree(top):
                if name in rule.profiles:
                    found.setdefault(name, top)
        if found:
            notes = [f"{n} asignado directamente" if via == n else
                     f"{n} incluido dentro del perfil compuesto {via} (quitar {via})" for n, via in sorted(found.items())]
            ev = [Evidence(f"Perfil {n}", "", "", "(perfil asignado)" if via == n else f"(dentro de {via})",
                           [], f"UST04: {via}", Certainty.ASIGNADO.value) for n, via in sorted(found.items())]
            return hit(ev, Certainty.ASIGNADO, notes)
        return None

    if rule.type == "requirements":
        evidence: list[Evidence] = []
        certs: list[Certainty] = []
        for req in rule.requirements:
            matches = [e for e in eff.by_object(req.object) if req.matching_instances([e.instance])]
            if not matches:
                return None
            evidence += [Evidence.from_instance(req.describe(), m) for m in matches[:5]]
            certs.append(min((m.certainty for m in matches), key=_cert_rank, default=Certainty.ASIGNADO))
        notes = []
        cert = min(certs, key=_cert_rank) if certs else Certainty.ASIGNADO
        if rule.tcodes:
            startable = [t for t in rule.tcodes if tcode_executable(eff, data, t)[0]]
            if startable:
                notes.append(f"Transacciones de acceso cubiertas: {', '.join(startable)}")
                if cert is Certainty.ASIGNADO:
                    cert = Certainty.CAPACIDAD_POTENCIAL
            else:
                notes.append("Ninguna transacción de referencia está autorizada; el riesgo puede "
                             "materializarse por otras vías (RFC, otros programas, Fiori/OData).")
        return hit(evidence, cert, notes)

    if rule.type == "sap_all_equivalence":
        ratio, cov, total, covered, ref = sap_all_coverage(data, eff, rule.reference_objects)
        if total and ratio >= threshold and "SAP_ALL" not in eff.profiles:
            ev = [Evidence.from_instance("Comodín total en todos los campos", e) for e in list(covered.values())[:30]]
            return hit(ev, Certainty.ASIGNADO,
                       [f"Cobertura {cov}/{total} ({ratio:.0%}) contra {ref}; umbral {threshold:.0%}"],
                       {"ratio": ratio, "covered": cov, "total": total})
        return None

    if rule.type == "user_attributes":
        u = eff.user
        if u is None:
            return None
        c = rule.user_conditions
        if "usernames" in c and u.username not in c["usernames"]:
            return None
        if "user_types" in c and u.user_type not in c["user_types"]:
            return None
        if "locked" in c and bool(c["locked"]) != u.is_locked:
            return None
        if c.get("inactive_days_gt") is not None:
            if u.last_logon is None:
                if not c.get("include_never_logged_on", True):
                    return None
            elif (as_of - u.last_logon).days <= int(c["inactive_days_gt"]):
                return None
        if c.get("min_instances") and len(eff.instances) < int(c["min_instances"]):
            return None
        detail = (f"Usuario {u.username} tipo {u.type_label}, {u.lock_label}, "
                  f"último acceso {u.last_logon or 'sin dato'}")
        return hit([Evidence("Atributos del usuario", "", "", detail, [], "USR02", Certainty.ASIGNADO.value)],
                   Certainty.ASIGNADO)
    return None


_CERT_ORDER = [Certainty.DEFINIDO_EN_ROL, Certainty.EN_PERFIL, Certainty.ASIGNADO,
               Certainty.CAPACIDAD_POTENCIAL, Certainty.CONFIRMADO_EN_SAP]


def _cert_rank(c: Certainty) -> int:
    return _CERT_ORDER.index(c)


def evaluate_critical(rules: RuleSet, data: SnapshotData, eff: EffectiveAuthorizations,
                      environment: str | None, as_of: date, threshold: float = 0.8,
                      inactivity_days: int = 90) -> list[RuleHit]:
    hits = []
    for r in rules.critical:
        h = evaluate_rule(r, data, eff, environment, as_of, threshold, inactivity_days)
        if h:
            hits.append(h)
    return sorted(hits, key=lambda h: -h.severity.rank)
