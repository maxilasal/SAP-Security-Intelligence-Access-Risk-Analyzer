"""Carga, validación y versionado de reglas (críticas, SoD y puntuación).

Las reglas viven en YAML versionado (``config/rules``). Cada análisis registra el
hash SHA-256 del conjunto de reglas utilizado, lo que permite reproducir y
auditar cualquier resultado.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..domain.models import RuleStatus, Severity
from .values import Requirement, parse_requirement


class RuleError(ValueError):
    pass


NOT_APPLICABLE = "no_aplica"
ENV_ALIASES = {"QAS": "QA", "TST": "QA", "TEST": "QA", "PROD": "PRD", "PRO": "PRD", "DES": "DEV"}


def norm_env(env: str | None) -> str:
    e = (env or "").strip().upper()
    return ENV_ALIASES.get(e, e)


def _by_env(raw: Any, ctx: str) -> dict[str, str]:
    """``by_environment: {DEV: bajo, QA: no_aplica}`` → gravedad (o «no_aplica») según el ambiente."""
    out: dict[str, str] = {}
    for k, v in (raw or {}).items():
        v = str(v).strip().lower()
        if v != NOT_APPLICABLE and v not in {s.value for s in Severity}:
            raise RuleError(f"{ctx}: by_environment.{k} = {v!r} no es una gravedad válida ni «no_aplica»")
        out[norm_env(str(k))] = v
    return out


def severity_for(base: Severity, environments: list[str], by_environment: dict[str, str],
                 environment: str | None) -> Severity | None:
    """Gravedad de la regla en ese ambiente; None = la regla no aplica allí."""
    env = norm_env(environment)
    if environments and env not in {norm_env(e) for e in environments}:
        return None
    v = by_environment.get(env)
    if v is None:
        return base
    return None if v == NOT_APPLICABLE else Severity(v)


@dataclass
class CriticalRule:
    id: str
    title: str
    type: str                       # profile | requirements | sap_all_equivalence | user_attributes
    severity: Severity
    status: RuleStatus
    category: str
    description: str
    recommendation: str
    version: str
    environments: list[str] = field(default_factory=list)   # vacío = todos
    profiles: list[str] = field(default_factory=list)
    requirements: list[Requirement] = field(default_factory=list)
    tcodes: list[str] = field(default_factory=list)
    reference_objects: list[str] = field(default_factory=list)
    user_conditions: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    by_environment: dict[str, str] = field(default_factory=dict)   # DEV: bajo | QA: no_aplica …

    def severity_in(self, environment: str | None) -> Severity | None:
        return severity_for(self.severity, self.environments, self.by_environment, environment)


@dataclass
class SodAction:
    """Forma de ejecutar una función: transacción(es) opcionales + requisitos de objetos."""

    id: str
    tcodes: list[str]
    requirements: list[Requirement]
    description: str = ""


@dataclass
class SodFunction:
    id: str
    title: str
    process: str
    actions: list[SodAction]
    org_fields: list[str] = field(default_factory=list)   # p. ej. BUKRS, WERKS, EKORG
    confidence: str = "media"   # confianza técnica en la definición (alta | media | baja)
    verify: str = ""            # qué debe verificarse en el sistema


@dataclass
class SodRisk:
    id: str
    title: str
    functions: list[str]
    severity: Severity
    status: RuleStatus
    process: str
    description: str
    recommendation: str
    version: str
    environments: list[str] = field(default_factory=list)
    compare_org_fields: list[str] = field(default_factory=list)
    mitigation_hint: str = ""
    by_environment: dict[str, str] = field(default_factory=dict)

    def severity_in(self, environment: str | None) -> Severity | None:
        return severity_for(self.severity, self.environments, self.by_environment, environment)


@dataclass
class RuleSet:
    critical: list[CriticalRule]
    functions: dict[str, SodFunction]
    risks: list[SodRisk]
    scoring: dict[str, Any]
    hash: str
    versions: dict[str, str]
    files: list[str]
    landscape: dict[str, Any] = field(default_factory=dict)   # control entre sistemas (DEV ↔ PRD)

    def critical_by_id(self, rid: str) -> CriticalRule | None:
        return next((r for r in self.critical if r.id == rid), None)


def _req_list(items: list[dict] | None, ctx: str) -> list[Requirement]:
    try:
        return [parse_requirement(i) for i in items or []]
    except (KeyError, ValueError) as exc:
        raise RuleError(f"{ctx}: requisito inválido: {exc}") from exc


def load_rules(rules_dir: str | Path) -> RuleSet:
    d = Path(rules_dir)
    files = sorted(d.glob("*.yaml"))
    if not files:
        raise RuleError(f"No hay archivos de reglas en {d}")
    digest = hashlib.sha256()
    docs: dict[str, dict] = {}
    for f in files:
        content = f.read_bytes()
        digest.update(f.name.encode() + b"\0" + content)
        docs[f.stem] = yaml.safe_load(content) or {}

    versions = {k: str(v.get("ruleset", {}).get("version", "")) for k, v in docs.items()}
    crit_doc = docs.get("critical_auth", {})
    crit: list[CriticalRule] = []
    seen: set[str] = set()
    for r in crit_doc.get("rules", []):
        rid = r["id"]
        if rid in seen:
            raise RuleError(f"Regla duplicada: {rid}")
        seen.add(rid)
        try:
            crit.append(CriticalRule(
                id=rid, title=r["title"], type=r["type"], severity=Severity(r["severity"]),
                status=RuleStatus(r.get("status", "ejemplo")), category=r.get("category", "general"),
                description=r.get("description", ""), recommendation=r.get("recommendation", ""),
                version=str(r.get("version", versions.get("critical_auth", ""))),
                environments=r.get("environments", []), profiles=r.get("profiles", []),
                requirements=_req_list(r.get("all_of"), rid), tcodes=r.get("tcodes", []),
                reference_objects=r.get("reference_objects", []),
                user_conditions=r.get("user_conditions", {}), references=r.get("references", []),
                by_environment=_by_env(r.get("by_environment"), rid)))
        except (KeyError, ValueError) as exc:
            raise RuleError(f"Regla crítica {rid} inválida: {exc}") from exc
        if crit[-1].type not in ("profile", "requirements", "sap_all_equivalence", "user_attributes"):
            raise RuleError(f"Tipo de regla desconocido en {rid}: {crit[-1].type}")

    sod_doc = docs.get("sod_rules", {})
    functions: dict[str, SodFunction] = {}
    for fdef in sod_doc.get("functions", []):
        actions = [SodAction(a["id"], a.get("tcodes", []), _req_list(a.get("all_of"), f"{fdef['id']}/{a['id']}"),
                             a.get("description", "")) for a in fdef.get("actions", [])]
        if not actions:
            raise RuleError(f"La función {fdef['id']} no tiene acciones")
        functions[fdef["id"]] = SodFunction(fdef["id"], fdef["title"], fdef.get("process", ""), actions,
                                            fdef.get("org_fields", []), fdef.get("confidence", "media"),
                                            fdef.get("verify", ""))
    risks: list[SodRisk] = []
    for rk in sod_doc.get("risks", []):
        for fid in rk["functions"]:
            if fid not in functions:
                raise RuleError(f"El riesgo {rk['id']} referencia la función inexistente {fid}")
        if len(rk["functions"]) < 2:
            raise RuleError(f"El riesgo {rk['id']} debe combinar al menos dos funciones")
        risks.append(SodRisk(
            id=rk["id"], title=rk["title"], functions=rk["functions"], severity=Severity(rk["severity"]),
            status=RuleStatus(rk.get("status", "ejemplo")), process=rk.get("process", ""),
            description=rk.get("description", ""), recommendation=rk.get("recommendation", ""),
            version=str(rk.get("version", versions.get("sod_rules", ""))),
            environments=rk.get("environments", []), compare_org_fields=rk.get("compare_org_fields", []),
            mitigation_hint=rk.get("mitigation_hint", ""), by_environment=_by_env(rk.get("by_environment"), rk["id"])))

    scoring = docs.get("risk_scoring", {})
    landscape = dict(crit_doc.get("landscape") or {})
    known = {r.id for r in crit}
    for rid in [landscape.get("developer_rule", "")] + list(landscape.get("production_rules") or []):
        if rid and rid not in known:
            raise RuleError(f"landscape: la regla {rid} no existe en critical_auth.yaml")
    return RuleSet(crit, functions, risks, scoring, digest.hexdigest(), versions, [f.name for f in files], landscape)
