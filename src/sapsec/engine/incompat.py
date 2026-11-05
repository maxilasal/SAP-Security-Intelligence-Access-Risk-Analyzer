"""Incompatibilidades entre roles: qué roles NO deberían combinarse, y qué roles NO debería recibir un usuario.

1. Para cada rol se calcula qué funciones SoD cumple **por sí solo** (perfil generado o PFCG).
2. Un rol es incompatible con otro si cada uno aporta una función distinta de un mismo riesgo.
3. Para un usuario se calculan las funciones que ya cumple y, por cada riesgo al que le falta una
   sola función, se listan los roles que la completarían.

Limitación: una función también puede completarse combinando partes de varios roles (p. ej.
la transacción en un rol y el objeto en otro). Estas listas son un piso; el simulador evalúa
siempre el caso exacto.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from ..storage.snapshot_data import SnapshotData
from .effective import EffectiveAuthorizations, role_as_effective
from .rules import RuleSet
from .sod import match_function


def _role_objects(data: SnapshotData, role: str) -> set[str]:
    roles = data.composite_children.get(role, []) if data.is_composite(role) else [role]
    objs: set[str] = set()
    for r in roles:
        objs |= {x["object"] for x in data.role_values.get(r, []) if x.get("deleted") != "X"}
        for p in data.role_profiles.get(r, []):
            objs |= {o for o, _ in data.profile_auths.get(p, [])}
    return objs


CACHE_DIR: Path | None = None   # lo define la capa de servicios (data/cache)


def _cache_file(rules: RuleSet, data: SnapshotData) -> Path | None:
    if CACHE_DIR is None or not data.snapshot_id:
        return None
    sig = f"{len(data.role_names)}-{len(data.users)}-{len(data.auth_values)}"  # evita reutilizar un caché ajeno
    return CACHE_DIR / f"rolefn_{data.snapshot_id}_{sig}_{rules.hash[:12]}.json"


def role_function_map_if_ready(rules: RuleSet, data: SnapshotData, as_of: date) -> dict[str, set[str]] | None:
    """Devuelve el mapa si ya está calculado (memoria o disco); nunca calcula."""
    key = (rules.hash, as_of)
    cache = getattr(data, "_role_fn_cache", None)
    if cache and cache[0] == key:
        return cache[1]
    f = _cache_file(rules, data)
    if f is not None and f.exists():
        try:
            m = {r: set(fs) for r, fs in json.loads(f.read_text(encoding="utf-8")).items()}
            data._role_fn_cache = (key, m)  # type: ignore[attr-defined]  # noqa: SLF001
            return m
        except (OSError, ValueError):
            return None
    return None


def role_function_map(rules: RuleSet, data: SnapshotData, as_of: date) -> dict[str, set[str]]:
    """Rol → funciones SoD que cumple por sí solo. Se cachea en memoria y en disco (snapshot inmutable)."""
    key = (rules.hash, as_of)
    ready = role_function_map_if_ready(rules, data, as_of)
    if ready is not None:
        return ready
    fiori = bool(getattr(data, "fiori_checks", None))
    needed: dict[str, list[set[str]]] = {}
    for fid, fn in rules.functions.items():
        alts: list[set[str]] = []
        for a in fn.actions:
            objs = {q.object for q in a.requirements}
            if a.tcodes:
                alts.append(objs | {"S_TCODE"})
                if fiori:
                    alts.append(objs | {"S_SERVICE"})  # la misma acción desde una app Fiori
            else:
                alts.append(objs)
        needed[fid] = alts
    result: dict[str, set[str]] = {}
    for role in data.role_names:
        objs = _role_objects(data, role)
        candidates = [fid for fid, alts in needed.items() if any(req <= objs for req in alts)]
        if not candidates:
            continue
        eff = role_as_effective(data, role, as_of)
        fs = {fid for fid in candidates if match_function(rules.functions[fid], eff, data)}
        if fs:
            result[role] = fs
    data._role_fn_cache = (key, result)  # type: ignore[attr-defined]  # noqa: SLF001
    f = _cache_file(rules, data)
    if f is not None:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({r: sorted(fs) for r, fs in result.items()}), encoding="utf-8")
    return result


@dataclass
class Incompatibility:
    risk_id: str
    risk_title: str
    severity: str
    has_function: str          # función que ya aporta el rol / tiene el usuario
    missing_function: str      # función que completaría el riesgo
    missing_title: str
    roles: list[str]           # roles que aportan la función faltante
    total_roles: int


def incompatible_with_role(rules: RuleSet, data: SnapshotData, role: str, as_of: date,
                           limit: int = 40, environment: str | None = None) -> tuple[list[Incompatibility], list[str]]:
    fmap = role_function_map(rules, data, as_of)
    mine = fmap.get(role, set())
    out, intra = [], []
    for risk in rules.risks:
        sev = risk.severity_in(environment)
        if sev is None:  # no aplica en este ambiente
            continue
        fs = set(risk.functions)
        if not mine & fs:
            continue
        missing = fs - mine
        if not missing:
            intra.append(risk.id)
            continue
        if len(missing) != 1:
            continue
        miss = missing.pop()
        providers = sorted(r for r, f in fmap.items() if miss in f and r != role)
        if providers:
            out.append(Incompatibility(risk.id, risk.title, sev.value,
                                       ", ".join(rules.functions[f].title for f in sorted(mine & fs)), miss,
                                       rules.functions[miss].title, providers[:limit], len(providers)))
    return sorted(out, key=lambda x: (-_rank(x.severity), x.risk_id)), intra


def forbidden_for_user(rules: RuleSet, data: SnapshotData, eff: EffectiveAuthorizations, as_of: date,
                       limit: int = 40, environment: str | None = None) -> list[Incompatibility]:
    """Roles que, agregados al usuario, completarían un riesgo SoD (a partir de lo que ya tiene)."""
    fmap = role_function_map(rules, data, as_of)
    has = {fid for fid, fn in rules.functions.items() if match_function(fn, eff, data)}
    current = set(eff.valid_roles())
    out = []
    for risk in rules.risks:
        sev = risk.severity_in(environment)
        if sev is None:
            continue
        fs = set(risk.functions)
        if not has & fs or fs <= has:
            continue  # sin relación o conflicto ya existente (se informa como hallazgo)
        missing = fs - has
        if len(missing) != 1:
            continue
        miss = missing.pop()
        providers = sorted(r for r, f in fmap.items() if miss in f and r not in current)
        if providers:
            out.append(Incompatibility(risk.id, risk.title, sev.value,
                                       ", ".join(rules.functions[f].title for f in sorted(has & fs)), miss,
                                       rules.functions[miss].title, providers[:limit], len(providers)))
    return sorted(out, key=lambda x: (-_rank(x.severity), x.risk_id))


def _rank(sev: str) -> int:
    return {"critico": 4, "alto": 3, "medio": 2, "bajo": 1}.get(sev, 0)
