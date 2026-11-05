"""Recomendaciones de mínimo privilegio basadas en subsunción de valores."""

from __future__ import annotations

from typing import Any


def redundant_roles(a: Any) -> list[tuple[str, list[str]]]:
    """Roles cuyas instancias están todas subsumidas por instancias de OTROS roles del usuario."""
    by_role: dict[str, list[Any]] = {}
    for e in a.eff.instances.values():
        for r in e.roles:
            by_role.setdefault(r, []).append(e)
    out = []
    for role, insts in by_role.items():
        if not insts:
            continue
        providers: set[str] = set()
        ok = True
        for e in insts:
            cover = [o for o in a.eff.instances.values() if o is not e and role not in o.roles
                     and o.instance.subsumes(e.instance)]
            if not cover:
                ok = False
                break
            providers |= {r for o in cover for r in o.roles}
        if ok and providers:
            out.append((role, sorted(providers)))
    return out
