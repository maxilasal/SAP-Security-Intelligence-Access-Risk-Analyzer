"""Búsquedas al estilo de las pantallas de selección de SAP.

* ``*`` = cualquier cantidad de caracteres; ``+`` = exactamente un carácter.
* Con comodines, el patrón se aplica al valor COMPLETO, como en SAP: ``Z*`` = empieza con Z,
  ``*PAGO*`` = contiene PAGO, ``Z_FI+`` = Z_FI más un carácter.
* Sin comodines, la búsqueda es «contiene» (lo más cómodo para escribir parte de un nombre).
* Varios criterios separados por coma: alcanza con que se cumpla uno (``Z_FI*, Z_MM*``).
* Mayúsculas y minúsculas dan lo mismo.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable

HINT = "Comodines como en SAP: Z* empieza con Z · *PAGO* contiene · + = un carácter · varios separados por coma"


def has_wildcards(text: str) -> bool:
    return "*" in text or "+" in text


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    rx = "".join(".*" if ch == "*" else "." if ch == "+" else re.escape(ch) for ch in pattern)
    return re.compile(f"^{rx}$", re.IGNORECASE | re.DOTALL)


def terms(query: str | None) -> list[str]:
    return [t.strip() for t in (query or "").split(",") if t.strip()]


def matches(query: str | None, *values: object) -> bool:
    """¿Algún valor cumple alguno de los criterios? (consulta vacía = sí)."""
    ts = terms(query)
    if not ts:
        return True
    texts = [str(v).strip() for v in values if v is not None and str(v).strip()]
    for t in ts:
        if has_wildcards(t):
            rx = _compile(t)
            if any(rx.match(x) for x in texts):
                return True
        else:
            low = t.casefold()
            if any(low in x.casefold() for x in texts):
                return True
    return False


def filter_values(query: str | None, values: Iterable[str], exact_without_wildcards: bool = False) -> list[str]:
    """Valores que cumplen la consulta. ``exact_without_wildcards``: sin comodines, valor exacto (como SAP)."""
    ts = terms(query)
    out = []
    for v in values:
        for t in ts:
            if has_wildcards(t):
                ok = bool(_compile(t).match(v))
            else:
                ok = v.casefold() == t.casefold() if exact_without_wildcards else t.casefold() in v.casefold()
            if ok:
                out.append(v)
                break
    return out
