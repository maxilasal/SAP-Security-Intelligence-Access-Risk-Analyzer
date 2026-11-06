"""Temas de colores y logo de la aplicación.

Cada persona elige su tema en «Mi cuenta» (se guarda en su usuario y en una cookie del navegador para la pantalla
de ingreso). Los colores salen de un solo lugar, ``THEMES``: de ahí se generan la hoja ``/temas.css``, las muestras
para elegir y el ícono de la pestaña del navegador (``/icono.svg``), que toma el color del tema.

Todas las combinaciones cumplen el contraste mínimo de accesibilidad (WCAG AA): enlaces sobre fondo claro ≥ 4,5:1,
texto blanco sobre botones ≥ 4,5:1 y texto de la barra lateral ≥ 4,5:1.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Theme:
    key: str
    name: str
    brand: str        # barra lateral y pantalla de ingreso
    brand2: str       # botones y elemento activo del menú
    accent: str       # enlaces
    hi: str           # resaltado en la barra lateral (logo, borde del elemento activo)
    side_ink: str     # texto de la barra lateral
    side_muted: str   # texto secundario de la barra lateral


THEMES: dict[str, Theme] = {t.key: t for t in (
    Theme("azul", "Azul", "#1f3a5f", "#2d5b8f", "#0b6bcb", "#7fb3ff", "#dbe6f3", "#a9bdd6"),
    Theme("petroleo", "Petróleo", "#123f3d", "#1b6660", "#0f766e", "#5fd4c4", "#d6eeeb", "#9cc7c2"),
    Theme("verde", "Verde", "#1d4428", "#2c6a3c", "#2e7d32", "#8fd19e", "#dcefe1", "#a6c9ae"),
    Theme("bordo", "Bordó", "#4f1626", "#7a2840", "#a3324f", "#f2a7b8", "#f3dde3", "#d1a6b2"),
    Theme("violeta", "Violeta", "#33265e", "#52409a", "#6347c0", "#c4b5fd", "#e5e0f7", "#b7aedb"),
    Theme("grafito", "Grafito", "#24282e", "#3f4650", "#2f6db0", "#9fb4cc", "#e1e5ea", "#a9b1bb"),
    Theme("cobre", "Cobre", "#44270f", "#8a4b1c", "#a64b0a", "#f6b073", "#f3e3d3", "#d2b49a"),
)}
DEFAULT = "azul"
COOKIE = "sapsec_tema"


def get(key: str | None) -> Theme:
    return THEMES.get((key or "").strip().lower(), THEMES[DEFAULT])


def valid(key: str | None) -> bool:
    return (key or "").strip().lower() in THEMES


def css() -> str:
    """Hoja de estilos con las variables de cada tema (el tema activo se elige con ``<html data-tema="…">``)."""
    out = ["/* Generado por sapsec.themes: no editar a mano. */"]
    for t in THEMES.values():
        sel = f':root,html[data-tema="{t.key}"]' if t.key == DEFAULT else f'html[data-tema="{t.key}"]'
        out.append(f"{sel}{{--brand:{t.brand};--brand2:{t.brand2};--accent:{t.accent};--hi:{t.hi};"
                   f"--side-ink:{t.side_ink};--side-muted:{t.side_muted}}}")
        out.append(f".swatch-{t.key}{{background:linear-gradient(135deg,{t.brand} 0 55%,{t.brand2} 55% 80%,{t.hi} 80%)}}")
    return "\n".join(out) + "\n"


# Escudo con cerradura (diseño propio): se ve bien desde 16 px.
SHIELD = "M32 4 L54 11 V29 C54 44.5 44.6 55.2 32 60 C19.4 55.2 10 44.5 10 29 V11 Z"
SHINE = "M32 4 L10 11 V29 C10 44.5 19.4 55.2 32 60 Z"
HOLE_C = (32, 27, 7.5)
HOLE_STEM = "M28.6 31.5 H35.4 L37.6 45 H26.4 Z"


def icon_svg(key: str | None = None) -> str:
    """Ícono para la pestaña del navegador, con los colores del tema (borde blanco: se ve en pestañas oscuras)."""
    t = get(key)
    cx, cy, r = HOLE_C
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            f'<path d="{SHIELD}" fill="{t.brand2}" stroke="#ffffff" stroke-width="3" stroke-linejoin="round"/>'
            f'<path d="{SHINE}" fill="#ffffff" fill-opacity=".14"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="#ffffff"/><path d="{HOLE_STEM}" fill="#ffffff"/></svg>')
