"""Temas de colores, modo claro/oscuro y logo de la aplicación.

Cada persona elige su tema y su modo en «Mi cuenta» (se guardan en su usuario y en cookies del navegador para la
pantalla de ingreso). Los colores salen de un solo lugar, ``THEMES`` y ``DARK``: de ahí se generan la hoja
``/temas.css``, las muestras para elegir y el ícono de la pestaña del navegador (``/icono.svg``).

Modo oscuro: el tema define el color (barra lateral, botones y, en oscuro, los enlaces con su color claro ``hi``);
el modo define las superficies (fondo, paneles, texto). «Automático» sigue la preferencia de Windows o del navegador
(``prefers-color-scheme``) sin JavaScript: la misma lista de reglas se emite dos veces.

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

MODES = {"claro": "Claro", "oscuro": "Oscuro", "auto": "Automático (como Windows)"}
DEFAULT_MODE = "claro"
MODE_COOKIE = "sapsec_modo"

# Superficies del modo oscuro (comunes a todos los temas). «§» = selector del modo (oscuro o automático).
DARK_VARS = {"--bg": "#14171c", "--panel": "#1c2027", "--soft": "#262c35", "--ink": "#e4e8ee", "--muted": "#9aa6b5",
             "--line": "#323945", "--crit": "#ff8a80", "--high": "#ffab70", "--med": "#f2c94c", "--low": "#6fcf97",
             "--info": "#a3adba"}
DARK = """
§{color-scheme:dark;%(vars)s;--accent:var(--hi)}
§ body{background:var(--bg);color:var(--ink)}
§ .topbar,§ .foot{background:var(--panel);border-color:var(--line)}
§ label,§ .qa dt,§ .tabs a,§ .fp,§ .note,§ .t-meta,§ .facts,§ .sevline,§ .reco-extra,§ .reco-impact,§ .reco-why,§ .howto b,§ .envnote{color:var(--ink)}
§ .chart text{fill:var(--ink)}
§ input,§ select,§ textarea{background:#12151a;border-color:#3d4552;color:var(--ink)}
§ .tbl{background:var(--panel)}
§ .tbl th{background:var(--soft);color:var(--ink);border-color:var(--line)}
§ .tbl td{border-color:var(--line)}
§ .tbl tr:hover td{background:#222831}
§ .pill,§ .chip{background:var(--soft);border-color:var(--line);color:var(--ink)}
§ a.chip:hover{background:#2f3641}
§ .chip.warn{background:#3a2c14;border-color:#6b4f1d}
§ .chip.bad{background:#3d1f1d;border-color:#7a3530}
§ .chip.good{background:#173226;border-color:#2c6045}
§ .sev.sev-critico{background:#3d1f1d;color:var(--crit)}
§ .sev.sev-alto{background:#3b2618;color:var(--high)}
§ .sev.sev-medio{background:#3a3115;color:var(--med)}
§ .sev.sev-bajo{background:#173226;color:var(--low)}
§ .sev.sev-informativo{background:var(--soft);color:var(--info)}
§ .cert{background:#1f2c3d;color:#9cc2f0}
§ .cert-definido_en_rol{background:#2a2340;color:#c7b6f2}
§ .rstatus-ejemplo{background:#3a2c14;color:#f2c27a}
§ .rstatus-validada{background:#173226;color:var(--low)}
§ .rstatus-aprobada{background:#1f2c3d;color:#9cc2f0}
§ .badge.warn{background:#3d1f1d;color:var(--crit)}
§ .kind{color:var(--hi);background:color-mix(in srgb,var(--hi) 14%%,var(--panel))}
§ .btn.ghost{color:var(--hi);border-color:color-mix(in srgb,var(--hi) 55%%,var(--panel))}
§ .btn.danger{background:#c0392b;border-color:#c0392b}
§ .btn.ghost.danger{background:transparent;color:var(--crit);border-color:#7a3530}
§ .note{background:#1e2733}
§ .warnbox{background:#2e2616}
§ .errbox{background:#331b1a}
§ .verdict.NO_RECOMENDADO{background:#331b1a;border-color:#7a3530;color:#ffb3ab}
§ .verdict.REQUIERE_REVISION{background:#2e2616;border-color:#6b4f1d;color:#f2d27a}
§ .verdict.APROBACION_RECOMENDADA{background:#173226;border-color:#2c6045;color:#9fe0bb}
§ .verdict-bar.sev-critico{background:#2a1c1c;border-color:#7a3530}
§ .verdict-bar.sev-alto{background:#2b2119;border-color:#6e4528}
§ .verdict-bar.sev-medio{background:#2a2617;border-color:#6b5a1d}
§ .verdict-bar.sev-bajo,§ .verdict-bar.sev-informativo{background:#17271f;border-color:#2c6045}
§ .reco{background:color-mix(in srgb,var(--rc) 9%%,var(--panel));border-color:color-mix(in srgb,var(--rc) 38%%,var(--panel));box-shadow:none}
§ .reco-foot{border-color:var(--line)}
§ .reco-label,§ .reco-steps li::before{color:#14171c}
§ .swatch-btn.on{border-color:var(--hi);box-shadow:0 0 0 2px var(--hi) inset}
§ .swatch-btn:hover,§ .mode-toggle:hover,§ .theme-dot:hover{border-color:var(--hi)}
§ .reco-note{background:#3a3115;color:#f2d27a}
§ .more-items{border-color:var(--line)}
§ .danger-zone{background:#241a1a;border-color:#7a3530}
§ .queue,§ .envnote{background:#1e2733;border-color:var(--line)}
§ .urlbox{background:var(--soft)}
§ a.task:hover{border-color:#3f4856;box-shadow:0 2px 8px rgba(0,0,0,.35)}
§ a.kpi-s:hover{border-color:#4a5566}
§ .diff-distinto td{background:#2a2617}
§ .diff-solo_A td{background:#1e2733}
§ .diff-solo_B td{background:#2a1c1c}
§ .login{background:var(--panel)}
§ .login h1{color:var(--ink)}
§ .login-logo .shield{fill:var(--hi)}
§ .login-logo .hole{fill:var(--panel)}
§ .delta.up{color:var(--crit)}
§ .delta.down{color:var(--low)}
"""


def get(key: str | None) -> Theme:
    return THEMES.get((key or "").strip().lower(), THEMES[DEFAULT])


def valid(key: str | None) -> bool:
    return (key or "").strip().lower() in THEMES


def valid_mode(mode: str | None) -> bool:
    return (mode or "").strip().lower() in MODES


def get_mode(mode: str | None) -> str:
    m = (mode or "").strip().lower()
    return m if m in MODES else DEFAULT_MODE


def dark_css(selector: str) -> str:
    rules = DARK % {"vars": ";".join(f"{k}:{v}" for k, v in DARK_VARS.items())}
    return rules.replace("§", selector)


def css() -> str:
    """Hoja de estilos: variables de cada tema (``<html data-tema="…">``) y modo oscuro (``data-modo``)."""
    out = ["/* Generado por sapsec.themes: no editar a mano. */"]
    for t in THEMES.values():
        sel = f':root,html[data-tema="{t.key}"]' if t.key == DEFAULT else f'html[data-tema="{t.key}"]'
        out.append(f"{sel}{{--brand:{t.brand};--brand2:{t.brand2};--accent:{t.accent};--hi:{t.hi};"
                   f"--side-ink:{t.side_ink};--side-muted:{t.side_muted}}}")
        out.append(f".swatch-{t.key}{{background:linear-gradient(135deg,{t.brand} 0 55%,{t.brand2} 55% 80%,{t.hi} 80%)}}")
    out.append(".swatch-modo-claro{background:linear-gradient(135deg,#f3f5f8 0 60%,#ffffff 60%)}")
    out.append(".swatch-modo-oscuro{background:linear-gradient(135deg,#14171c 0 60%,#262c35 60%)}")
    out.append(".swatch-modo-auto{background:linear-gradient(135deg,#f3f5f8 0 50%,#14171c 50%)}")
    out.append("/* Modo oscuro elegido */")
    out.append(dark_css('html[data-modo="oscuro"]'))
    out.append("/* Modo automático: oscuro si Windows o el navegador lo están */")
    out.append("@media (prefers-color-scheme: dark){" + dark_css('html[data-modo="auto"]') + "}")
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
