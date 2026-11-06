"""Temas de colores: todos legibles (contraste WCAG AA) y un ícono propio por tema."""

from __future__ import annotations

from sapsec import themes


def _lum(color: str) -> float:
    r, g, b = (int(color.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4))
    f = (lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def _contrast(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_every_theme_is_readable():
    for t in themes.THEMES.values():
        assert _contrast(t.accent, "#ffffff") >= 4.5, (t.key, "enlaces sobre blanco")
        assert _contrast(t.accent, "#f3f5f8") >= 4.5, (t.key, "enlaces sobre el fondo")
        assert _contrast("#ffffff", t.brand2) >= 4.5, (t.key, "texto de los botones")
        assert _contrast(t.side_ink, t.brand) >= 7, (t.key, "menú lateral")
        assert _contrast(t.side_muted, t.brand) >= 4.5, (t.key, "texto secundario del menú")
        assert _contrast(t.hi, t.brand) >= 3, (t.key, "logo y resaltado del menú")


def test_css_and_icon_come_from_the_same_colors():
    css = themes.css()
    for t in themes.THEMES.values():
        assert f'html[data-tema="{t.key}"]' in css and f"--brand2:{t.brand2}" in css and f".swatch-{t.key}" in css
        assert t.brand2 in themes.icon_svg(t.key)
    assert themes.get("no-existe").key == themes.DEFAULT and not themes.valid("no-existe")
    assert themes.icon_svg().startswith("<svg") and themes.THEMES[themes.DEFAULT].brand2 in themes.icon_svg("x")


def test_dark_mode_is_readable_with_every_theme():
    d = themes.DARK_VARS
    assert _contrast(d["--ink"], d["--panel"]) >= 7 and _contrast(d["--ink"], d["--bg"]) >= 7
    for k in ("--muted", "--crit", "--high", "--med", "--low", "--info"):
        assert _contrast(d[k], d["--panel"]) >= 4.5, k
        assert _contrast(d[k], d["--soft"]) >= 4.5, k
    for t in themes.THEMES.values():  # en oscuro los enlaces usan el color claro del tema
        assert _contrast(t.hi, d["--panel"]) >= 4.5 and _contrast(t.hi, d["--bg"]) >= 4.5, t.key


def test_dark_mode_rules_for_chosen_and_automatic_mode():
    css = themes.css()
    assert "§" not in css and 'html[data-modo="oscuro"]{color-scheme:dark' in css
    auto = css[css.index("@media (prefers-color-scheme: dark)"):]
    assert 'html[data-modo="auto"]{color-scheme:dark' in auto and 'html[data-modo="auto"] .tbl th' in auto
    assert themes.get_mode("inventado") == themes.DEFAULT_MODE and themes.valid_mode("auto")
