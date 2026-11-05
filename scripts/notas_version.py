"""Imprime las notas de una versión tomadas de CHANGELOG.md (las usa la publicación automática).

Uso: python scripts/notas_version.py [VERSION]   (sin VERSION: la de pyproject.toml)
Termina con error si la versión no tiene su sección «## [X.Y.Z]» en el CHANGELOG.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def project_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def notes(version: str) -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|^\[[^\]]+\]: |\Z)", text, re.S | re.M)
    if not m or not m.group(1).strip():
        raise SystemExit(f"CHANGELOG.md no tiene la sección «## [{version}]» con el detalle de la versión.")
    return m.group(1).strip() + "\n"


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    print(notes(sys.argv[1] if len(sys.argv) > 1 else project_version()), end="")
