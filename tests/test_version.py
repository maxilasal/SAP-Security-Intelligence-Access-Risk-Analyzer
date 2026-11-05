"""La versión es una sola: pyproject.toml, el paquete y el CHANGELOG (de ahí salen el tag y la Release)."""

from __future__ import annotations

import subprocess
import sys
import tomllib

from conftest import ROOT


def test_version_is_consistent_and_documented():
    import sapsec
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert sapsec.__version__ == version, "subir la versión en pyproject.toml y en src/sapsec/__init__.py a la vez"
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "notas_version.py")], capture_output=True,
                         text=True, encoding="utf-8", errors="replace", check=True).stdout
    assert out.strip(), f"CHANGELOG.md debe tener la sección «## [{version}]»"


def test_release_notes_missing_version_fails():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "notas_version.py"), "99.0.0"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    assert r.returncode != 0 and "99.0.0" in (r.stderr or "") + (r.stdout or "")
