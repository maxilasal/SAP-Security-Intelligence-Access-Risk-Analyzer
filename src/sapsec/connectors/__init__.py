"""Fábrica de conectores RFC."""

from __future__ import annotations

from .base import ConnectionParams, LoadLimits, RfcConnector


def create_connector(backend: str, params: ConnectionParams, limits: LoadLimits | None = None,
                     fixture_path: str | None = None) -> RfcConnector:
    backend = backend.lower()
    if backend == "nwrfc":
        from .nwrfc_connector import NwRfcConnector
        return NwRfcConnector(params, limits)
    if backend == "pyrfc":
        from .pyrfc_connector import PyRfcConnector
        return PyRfcConnector(params, limits)
    if backend == "fixture":
        from .fixture_connector import FixtureConnector
        return FixtureConnector(params, limits, fixture_path=fixture_path)
    raise ValueError(f"Backend RFC desconocido: {backend}")


__all__ = ["ConnectionParams", "LoadLimits", "RfcConnector", "create_connector"]
