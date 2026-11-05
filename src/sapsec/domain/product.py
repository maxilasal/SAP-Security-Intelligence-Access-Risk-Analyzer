"""Producto SAP del sistema a partir de sus componentes de software (tabla CVERS).

Solo se usan nombres de componentes estándar: S4CORE (S/4HANA), SAP_APPL (ECC/ERP),
SAP_BASIS (NetWeaver), SAP_GWFND (Gateway/OData) y SAP_UI (Fiori launchpad / UI5).
"""

from __future__ import annotations

from typing import Any


def describe(cvers: list[dict[str, str]]) -> dict[str, Any]:
    comps = {(r.get("component") or r.get("COMPONENT") or "").strip(): (r.get("release") or r.get("RELEASE") or "").strip()
             for r in cvers}
    comps.pop("", None)
    if not comps:
        return {}
    if "S4CORE" in comps:
        kind, label = "S4", f"SAP S/4HANA (S4CORE {comps['S4CORE']})"
    elif "SAP_APPL" in comps:
        kind, label = "ECC", f"SAP ERP / ECC (SAP_APPL {comps['SAP_APPL']})"
    elif "SAP_UI" in comps or "SAP_GWFND" in comps:
        kind, label = "FES", "Servidor Fiori / Gateway (front-end)"
    else:
        kind, label = "NW", f"SAP NetWeaver (SAP_BASIS {comps.get('SAP_BASIS', '?')})"
    fiori = "SAP_UI" in comps or "SAP_GWFND" in comps
    return {"kind": kind, "label": label, "fiori": fiori,
            "fiori_label": (f"Fiori/Gateway: SAP_UI {comps.get('SAP_UI', '—')} · SAP_GWFND {comps.get('SAP_GWFND', '—')}"
                            if fiori else ""),
            "components": {k: comps[k] for k in sorted(comps) if k in
                           ("SAP_BASIS", "SAP_ABA", "SAP_APPL", "S4CORE", "S4FND", "SAP_GWFND", "SAP_UI", "UIS4HOP1",
                            "UIAPFI70", "SAP_HR", "EA-APPL")}}
