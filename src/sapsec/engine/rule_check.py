"""Validación de las reglas contra el propio sistema SAP (sin depender de matrices externas).

Para cada acción de cada función SoD (y cada regla crítica con transacciones) se verifica:

* que las transacciones existan en el sistema (TSTC);
* que los objetos de autorización existan (TOBJ);
* que la SU24 del propio sistema (USOBX_C) indique que la transacción verifica el objeto.

Resultado por acción:
  ``confirmada_su24``  – todas las transacciones/objetos existen y SU24 confirma la relación.
  ``sin_confirmar``    – existen, pero SU24 no confirma la relación (puede verificarse en el código
                         sin estar en SU24: requiere prueba con traza STAUTHTRACE).
  ``solo_objetos``     – acción sin transacción (vía Fiori/API): se evalúa por objetos.
  ``referencia_inexistente`` – transacción u objeto que no existe en este sistema: la regla no detecta nada.
  ``sin_datos``        – el snapshot no tiene TSTC/TOBJ/SU24 para evaluar.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..storage.snapshot_data import SnapshotData
from .rules import RuleSet

OK_FLAGS = {"X", "Y"}


@dataclass
class ActionCheck:
    function_id: str
    function_title: str
    action_id: str
    confidence: str
    verify: str
    tcodes_ok: list[str] = field(default_factory=list)
    tcodes_missing: list[str] = field(default_factory=list)
    objects_missing: list[str] = field(default_factory=list)
    su24_confirmed: list[str] = field(default_factory=list)     # "TCODE→OBJETO"
    su24_unconfirmed: list[str] = field(default_factory=list)
    status: str = "sin_datos"

    @property
    def label(self) -> str:
        return {"confirmada_su24": "Confirmada por SU24 del sistema",
                "sin_confirmar": "Existe, SU24 no lo confirma",
                "solo_objetos": "Solo objetos (vía Fiori/API)",
                "referencia_inexistente": "Transacción u objeto inexistente",
                "sin_datos": "Sin datos para verificar"}[self.status]


def check_rules(rules: RuleSet, data: SnapshotData) -> list[ActionCheck]:
    have_tstc = bool(data.tcode_program)
    have_tobj = bool(data.object_fields)
    out: list[ActionCheck] = []
    for fn in rules.functions.values():
        for a in fn.actions:
            c = ActionCheck(fn.id, fn.title, a.id, fn.confidence, fn.verify)
            objs = [q.object for q in a.requirements]
            if have_tobj:
                c.objects_missing = [o for o in objs if o not in data.object_fields]
            if have_tstc:
                c.tcodes_ok = [t for t in a.tcodes if t in data.tcode_program]
                c.tcodes_missing = [t for t in a.tcodes if t not in data.tcode_program]
            for t in c.tcodes_ok:
                for o in objs:
                    flag = data.su24_check.get((t, o))
                    (c.su24_confirmed if flag in OK_FLAGS else c.su24_unconfirmed).append(f"{t}→{o}")
            if c.objects_missing or (a.tcodes and have_tstc and not c.tcodes_ok):
                c.status = "referencia_inexistente"
            elif not a.tcodes:
                c.status = "solo_objetos" if have_tobj else "sin_datos"
            elif not (have_tstc and have_tobj):
                c.status = "sin_datos"
            elif data.su24_loaded and all(
                    any(data.su24_check.get((t, o)) in OK_FLAGS for t in c.tcodes_ok) for o in objs):
                c.status = "confirmada_su24"
            else:
                c.status = "sin_confirmar"
            out.append(c)
    return out


def summarize(checks: list[ActionCheck]) -> dict[str, int]:
    res: dict[str, int] = {}
    for c in checks:
        res[c.status] = res.get(c.status, 0) + 1
    return res
