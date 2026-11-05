"""Semántica de valores de campos de autorización SAP.

Reglas implementadas (comportamiento del AUTHORITY-CHECK sobre el buffer de usuario):

* Un AUTHORITY-CHECK tiene éxito si existe AL MENOS UNA instancia del objeto en la
  que TODOS los campos verificados cubren el valor solicitado. Los campos de
  instancias distintas no se combinan.
* ``*`` en solitario cubre cualquier valor (incluido el vacío).
* ``ABC*`` cubre los valores que comienzan con ``ABC`` (genérico por prefijo).
* ``VON``–``BIS`` definen un intervalo con comparación de caracteres.
* ``' '`` (comillas con espacio) autoriza explícitamente el valor vacío.
* Un campo sin valores no autoriza nada salvo chequeos con ``DUMMY``.
* Una variable organizativa sin resolver (``$BUKRS``) no autoriza nada.

Esto describe el comportamiento estándar documentado; los chequeos que cada
programa realiza (qué campos, qué valores, si usa DUMMY) dependen del código de
la aplicación y por eso los resultados se califican como *capacidad potencial*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

DUMMY = object()  # marcador: el chequeo no verifica este campo


@dataclass(frozen=True)
class FieldValue:
    low: str
    high: str = ""

    @property
    def is_full_wildcard(self) -> bool:
        return self.low == "*" and not self.high

    @property
    def is_unresolved_variable(self) -> bool:
        return self.low.startswith("$")

    @property
    def is_generic(self) -> bool:
        """Comodín total, prefijo genérico o intervalo."""
        return self.is_full_wildcard or self.low.endswith("*") or bool(self.high)

    def covers(self, value: str) -> bool:
        if self.is_unresolved_variable:
            return False
        if self.is_full_wildcard:
            return True
        if self.low == "' '":
            return value.strip() == ""
        if self.high:
            return self.low <= value <= self.high
        if self.low.endswith("*"):
            return value.startswith(self.low[:-1])
        return value == self.low

    def contains(self, other: "FieldValue") -> bool:
        """¿Este valor autoriza todo lo que autoriza ``other``? (subsunción)."""
        if self.is_unresolved_variable:
            return False
        if self.is_full_wildcard:
            return True
        if other.is_unresolved_variable:
            return True  # ``other`` no autoriza nada
        if other.is_full_wildcard:
            return False
        if other.high:
            if self.high:
                return self.low <= other.low and other.high <= self.high
            return False
        if other.low.endswith("*"):
            prefix = other.low[:-1]
            return self.low.endswith("*") and not self.high and prefix.startswith(self.low[:-1])
        return self.covers(other.low)

    def __str__(self) -> str:
        return f"{self.low}–{self.high}" if self.high else self.low


@dataclass
class AuthInstance:
    """Instancia (objeto, autorización) con sus valores por campo."""

    object: str
    auth: str
    fields: dict[str, list[FieldValue]] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        return (self.object, self.auth)

    def values(self, field_name: str) -> list[FieldValue]:
        return self.fields.get(field_name, [])

    def field_covers(self, field_name: str, value: str) -> bool:
        return any(v.covers(value) for v in self.values(field_name))

    def field_is_full_wildcard(self, field_name: str) -> bool:
        return any(v.is_full_wildcard for v in self.values(field_name))

    def field_is_generic(self, field_name: str) -> bool:
        return any(v.is_generic for v in self.values(field_name))

    def subsumes(self, other: "AuthInstance") -> bool:
        """True si esta instancia autoriza todo lo que autoriza ``other`` (mismo objeto)."""
        if self.object != other.object:
            return False
        for fname, ovals in other.fields.items():
            mine = self.values(fname)
            if not all(any(m.contains(o) for m in mine) for o in ovals):
                return False
        return True

    def check(self, requested: dict[str, object]) -> bool:
        """Simula un AUTHORITY-CHECK con valores concretos (o DUMMY) sobre esta instancia."""
        for fname, val in requested.items():
            if val is DUMMY:
                continue
            if not self.field_covers(fname, str(val)):
                return False
        return True

    def as_text(self) -> str:
        parts = [f"{f}=" + ",".join(str(v) for v in vals) for f, vals in sorted(self.fields.items())]
        return f"{self.object} [{self.auth}] " + "; ".join(parts)


@dataclass(frozen=True)
class FieldCondition:
    """Condición sobre un campo usada por reglas críticas y SoD.

    Modos:
      * ``any_of``: la instancia cubre al menos uno de ``values``.
      * ``all_of``: la instancia cubre todos los ``values``.
      * ``full_wildcard``: el campo contiene ``*``.
      * ``generic``: el campo contiene ``*``, un prefijo genérico o un intervalo.
      * ``present``: el campo tiene al menos un valor resoluble.
    """

    mode: str
    values: tuple[str, ...] = ()

    def matches(self, inst: AuthInstance, field_name: str) -> bool:
        vals = inst.values(field_name)
        if self.mode == "any_of":
            return any(inst.field_covers(field_name, v) for v in self.values)
        if self.mode == "all_of":
            return all(inst.field_covers(field_name, v) for v in self.values)
        if self.mode == "full_wildcard":
            return inst.field_is_full_wildcard(field_name)
        if self.mode == "generic":
            return inst.field_is_generic(field_name)
        if self.mode == "present":
            return any(not v.is_unresolved_variable for v in vals)
        raise ValueError(f"Modo de condición desconocido: {self.mode}")

    def describe(self) -> str:
        if self.mode in ("any_of", "all_of"):
            sep = " o " if self.mode == "any_of" else " y "
            return sep.join(self.values)
        return {"full_wildcard": "* (comodín total)", "generic": "valor genérico (*, prefijo o rango)",
                "present": "cualquier valor"}[self.mode]


@dataclass(frozen=True)
class Requirement:
    """Requisito sobre UN objeto: todas las condiciones deben cumplirse en la MISMA instancia."""

    object: str
    conditions: tuple[tuple[str, FieldCondition], ...]

    def matching_instances(self, instances: Iterable[AuthInstance]) -> list[AuthInstance]:
        return [i for i in instances if i.object == self.object
                and all(c.matches(i, f) for f, c in self.conditions)]

    def describe(self) -> str:
        conds = ", ".join(f"{f} = {c.describe()}" for f, c in self.conditions)
        return f"{self.object} ({conds})" if conds else self.object


def parse_condition(spec: object) -> FieldCondition:
    """Convierte la notación YAML a FieldCondition.

    Ejemplos aceptados::

        ACTVT: ["01", "02"]          -> any_of
        ACTVT: {all_of: ["01","02"]}
        TABLE: "*"                   -> full_wildcard
        TCD: {mode: generic}
        BUKRS: {mode: present}
    """
    if isinstance(spec, str):
        return FieldCondition("full_wildcard") if spec == "*" else FieldCondition("any_of", (spec,))
    if isinstance(spec, (list, tuple)):
        return FieldCondition("any_of", tuple(str(v) for v in spec))
    if isinstance(spec, dict):
        if "all_of" in spec:
            return FieldCondition("all_of", tuple(str(v) for v in spec["all_of"]))
        if "any_of" in spec:
            return FieldCondition("any_of", tuple(str(v) for v in spec["any_of"]))
        mode = spec.get("mode")
        if mode in ("full_wildcard", "generic", "present"):
            return FieldCondition(mode)
    raise ValueError(f"Especificación de condición inválida: {spec!r}")


def parse_requirement(spec: dict) -> Requirement:
    obj = spec["object"]
    fields = spec.get("fields", {}) or {}
    return Requirement(obj, tuple((f, parse_condition(c)) for f, c in fields.items()))
