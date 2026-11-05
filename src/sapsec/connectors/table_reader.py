"""Lectura controlada de tablas vía RFC_READ_TABLE.

Medidas de protección:

* Lista permitida de tablas y campos (``extraction/sources.py``); campos de
  contraseñas prohibidos aunque la tabla esté permitida.
* Selección explícita de campos (nunca ``SELECT *``) y control del ancho de
  fila (512 caracteres: límite de RFC_READ_TABLE-DATA-WA).
* Lotes por clave (``WHERE campo IN (...)``) en lugar de ROWSKIPS, que en
  RFC_READ_TABLE vuelve a leer todas las filas anteriores en cada página.
* Detección de truncamiento: si un lote devuelve exactamente ROWCOUNT filas,
  se divide y se vuelve a leer.
* Interpretación por OFFSET/LENGTH devueltos por SAP (sin delimitadores que
  podrían aparecer dentro de los valores).

Limitación conocida: RFC_READ_TABLE no está liberado para clientes (SAP Note
382318). Es la opción sin desarrollos Z; el extractor Z opcional
(docs/04_extractor_z_opcional.md) elimina estas limitaciones.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Iterator, Sequence

from ..extraction.sources import FORBIDDEN_FIELDS, FORBIDDEN_TABLES, allowed_tables
from .base import RfcAbapException, RfcAuthorizationError, RfcConnector, RfcError

log = logging.getLogger(__name__)

MAX_ROW_WIDTH = 512
OPTION_LINE = 72


class TableAccessDenied(RfcError):
    pass


@dataclass(frozen=True)
class FieldMeta:
    name: str
    offset: int
    length: int
    type: str


def escape(value: str) -> str:
    return value.replace("'", "''")


def build_where(conditions: Sequence[str], in_field: str | None = None,
                in_values: Sequence[str] = ()) -> list[dict[str, str]]:
    """Construye OPTIONS respetando el ancho de 72 caracteres por línea."""
    tokens: list[str] = []
    for i, cond in enumerate(conditions):
        if i:
            tokens.append("AND")
        tokens.extend(cond.split(" "))
    if in_field and in_values:
        if tokens:
            tokens.append("AND")
        tokens += [in_field, "IN", "("]
        for j, v in enumerate(in_values):
            tokens.append(f"'{escape(v)}'" + ("," if j < len(in_values) - 1 else ""))
        tokens.append(")")
    lines: list[str] = []
    current = ""
    for tok in tokens:
        if len(tok) > OPTION_LINE:
            raise ValueError(f"Valor demasiado largo para OPTIONS: {tok}")
        candidate = f"{current} {tok}".strip()
        if len(candidate) > OPTION_LINE:
            lines.append(current)
            current = tok
        else:
            current = candidate
    if current:
        lines.append(current)
    return [{"TEXT": line} for line in lines]


class TableReader:
    def __init__(self, connector: RfcConnector):
        self.conn = connector
        self.allowed = allowed_tables()
        self.max_rows = connector.limits.max_rows_per_call
        self.batch = connector.limits.batch_size_in_list
        self.truncation_events = 0

    # ---------------------------------------------------------------------------------
    def _validate(self, table: str, fields: Sequence[str]) -> None:
        t = table.upper()
        if t in FORBIDDEN_TABLES:
            raise TableAccessDenied(f"La tabla {t} está prohibida por política")
        if t not in self.allowed:
            raise TableAccessDenied(f"La tabla {t} no está en la lista permitida")
        forbidden = FORBIDDEN_FIELDS.get(t, frozenset())
        for f in fields:
            fu = f.upper()
            if fu in forbidden or "*" in forbidden:
                raise TableAccessDenied(f"El campo {t}-{fu} está prohibido (dato sensible)")
            if fu not in self.allowed[t]:
                raise TableAccessDenied(f"El campo {t}-{fu} no está en la lista permitida")

    def _invoke(self, table: str, fields: Sequence[str], options: list[dict[str, str]],
                rowcount: int, rowskips: int = 0, no_data: bool = False) -> dict:
        try:
            return self.conn.call(
                "RFC_READ_TABLE", QUERY_TABLE=table, DELIMITER="", NO_DATA="X" if no_data else "",
                ROWCOUNT=rowcount, ROWSKIPS=rowskips,
                FIELDS=[{"FIELDNAME": f} for f in fields], OPTIONS=options)
        except RfcAbapException as exc:
            if exc.key in ("NOT_AUTHORIZED",):
                raise RfcAuthorizationError(
                    f"Sin autorización de lectura para {table} (S_TABU_NAM ACTVT=03 TABLE={table})",
                    key=exc.key) from exc
            raise

    def describe(self, table: str, fields: Sequence[str]) -> list[FieldMeta]:
        self._validate(table, fields)
        res = self._invoke(table, fields, [], rowcount=1, no_data=True)
        metas = [FieldMeta(r["FIELDNAME"].strip(), int(r["OFFSET"]), int(r["LENGTH"]), r.get("TYPE", ""))
                 for r in res.get("FIELDS", [])]
        width = max((m.offset + m.length for m in metas), default=0)
        if width > MAX_ROW_WIDTH:
            raise RfcError(f"La selección de {table} ocupa {width} caracteres (> {MAX_ROW_WIDTH}); "
                           "reduzca campos o use el extractor Z.")
        return metas

    def read(self, table: str, fields: Sequence[str], where: Sequence[str] = (),
             in_field: str | None = None, in_values: Sequence[str] = ()) -> list[dict[str, str]]:
        """Lee una selección completa. Divide automáticamente si detecta truncamiento."""
        self._validate(table, fields)
        options = build_where(where, in_field, in_values)
        res = self._invoke(table, fields, options, rowcount=self.max_rows)
        rows = self._parse(res)
        if len(rows) >= self.max_rows:
            self.truncation_events += 1
            if in_field and len(in_values) > 1:
                mid = len(in_values) // 2
                log.info("Lote de %s truncado; se divide (%d claves)", table, len(in_values))
                return (self.read(table, fields, where, in_field, in_values[:mid])
                        + self.read(table, fields, where, in_field, in_values[mid:]))
            log.warning("Selección de %s supera %d filas con una sola clave: se pagina con ROWSKIPS",
                        table, self.max_rows)
            skips = len(rows)
            while True:
                page = self._parse(self._invoke(table, fields, options, rowcount=self.max_rows,
                                                rowskips=skips))
                rows += page
                skips += len(page)
                if len(page) < self.max_rows:
                    break
        return rows

    def read_partitioned(self, table: str, fields: Sequence[str], key_field: str,
                         keys: Iterable[str], where: Sequence[str] = ()) -> Iterator[list[dict[str, str]]]:
        unique = sorted({k for k in keys if k})
        for i in range(0, len(unique), self.batch):
            yield self.read(table, fields, where, key_field, unique[i:i + self.batch])

    @staticmethod
    def _parse(res: dict) -> list[dict[str, str]]:
        metas = [(r["FIELDNAME"].strip(), int(r["OFFSET"]), int(r["LENGTH"])) for r in res.get("FIELDS", [])]
        out = []
        for row in res.get("DATA", []):
            wa = row["WA"]
            out.append({n: wa[o:o + ln].rstrip() for n, o, ln in metas})
        return out
