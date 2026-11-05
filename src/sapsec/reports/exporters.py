"""Modelo de reporte y exportadores (CSV, Excel, HTML, PDF).

Todo reporte incluye obligatoriamente: fecha de los datos, sistema, mandante,
alcance, versión/hash de reglas, limitaciones y si los datos son de prueba.
"""

from __future__ import annotations

import csv
import html
import io
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Table:
    columns: list[str]
    rows: list[list[Any]]


@dataclass
class Section:
    heading: str
    paragraphs: list[str] = field(default_factory=list)
    table: Table | None = None


@dataclass
class ReportDoc:
    title: str
    meta: dict[str, str]
    limitations: list[str]
    sections: list[Section]
    generated_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def meta_rows(self) -> list[tuple[str, str]]:
        return [("Informe", self.title), ("Generado", self.generated_at), *self.meta.items()]


STANDARD_LIMITATIONS = [
    "Las autorizaciones se reconstruyen desde el maestro de usuarios (UST04/UST10S/UST12). Indican capacidad "
    "potencial; la ejecución real depende de los AUTHORITY-CHECK implementados en cada programa o servicio.",
    "Las reglas críticas y SoD en estado 'ejemplo' no han sido validadas ni aprobadas por la organización.",
    "Una autorización de inicio (S_TCODE, S_SERVICE, S_START) no implica autorización de negocio en backend.",
    "Las recomendaciones son orientativas y no sustituyen la decisión del responsable de seguridad.",
]


def _cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        return ", ".join(str(x) for x in v)
    return str(v)


def to_csv(doc: ReportDoc) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    for k, v in doc.meta_rows():
        w.writerow([f"# {k}", v])
    for lim in doc.limitations:
        w.writerow(["# Limitación", lim])
    for s in doc.sections:
        if s.table:
            w.writerow([])
            w.writerow([f"## {s.heading}"])
            w.writerow(s.table.columns)
            for r in s.table.rows:
                w.writerow([_cell(c) for c in r])
    return ("﻿" + buf.getvalue()).encode("utf-8")  # BOM para Excel en Windows


def to_xlsx(doc: ReportDoc) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Metadatos"
    bold = Font(bold=True)
    for k, v in doc.meta_rows():
        ws.append([k, v])
        ws.cell(ws.max_row, 1).font = bold
    ws.append([])
    ws.append(["Limitaciones"])
    ws.cell(ws.max_row, 1).font = bold
    for lim in doc.limitations:
        ws.append(["", lim])
    ws.column_dimensions["A"].width = 28
    ws.column_dimensions["B"].width = 120
    head_fill = PatternFill("solid", fgColor="1F3A5F")
    used: set[str] = set()
    for s in doc.sections:
        if not s.table:
            continue
        name = "".join(ch for ch in s.heading if ch not in "[]:*?/\\")[:28] or "Datos"
        base, i = name, 1
        while name in used:
            i += 1
            name = f"{base[:25]}_{i}"
        used.add(name)
        sh = wb.create_sheet(name)
        sh.append(s.table.columns)
        for c in range(1, len(s.table.columns) + 1):
            cell = sh.cell(1, c)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = head_fill
        for r in s.table.rows:
            sh.append([_cell(x) for x in r])
        for c, col in enumerate(s.table.columns, start=1):
            width = max([len(str(col))] + [len(_cell(r[c - 1])) for r in s.table.rows[:200]]) + 2
            sh.column_dimensions[get_column_letter(c)].width = min(width, 80)
        for row in sh.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
        sh.freeze_panes = "A2"
        sh.auto_filter.ref = sh.dimensions
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def to_html(doc: ReportDoc) -> bytes:
    e = html.escape
    parts = [f"<!doctype html><html lang='es'><head><meta charset='utf-8'><title>{e(doc.title)}</title>",
             "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b2430}"
             "h1{color:#1f3a5f}table{border-collapse:collapse;width:100%;margin:8px 0 20px}"
             "th{background:#1f3a5f;color:#fff;text-align:left}th,td{border:1px solid #cfd6df;padding:5px 7px;"
             "font-size:12px;vertical-align:top}.meta td:first-child{font-weight:600;width:220px}"
             ".lim{background:#fff7e6;border-left:4px solid #e8a33d;padding:8px 12px}</style></head><body>",
             f"<h1>{e(doc.title)}</h1><table class='meta'>"]
    parts += [f"<tr><td>{e(k)}</td><td>{e(str(v))}</td></tr>" for k, v in doc.meta_rows()]
    parts.append("</table><div class='lim'><b>Limitaciones</b><ul>")
    parts += [f"<li>{e(lim)}</li>" for lim in doc.limitations]
    parts.append("</ul></div>")
    for s in doc.sections:
        parts.append(f"<h2>{e(s.heading)}</h2>")
        parts += [f"<p>{e(p)}</p>" for p in s.paragraphs]
        if s.table:
            parts.append("<table><tr>" + "".join(f"<th>{e(c)}</th>" for c in s.table.columns) + "</tr>")
            for r in s.table.rows:
                parts.append("<tr>" + "".join(f"<td>{e(_cell(c))}</td>" for c in r) + "</tr>")
            parts.append("</table>")
    parts.append("</body></html>")
    return "".join(parts).encode("utf-8")


def to_pdf(doc: ReportDoc) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle

    out = io.BytesIO()
    pdf = SimpleDocTemplate(out, pagesize=landscape(A4), leftMargin=1.5 * cm, rightMargin=1.5 * cm,
                            topMargin=1.5 * cm, bottomMargin=1.5 * cm, title=doc.title)
    ss = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=ss["BodyText"], fontSize=7.5, leading=9)
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9, leading=11.5)
    e = html.escape
    story: list[Any] = [Paragraph(e(doc.title), ss["Title"])]
    meta = LongTable([[Paragraph(f"<b>{e(k)}</b>", small), Paragraph(e(str(v)), small)] for k, v in doc.meta_rows()],
                     colWidths=[5 * cm, 20 * cm])
    meta.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey)]))
    story += [meta, Spacer(1, 8), Paragraph("<b>Limitaciones</b>", body)]
    story += [Paragraph("• " + e(lim), small) for lim in doc.limitations]
    width = landscape(A4)[0] - 3 * cm
    for s in doc.sections:
        story += [Spacer(1, 10), Paragraph(e(s.heading), ss["Heading2"])]
        story += [Paragraph(e(p), body) for p in s.paragraphs]
        if s.table and s.table.rows:
            n = len(s.table.columns)
            data = [[Paragraph(f"<b>{e(c)}</b>", small) for c in s.table.columns]]
            data += [[Paragraph(e(_cell(c))[:1500], small) for c in r] for r in s.table.rows[:2000]]
            t = LongTable(data, colWidths=[width / n] * n, repeatRows=1)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                                   ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                   ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9AA5B1")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            # el encabezado usa Paragraph: forzar color blanco
            for cell in data[0]:
                cell.style = ParagraphStyle("h", parent=small, textColor=colors.white)
            story.append(t)
    pdf.build(story)
    return out.getvalue()


EXPORTERS = {
    "csv": (to_csv, "text/csv; charset=utf-8"),
    "xlsx": (to_xlsx, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "html": (to_html, "text/html; charset=utf-8"),
    "pdf": (to_pdf, "application/pdf"),
}
