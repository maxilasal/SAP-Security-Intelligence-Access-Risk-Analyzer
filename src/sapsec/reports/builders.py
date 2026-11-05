"""Construcción de reportes a partir de resultados de análisis y hallazgos."""

from __future__ import annotations

from typing import Iterable

from ..engine.analysis import UserAnalysis
from ..engine.simulator import SimulationResult
from ..storage.orm import Finding, Snapshot
from .exporters import STANDARD_LIMITATIONS, ReportDoc, Section, Table


def snapshot_meta(snap: Snapshot, scope: str, rules_hash: str = "") -> dict[str, str]:
    meta = {
        "Sistema": f"{snap.connection.system.label} ({snap.sid})" if snap.connection else snap.sid,
        "Ambiente": (snap.connection.system.environment if snap.connection else "") or "",
        "Mandante": snap.client,
        "Fecha de los datos (snapshot)": f"{snap.started_at:%Y-%m-%d %H:%M} (snapshot #{snap.id})",
        "Estado del snapshot": snap.status, "Alcance": scope,
        "Hash del conjunto de reglas": rules_hash or snap.ruleset_hash or "n/d",
        "Origen de los datos": "DATOS DE PRUEBA (conector ficticio)" if snap.is_test_data
        else f"SAP vía RFC ({snap.backend})",
    }
    return meta


def _limitations(snap: Snapshot) -> list[str]:
    lims = list(STANDARD_LIMITATIONS)
    if snap.status != "completo":
        lims.insert(0, "El snapshot está INCOMPLETO: " + "; ".join(i.get("message", "") for i in snap.issues or []))
    if snap.is_test_data:
        lims.insert(0, "ESTE INFORME SE BASA EN DATOS FICTICIOS DE PRUEBA.")
    return lims


def findings_report(snap: Snapshot, findings: Iterable[Finding], title: str, scope: str) -> ReportDoc:
    rows = [[f.code, f.severity, f.kind, f.rule_id, f.rule_status, f.title, f.subject_user or "", f.subject_role or "",
             f.roles_responsible, f.certainty, f.status, f.recommendation, f.detected_at.strftime("%Y-%m-%d")]
            for f in findings]
    cols = ["Hallazgo", "Gravedad", "Tipo", "Regla", "Estado regla", "Título", "Usuario", "Rol", "Roles responsables",
            "Certeza", "Estado", "Recomendación", "Detectado"]
    return ReportDoc(title, snapshot_meta(snap, scope), _limitations(snap),
                     [Section("Hallazgos", [f"Total: {len(rows)}"], Table(cols, rows))])


def user_report(snap: Snapshot, a: UserAnalysis) -> ReportDoc:
    u = a.eff.user
    secs = [Section("Usuario", [
        f"Usuario: {a.username} — {u.full_name if u else ''}",
        f"Tipo: {u.type_label if u else '?'} | Grupo: {u.user_group if u else ''} | {u.lock_label if u else ''}",
        f"Último acceso: {u.last_logon if u and u.last_logon else 'sin dato'}",
        f"Riesgo inherente: {a.risk.inherent_level.label} ({a.risk.inherent_score}) | actual: "
        f"{a.risk.current_level.label} ({a.risk.current_score}) | residual: {a.risk.residual_level.label} "
        f"({a.risk.residual_score})", *a.risk.notes])]
    secs.append(Section("Roles", table=Table(["Rol", "Desde", "Hasta", "Estado", "Heredado de compuesto"], [
        [x.role, x.valid_from, x.valid_to, x.state(a.eff.as_of), x.via_composite or ""] for x in a.eff.assignments])))
    secs.append(Section("Autorizaciones críticas", table=Table(
        ["Regla", "Gravedad", "Título", "Roles", "Certeza", "Evidencia"],
        [[h.rule_id, h.severity.label, h.title, h.roles, h.certainty.label,
          " | ".join(f"{e.values} ← {e.provenance}" for e in h.evidence[:5])] for h in a.critical])))
    secs.append(Section("Conflictos SoD", table=Table(
        ["Riesgo", "Gravedad", "Título", "Alcance", "Explicación", "Organización"],
        [[h.risk_id, h.severity.label, h.title, h.scope, h.explanation, " ".join(h.org_analysis)] for h in a.sod])))
    secs.append(Section("Autorizaciones efectivas", table=Table(
        ["Objeto", "Autorización", "Valores", "Procedencia"],
        [[e.instance.object, e.instance.auth, e.instance.as_text(), e.provenance()]
         for e in sorted(a.eff.instances.values(), key=lambda x: x.instance.key)])))
    secs.append(Section("Observaciones de consistencia", table=Table(
        ["Código", "Gravedad", "Mensaje"], [[i.code, i.severity.label, i.message] for i in a.issues])))
    return ReportDoc(f"Auditoría de usuario {a.username}", snapshot_meta(snap, f"Usuario {a.username}"),
                     _limitations(snap), secs)


def simulation_report(snap: Snapshot, r: SimulationResult, evaluated_at: str, executive: bool = False) -> ReportDoc:
    title = ("Informe ejecutivo" if executive else "Informe técnico") + f" de simulación — {r.username}"
    exec_sec = Section("Resultado", [
        f"Usuario: {r.username} | Sistema: {snap.sid} / {snap.client} | Evaluación: {evaluated_at}",
        f"Escenario: {r.scenario.describe()}",
        f"Riesgo actual: {r.before.risk.inherent_level.label} ({r.before.risk.inherent_score})",
        f"Riesgo simulado: {r.after.risk.inherent_level.label} ({r.after.risk.inherent_score})",
        f"Resultado: {r.recommendation_label}",
        "Motivos:", *[f"• {x}" for x in r.reasons],
        "Medidas sugeridas:", *[f"• {x}" for x in r.measures],
        "La recomendación es orientativa y no sustituye la decisión del responsable de seguridad.",
    ])
    secs = [exec_sec]
    if r.alternatives:
        secs.append(Section("Alternativas con menos riesgo (validar funcionalmente)", table=Table(
            ["Rol", "Descripción", "Cobertura transacciones", "Faltantes", "Nuevos críticos", "Nuevos SoD", "Confianza"],
            [[a.role, a.description, f"{a.tcode_coverage:.0%}", a.missing_tcodes, a.new_critical, a.new_sod,
              a.confidence] for a in r.alternatives])))
    if not executive:
        secs.append(Section("Nuevos conflictos SoD — evidencia", table=Table(
            ["Riesgo", "Función", "Acción/Tcode", "Roles", "Objeto/valores", "Procedencia"],
            [[h.risk_id, m.title, f"{m.action_id} {', '.join(m.tcodes)}", m.roles, ev.values, ev.provenance]
             for h in r.new_sod for m in h.functions for ev in m.evidence])))
        secs.append(Section("Nuevas autorizaciones críticas — evidencia", table=Table(
            ["Regla", "Gravedad", "Requisito", "Objeto/valores", "Procedencia"],
            [[h.rule_id, h.severity.label, ev.requirement, ev.values, ev.provenance]
             for h in r.new_critical for ev in h.evidence])))
        secs.append(Section("Conflictos SoD preexistentes", table=Table(
            ["Riesgo", "Título", "Roles"], [[h.risk_id, h.title, h.roles] for h in r.preexisting_sod])))
        secs.append(Section("Permisos que incorpora el escenario", table=Table(
            ["Objeto", "Autorización", "Valores", "Rol", "Certeza", "Ya cubierto", "Objeto crítico"],
            [[p.object, p.auth, p.values, p.role, p.certainty, "sí" if p.already_covered else "no",
              "sí" if p.critical_object else ""] for p in r.new_permissions])))
        secs.append(Section("Calidad de datos y observaciones", table=Table(
            ["Código", "Mensaje"], [[i.code, i.message] for i in r.issues])))
    return ReportDoc(title, snapshot_meta(snap, f"Simulación: {r.scenario.describe()}"), _limitations(snap), secs)


def executive_report(snap: Snapshot, stats: dict, top: list[Finding]) -> ReportDoc:
    secs = [Section("Indicadores", table=Table(["Indicador", "Valor"], [
        ["Usuarios analizados", stats["usuarios"]], ["Usuarios privilegiados", stats["privilegiados"]],
        ["Usuarios con SAP_ALL", stats["sap_all"]], ["Roles analizados", stats["roles"]],
        ["Roles con autorizaciones críticas", stats["roles_criticos"]], ["Conflictos SoD (usuarios)", stats["sod"]],
        ["Hallazgos críticos", stats["criticos"]], ["Hallazgos altos", stats["altos"]],
        ["Hallazgos pendientes", stats["pendientes"]]])),
        Section("Principales hallazgos", table=Table(["Hallazgo", "Gravedad", "Título", "Usuario/Rol", "Recomendación"],
                                                      [[f.code, f.severity, f.title, f.subject_user or f.subject_role,
                                                        f.recommendation] for f in top]))]
    return ReportDoc("Informe ejecutivo de seguridad SAP", snapshot_meta(snap, "Todos los usuarios y roles del snapshot"),
                     _limitations(snap), secs)
