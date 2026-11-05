"""Servicios de aplicación: orquestan conectores, extracción, motores y persistencia."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from datetime import date, datetime
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .connectors import ConnectionParams, LoadLimits, create_connector
from .connectors.base import ALLOWED_FUNCTIONS, RfcAuthorizationError, RfcConnector, RfcError
from .connectors.table_reader import TableReader
from .engine.analysis import AnalysisContext, analyze_role, analyze_user
from .engine.rules import RuleSet, load_rules
from .extraction.extractor import Extractor
from .extraction.sources import DATASETS
from .security.secrets import get_password
from .storage.db import get_engine
from .storage.orm import EmergencyUser, Finding, Mitigation, SapConnection, SapSystem, Snapshot, utcnow
from .storage.snapshot_data import SnapshotData, get_snapshot_data
from .engine import incompat as _incompat

log = logging.getLogger(__name__)

_rules_cache: dict[str, RuleSet] = {}


def _init_cache_dir() -> None:
    try:
        _incompat.CACHE_DIR = Path(get_settings().log_dir).parent / "cache"
    except Exception:  # noqa: BLE001
        pass


_init_cache_dir()


def get_rules() -> RuleSet:
    """Carga las reglas; se recargan si cambia el contenido (hash)."""
    rs = load_rules(get_settings().rules_dir)
    cached = _rules_cache.get("rs")
    if cached and cached.hash == rs.hash:
        return cached
    _rules_cache["rs"] = rs
    return rs


def connector_for(conn: SapConnection) -> RfcConnector:
    params = ConnectionParams(
        client=conn.client, user=conn.rfc_user, password=None if conn.backend == "fixture" or conn.snc_mode
        and not conn.credential_ref else get_password(conn.credential_ref),
        ashost=conn.ashost, sysnr=conn.sysnr, mshost=conn.mshost, msserv=conn.msserv,
        sysid=conn.system.sid if conn.mshost else None, group=conn.logon_group, saprouter=conn.saprouter,
        lang=conn.lang, snc_mode=conn.snc_mode, snc_qop=conn.snc_qop, snc_myname=conn.snc_myname,
        snc_partnername=conn.snc_partnername, snc_lib=conn.snc_lib)
    limits = LoadLimits(**(conn.limits or {}))
    if conn.backend == "fixture":
        limits.pause_between_calls_ms = 0
        limits.max_calls_per_minute = 10 ** 6
    return create_connector(conn.backend, params, limits, fixture_path=conn.fixture_path)


def test_connection(conn: SapConnection) -> dict[str, Any]:
    """Prueba de conectividad y diagnóstico de permisos del usuario RFC (solo lectura)."""
    result: dict[str, Any] = {"fecha": datetime.now().isoformat(timespec="seconds"), "ok": False,
                              "funciones": {}, "tablas": {}, "sistema": {}}
    try:
        c = connector_for(conn)
        with c:
            c.ping()
            result["sistema"] = c.system_info()
            if hasattr(c, "sdk_version"):
                result["sdk"] = c.sdk_version()  # type: ignore[attr-defined]
            sid = result["sistema"].get("RFCSYSID", "")
            result["sid_coincide"] = not sid or sid.upper() == conn.system.sid.upper()
            for fn in sorted(ALLOWED_FUNCTIONS):
                try:
                    result["funciones"][fn] = "disponible" if c.function_exists(fn) else "no existe"
                except RfcAuthorizationError:
                    result["funciones"][fn] = "sin autorización"
                except RfcError as exc:
                    result["funciones"][fn] = f"error: {exc}"
            reader = TableReader(c)
            for ds in DATASETS:
                if ds.name == "usr02" and conn.user_logon_source != "usr02_restricted":
                    result["tablas"][ds.table] = "no se usa (modo BAPI)"
                    continue
                try:
                    reader.describe(ds.table, ds.fields)
                    result["tablas"][ds.table] = "lectura permitida"
                except RfcAuthorizationError:
                    result["tablas"][ds.table] = "SIN AUTORIZACIÓN" + ("" if ds.required else " (opcional)")
                except RfcError as exc:
                    result["tablas"][ds.table] = f"error: {exc}"
            result["ok"] = True
    except RfcError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


ANALYZING: set[int] = set()   # snapshots en análisis (evita análisis concurrentes)


def run_extraction(db: Session, conn: SapConnection, user: str,
                   progress: Callable[[str], None] | None = None) -> Snapshot:
    ext = Extractor(connector_for(conn), db, conn, user)
    if progress:
        ext.progress = progress
    snap = ext.run()
    db.commit()
    if snap.status in ("completo", "incompleto"):
        analyze_snapshot(db, snap.id, progress=progress)
    return snap


def snapshot_meta(snap: Snapshot) -> dict[str, Any]:
    age = max((utcnow() - (snap.finished_at or snap.started_at)).days, 0)  # ambas en UTC
    return {"status": snap.status, "age_days": age,
            "stale": age > get_settings().analysis.stale_snapshot_days,
            "is_test_data": snap.is_test_data}


def active_mitigations(db: Session, sid: str) -> dict[str, tuple[str, float]]:
    now = utcnow()
    rows = db.scalars(select(Mitigation).where(Mitigation.valid_from <= now, Mitigation.valid_to >= now)).all()
    out: dict[str, tuple[str, float]] = {}
    for m in rows:
        if m.sid and m.sid != sid:
            continue
        subject = m.scope_user or m.scope_role or "*"
        out[f"{m.rule_id}|{subject}"] = (m.code, m.effectiveness)
    return out


def context_for(db: Session, snap: Snapshot, as_of: date | None = None) -> AnalysisContext:
    s = get_settings()
    system = snap.connection.system
    return AnalysisContext(get_rules(), system.environment, system.sensitivity, as_of or date.today(),
                           s.analysis.sap_all_equivalence_threshold, s.analysis.inactivity_days,
                           active_mitigations(db, snap.sid))


def data_for(snap: Snapshot) -> SnapshotData:
    return get_snapshot_data(get_engine(), snap.id, str(snap.started_at))


def fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def analyze_snapshot(db: Session, snapshot_id: int, as_of: date | None = None,
                     progress: Callable[[str], None] | None = None) -> int:
    if snapshot_id in ANALYZING:
        raise RuntimeError(f"El snapshot {snapshot_id} ya se está analizando")
    ANALYZING.add(snapshot_id)
    try:
        return _analyze_snapshot(db, snapshot_id, as_of, progress or (lambda m: None))
    finally:
        ANALYZING.discard(snapshot_id)


def _analyze_snapshot(db: Session, snapshot_id: int, as_of: date | None,
                      progress: Callable[[str], None]) -> int:
    """Evalúa todos los usuarios y roles y persiste hallazgos, conservando el estado de
    gestión (responsable, excepción, mitigación) de hallazgos ya conocidos."""
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise ValueError("Snapshot inexistente")
    ctx = context_for(db, snap, as_of)
    data = data_for(snap)
    previous: dict[str, Finding] = {}
    prev_snap = db.scalars(select(Snapshot).where(Snapshot.connection_id == snap.connection_id,
                                                  Snapshot.id < snap.id, Snapshot.analyzed_at.is_not(None))
                           .order_by(Snapshot.id.desc())).first()
    if prev_snap:
        for f in db.scalars(select(Finding).where(Finding.snapshot_id == prev_snap.id)):
            previous[f.fingerprint] = f
    db.query(Finding).filter(Finding.snapshot_id == snapshot_id).delete()
    db.commit()
    count = 0
    seen: set[str] = set()
    folded: set[str] = set()

    def add(kind: str, rule_id: str, version: str, status: str, severity: str, title: str, desc: str,
            rec: str, certainty: str, user: str | None, role: str | None, roles: list[str], evidence: dict,
            inherent: float, residual: float) -> None:
        nonlocal count
        fp = fingerprint(snap.sid, snap.client, kind, rule_id, user or "", role or "")
        seen.add(fp)
        prev = previous.get(fp)
        # El estado lo hereda solo si lo decidió una persona; el automático (usuarios de emergencia) se recalcula.
        inherit = prev is not None and prev.status != "corregido" and not prev.auto_status
        count += 1
        db.add(Finding(
            code=prev.code if prev else f"H-{snap.sid}-{snap.client}-{fp[:8].upper()}", fingerprint=fp,
            snapshot_id=snap.id, kind=kind, rule_id=rule_id, rule_version=version, rule_status=status,
            severity=severity, title=title, description=desc, recommendation=rec, certainty=certainty,
            sid=snap.sid, client=snap.client, subject_user=user, subject_role=role, roles_responsible=roles,
            evidence=evidence, inherent_score=inherent, residual_score=residual,
            status=prev.status if inherit else "abierto",
            owner=prev.owner if prev else None, detected_at=prev.detected_at if prev else utcnow(),
            last_validated_at=utcnow(),
            exception_justification=prev.exception_justification if prev else None,
            exception_expires=prev.exception_expires if prev else None,
            mitigation_id=prev.mitigation_id if prev else None))

    users = sorted(data.users)
    for i, username in enumerate(users, start=1):
        if i == 1 or i % 100 == 0 or i == len(users):
            msg = f"Analizando usuarios {i}/{len(users)}"
            log.info(msg)
            progress(msg)
            db.commit()  # liberar la base periódicamente (SQLite: un solo escritor)
        a = analyze_user(ctx, data, username)
        for h in a.critical:  # riesgos que ahora van dentro de la alerta de SAP_ALL (no se corrigieron)
            for c in h.metrics.get("consecuencias", []):
                folded.add(fingerprint(snap.sid, snap.client, "critica" if c["tipo"] == "critica" else "sod",
                                       c["regla"], username, ""))
        scores = {i.ref: i for i in a.risk.items}
        for h in a.critical:
            sc = scores.get(f"{h.rule_id}|{username}")
            add("critica", h.rule_id, h.rule_version, h.rule_status, h.severity.value, h.title, h.description,
                h.recommendation, h.certainty.value, username, None, h.roles,
                {"evidencia": [vars(e) for e in h.evidence], "notas": h.notes,
                 "consecuencias": h.metrics.get("consecuencias", [])},
                sc.inherent if sc else 0, sc.residual if sc else 0)
        for h in a.sod:
            sc = scores.get(f"{h.risk_id}|{username}")
            add("sod", h.risk_id, h.rule_version, h.rule_status, h.severity.value, h.title, h.explanation,
                h.recommendation, "capacidad_potencial", username, None, h.roles,
                {"alcance": h.scope, "organizacion": h.org_analysis,
                 "funciones": [{"funcion": m.function_id, "titulo": m.title, "accion": m.action_id,
                                "tcodes": m.tcodes, "servicios": m.services, "roles": m.roles,
                                "perfiles_directos": m.direct_profiles,
                                "evidencia": [vars(e) for e in m.evidence]} for m in h.functions]},
                sc.inherent if sc else 0, sc.residual if sc else 0)
    roles = sorted(data.role_names)
    for i, role in enumerate(roles, start=1):
        if i == 1 or i % 500 == 0 or i == len(roles):
            msg = f"Analizando roles {i}/{len(roles)}"
            log.info(msg)
            progress(msg)
            db.commit()
        ra = analyze_role(ctx, data, role)
        for h in ra.sod:
            add("sod_rol", h.risk_id, h.rule_version, h.rule_status, h.severity.value, h.title, h.explanation,
                h.recommendation, "en_perfil", None, role, h.roles, {"alcance": h.scope}, 0, 0)
        if ra.consistency and not ra.consistency.consistent:
            add("calidad", "ROL-PERFIL", "", "validada", "medio", f"Perfil no generado o desactualizado: {role}",
                "El perfil del rol no coincide con la definición en PFCG.", "Regenerar el perfil en PFCG y "
                "ejecutar la comparación de usuarios.", "en_perfil", None, role, [role],
                {"solo_en_rol": ra.consistency.only_in_role[:50],
                 "solo_en_perfil": ra.consistency.only_in_profile[:50]}, 0, 0)
    # Hallazgos que desaparecieron → se registran como corregidos en el nuevo snapshot
    for fp, prev in previous.items():
        if fp not in seen and fp not in folded and prev.status not in ("corregido",):
            count += 1
            db.add(Finding(code=prev.code, fingerprint=fp, snapshot_id=snap.id, kind=prev.kind, rule_id=prev.rule_id,
                           rule_version=prev.rule_version, rule_status=prev.rule_status, severity=prev.severity,
                           title=prev.title, description=prev.description, recommendation=prev.recommendation,
                           certainty=prev.certainty, sid=prev.sid, client=prev.client, subject_user=prev.subject_user,
                           subject_role=prev.subject_role, roles_responsible=prev.roles_responsible,
                           evidence=prev.evidence, status="corregido", owner=prev.owner,
                           detected_at=prev.detected_at, last_validated_at=utcnow()))
    snap.analyzed_at = utcnow()
    snap.ruleset_hash = ctx.rules.hash
    db.commit()
    from .emergency import apply as apply_emergency
    apply_emergency(db, snap)  # usuarios de emergencia declarados: bloqueados = controlados
    return count


def latest_snapshots(db: Session) -> list[Snapshot]:
    sub = (select(Snapshot.connection_id, func.max(Snapshot.id).label("mid"))
           .where(Snapshot.status.in_(["completo", "incompleto"])).group_by(Snapshot.connection_id).subquery())
    return list(db.scalars(select(Snapshot).join(sub, Snapshot.id == sub.c.mid)).all())


def dashboard_stats(db: Session, snap: Snapshot) -> dict[str, Any]:
    """Indicadores por SQL (no carga el snapshot completo en memoria: el dashboard abre al instante)."""
    from .storage.orm import SAP_TABLES
    t_u, t_r, t_p = SAP_TABLES["usr02"], SAP_TABLES["agr_define"], SAP_TABLES["ust04"]
    n_users = db.scalar(select(func.count()).select_from(t_u).where(t_u.c.snapshot_id == snap.id)) or 0
    n_roles = db.scalar(select(func.count()).select_from(t_r).where(t_r.c.snapshot_id == snap.id)) or 0
    sap_all = set(db.scalars(select(t_p.c.bname).where(t_p.c.snapshot_id == snap.id, t_p.c.profile == "SAP_ALL")))
    sap_all_locked = set(db.scalars(select(t_u.c.bname).where(
        t_u.c.snapshot_id == snap.id, t_u.c.bname.in_(sap_all), t_u.c.uflag.not_in(["", "0"])))) if sap_all else set()
    f = db.scalars(select(Finding).where(Finding.snapshot_id == snap.id)).all()
    open_f = [x for x in f if x.status not in ("corregido", "falso_positivo")]
    privileged = {x.subject_user for x in open_f if x.kind == "critica" and x.severity in ("critico", "alto")}
    crit_roles = {r for x in open_f if x.kind in ("critica",) and x.severity in ("critico", "alto")
                  for r in (x.roles_responsible or [])}
    hist = db.scalars(select(Snapshot).where(Snapshot.connection_id == snap.connection_id,
                                             Snapshot.analyzed_at.is_not(None)).order_by(Snapshot.id)).all()
    evolution = []
    for h in hist[-12:]:
        rows = db.execute(select(Finding.severity, func.count()).where(
            Finding.snapshot_id == h.id, Finding.status.not_in(["corregido", "falso_positivo"]))
            .group_by(Finding.severity)).all()
        evolution.append({"snapshot": h.id, "fecha": h.started_at.strftime("%d/%m %H:%M"), **dict(rows)})
    emer = (snap.stats or {}).get("emergencia") or {}
    return {
        "usuarios": n_users, "privilegiados": len(privileged), "sap_all": len(sap_all),
        "sap_all_bloqueados": len(sap_all_locked),
        "sap_all_emergencia": sum(1 for u in sap_all if (emer.get(u) or {}).get("estado") in ("controlado",
                                                                                              "fuera_de_validez")),
        "roles": n_roles, "roles_criticos": len(crit_roles),
        "sod": sum(1 for x in open_f if x.kind == "sod"),
        "criticos": sum(1 for x in open_f if x.severity == "critico"),
        "altos": sum(1 for x in open_f if x.severity == "alto"),
        "pendientes": sum(1 for x in open_f if x.status in ("abierto", "en_revision")),
        "corregidos": sum(1 for x in f if x.status == "corregido"),
        "nuevos": sum(1 for x in open_f if x.detected_at >= (snap.started_at)),
        "por_severidad": {s: sum(1 for x in open_f if x.severity == s)
                          for s in ("critico", "alto", "medio", "bajo", "informativo")},
        "evolucion": evolution,
    }



# ---------------------------------------------------------------------------------- precálculos en disco
def cache_dir() -> Path:
    d = Path(get_settings().log_dir).parent / "cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _recs_file(snap: Snapshot, rules_hash: str) -> Path:
    return cache_dir() / f"recs_{snap.id}_{snap.started_at:%Y%m%d%H%M%S}_{rules_hash[:12]}.json"


def load_recommendations(snap: Snapshot, rules_hash: str) -> list[dict] | None:
    f = _recs_file(snap, rules_hash)
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def compute_recommendations(ctx: AnalysisContext, data: SnapshotData) -> list[dict]:
    from .engine.recommend import redundant_roles
    recs: list[dict] = []
    for r in sorted(data.role_names):
        ra = analyze_role(ctx, data, r)
        failed = [c for c in ra.quality.criteria if not c.passed]
        if ra.quality.score < 80:
            recs.append({"tipo": "Rediseño de rol", "objeto": r, "link": f"/roles/{r}",
                         "detalle": "; ".join(f"{c.label}: {c.detail}" for c in failed),
                         "beneficio": "Reduce privilegios y conflictos internos",
                         "impacto": f"{len(ra.users)} usuario(s) asignado(s)",
                         "confianza": "alta (basada en reglas y datos del rol)"})
        for g in ra.generic[:3]:
            recs.append({"tipo": "Restringir valores genéricos", "objeto": r, "link": f"/roles/{r}",
                         "detalle": f"{g['object']}-{g['field']} = {g['values']}",
                         "beneficio": "Aplica mínimo privilegio sobre unidades organizativas/actividades",
                         "impacto": "Puede impedir tareas legítimas: validar con el dueño del proceso",
                         "confianza": "media"})
    for uname in sorted(data.users):
        a = analyze_user(ctx, data, uname)
        for role, by in redundant_roles(a):
            recs.append({"tipo": "Rol redundante para el usuario", "objeto": f"{uname} / {role}",
                         "link": f"/usuarios/{uname}", "detalle": f"Todas sus autorizaciones ya las aportan: {', '.join(by)}",
                         "beneficio": "Simplifica la asignación", "impacto": "Bajo: no reduce permisos efectivos",
                         "confianza": "alta (subsunción de valores); verificar menús/Fiori"})
        if a.eff._direct - {"SAP_ALL", "SAP_NEW"}:  # noqa: SLF001
            recs.append({"tipo": "Sustituir perfiles directos por roles", "objeto": uname,
                         "link": f"/usuarios/{uname}", "detalle": ", ".join(sorted(a.eff._direct)),  # noqa: SLF001
                         "beneficio": "Trazabilidad y gobierno vía PFCG", "impacto": "Requiere diseñar rol equivalente",
                         "confianza": "alta"})
    return recs


def precompute(db: Session, snapshot_id: int, progress: Callable[[str], None] | None = None) -> None:
    """Cálculos pesados para la interfaz (incompatibilidades entre roles y recomendaciones), guardados en disco.
    Se ejecuta en el proceso de extracción o con «sapsec precompute», nunca dentro de la aplicación web."""
    from .engine.incompat import role_function_map
    progress = progress or (lambda m: None)
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise ValueError("Snapshot inexistente")
    ctx = context_for(db, snap)
    data = data_for(snap)
    progress("Precalculando incompatibilidades entre roles")
    role_function_map(ctx.rules, data, ctx.as_of)
    progress("Precalculando recomendaciones")
    recs = compute_recommendations(ctx, data)
    _recs_file(snap, ctx.rules.hash).write_text(json.dumps(recs, ensure_ascii=False), encoding="utf-8")



# ---------------------------------------------------------------------------------- borrado de datos
def _remove_cache_files(snapshot_id: int) -> None:
    d = Path(get_settings().log_dir).parent / "cache"
    if d.exists():
        for f in list(d.glob(f"rolefn_{snapshot_id}_*")) + list(d.glob(f"recs_{snapshot_id}_*")):
            f.unlink(missing_ok=True)


def delete_snapshot(db: Session, snapshot_id: int) -> dict[str, int]:
    """Elimina un snapshot con todos sus datos SAP, hallazgos y simulaciones. El registro de auditoría se conserva."""
    from sqlalchemy import delete as sql_delete

    from .storage.orm import SAP_TABLES, Simulation
    from .storage.snapshot_data import clear_cache
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise ValueError(f"No existe el snapshot #{snapshot_id}")
    if snapshot_id in ANALYZING:
        raise ValueError(f"El snapshot #{snapshot_id} se está analizando; espere a que termine.")
    counts: dict[str, int] = {}
    for name, table in SAP_TABLES.items():
        counts[name] = db.execute(table.delete().where(table.c.snapshot_id == snapshot_id)).rowcount or 0
        db.commit()  # transacciones cortas: la interfaz sigue respondiendo
    counts["hallazgos"] = db.execute(sql_delete(Finding).where(Finding.snapshot_id == snapshot_id)).rowcount or 0
    counts["simulaciones"] = db.execute(sql_delete(Simulation).where(Simulation.snapshot_id == snapshot_id)).rowcount or 0
    db.execute(sql_delete(Snapshot).where(Snapshot.id == snapshot_id))
    db.commit()
    _remove_cache_files(snapshot_id)
    clear_cache()
    return counts


def delete_connection(db: Session, connection_id: int) -> dict[str, Any]:
    """Elimina una conexión, sus snapshots y su contraseña guardada; y el sistema si queda sin conexiones."""
    from sqlalchemy import delete as sql_delete

    from .security.secrets import delete_password
    from .storage.orm import SapSystem
    conn = db.get(SapConnection, connection_id)
    if conn is None:
        raise ValueError(f"No existe la conexión {connection_id}")
    sid, client, name = conn.system.sid, conn.client, conn.name
    snaps = list(db.scalars(select(Snapshot.id).where(Snapshot.connection_id == connection_id)))
    for snap_id in snaps:
        delete_snapshot(db, snap_id)
    conn = db.get(SapConnection, connection_id)
    cred_deleted = False
    try:
        cred_deleted = delete_password(conn.credential_ref)  # type: ignore[union-attr]
    except Exception as exc:  # noqa: BLE001 - no impedir el borrado; se informa
        log.warning("No se pudo eliminar la credencial guardada de %s: %s", name, exc)
    system_id = conn.system_id  # type: ignore[union-attr]
    db.execute(sql_delete(EmergencyUser).where(EmergencyUser.connection_id == connection_id))
    db.delete(conn)
    db.commit()
    system_deleted = False
    if not db.scalars(select(SapConnection).where(SapConnection.system_id == system_id)).first():
        system = db.get(SapSystem, system_id)
        if system is not None:
            db.execute(sql_delete(Mitigation).where(Mitigation.sid == system.sid))
            db.delete(system)
            system_deleted = True
        db.commit()
    return {"conexion": name, "sistema": f"{sid}/{client}", "snapshots": len(snaps),
            "credencial_borrada": cred_deleted, "sistema_borrado": system_deleted}


def reset_sap_data(db: Session) -> dict[str, Any]:
    """Borra TODOS los sistemas, conexiones, snapshots, hallazgos, simulaciones, mitigaciones y contraseñas
    guardadas. Conserva los usuarios de la aplicación y el registro de auditoría."""
    from sqlalchemy import delete as sql_delete

    from .storage.orm import SapSystem, Simulation
    result: dict[str, Any] = {"conexiones": [], "snapshots_huerfanos": 0}
    for cid in list(db.scalars(select(SapConnection.id))):
        result["conexiones"].append(delete_connection(db, cid))
    for snap_id in list(db.scalars(select(Snapshot.id))):
        delete_snapshot(db, snap_id)
        result["snapshots_huerfanos"] += 1
    db.execute(sql_delete(Simulation))
    db.execute(sql_delete(Mitigation))
    db.execute(sql_delete(EmergencyUser))
    db.execute(sql_delete(SapSystem))
    db.commit()
    compact_database()
    return result


def compact_database() -> None:
    """Recupera el espacio en disco (SQLite VACUUM). Sin efecto en PostgreSQL."""
    eng = get_engine()
    if eng.dialect.name != "sqlite":
        return
    try:
        with eng.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
            c.exec_driver_sql("VACUUM")
    except Exception as exc:  # noqa: BLE001 - si la base está en uso se omite; no es crítico
        log.warning("No se pudo compactar la base (se reintentará en el próximo borrado): %s", exc)



# ---------------------------------------------------------------------------------- varios sistemas
def prune_snapshots(db: Session, connection_id: int, keep: int) -> int:
    """Conserva los últimos ``keep`` snapshots válidos de una conexión (0 = todos). Devuelve cuántos borró."""
    if keep <= 0:
        return 0
    ids = list(db.scalars(select(Snapshot.id).where(Snapshot.connection_id == connection_id)
                          .order_by(Snapshot.id.desc())))
    valid = [i for i in ids if (db.get(Snapshot, i).status in ("completo", "incompleto"))]
    keep_ids = set(valid[:keep])
    # Se borran los anteriores a los conservados (incluidos los fallidos viejos); el más reciente nunca.
    newest = ids[0] if ids else None
    removed = 0
    for i in ids:
        if i in keep_ids or i == newest:
            continue
        if keep_ids and i > min(keep_ids):
            continue  # un snapshot fallido más nuevo que los conservados se deja para diagnóstico
        delete_snapshot(db, i)
        removed += 1
    return removed


def extract_and_prepare(db: Session, conn: SapConnection, user: str,
                        progress: Callable[[str], None] | None = None) -> Snapshot:
    """Flujo completo para un sistema: extracción → análisis → precálculos → retención."""
    progress = progress or (lambda m: None)
    snap = run_extraction(db, conn, user, progress=progress)
    if snap.status in ("completo", "incompleto"):
        try:
            precompute(db, snap.id, progress=progress)
        except Exception:  # noqa: BLE001 - no invalida la extracción
            log.exception("Falló el precálculo del snapshot %s", snap.id)
        keep = get_settings().snapshots_to_keep
        n = prune_snapshots(db, conn.id, keep)
        if n:
            progress(f"Retención: se eliminaron {n} snapshot(s) antiguos (se conservan los últimos {keep})")
    return snap


def latest_by_connection(db: Session, analyzed_only: bool = True) -> dict[int, Snapshot]:
    """Último snapshot (analizado) de cada conexión."""
    q = select(Snapshot).where(Snapshot.status.in_(["completo", "incompleto"]))
    if analyzed_only:
        q = q.where(Snapshot.analyzed_at.is_not(None))
    out: dict[int, Snapshot] = {}
    for s in db.scalars(q.order_by(Snapshot.id.desc())):
        out.setdefault(s.connection_id, s)
    return out


def system_overview(db: Session) -> list[dict[str, Any]]:
    """Panorama de todos los sistemas (consultas SQL livianas, sin cargar snapshots en memoria)."""
    from .storage.orm import SAP_TABLES
    latest = latest_by_connection(db)
    t_u, t_p = SAP_TABLES["usr02"], SAP_TABLES["ust04"]
    open_states = ("corregido", "falso_positivo", "excepcion", "mitigado")
    stale_days = get_settings().analysis.stale_snapshot_days
    rows = []
    for c in db.scalars(select(SapConnection).order_by(SapConnection.id)):
        s = latest.get(c.id)
        row: dict[str, Any] = {"conn": c, "snap": s, "env": (c.system.environment or "OTRO").upper()}
        if s is not None:
            def users_with(*sev: str, kind: str | None = None) -> int:
                q = select(func.count(func.distinct(Finding.subject_user))).where(
                    Finding.snapshot_id == s.id, Finding.subject_user.is_not(None),
                    Finding.status.not_in(open_states))
                if sev:
                    q = q.where(Finding.severity.in_(sev))
                if kind:
                    q = q.where(Finding.kind == kind)
                return db.scalar(q) or 0
            age = max((utcnow() - (s.finished_at or s.started_at)).days, 0)
            row.update(
                usuarios=db.scalar(select(func.count()).select_from(t_u).where(t_u.c.snapshot_id == s.id)) or 0,
                criticos=users_with("critico"), altos=users_with("alto"), sod=users_with(kind="sod"),
                sap_all=db.scalar(select(func.count()).select_from(t_p).where(
                    t_p.c.snapshot_id == s.id, t_p.c.profile == "SAP_ALL")) or 0,
                age=age, stale=age > stale_days,
                n_snaps=db.scalar(select(func.count()).select_from(Snapshot).where(
                    Snapshot.connection_id == c.id)) or 0)
        rows.append(row)
    order = {"PRD": 0, "QA": 1, "DEV": 2}
    rows.sort(key=lambda r: (order.get(r["env"], 3), r["conn"].system.label, r["conn"].client))
    return rows


# ------------------------------------------------------------------------------- control entre sistemas
def _same_landscape(a: SapSystem, b: SapSystem) -> bool | None:
    """True = mismo landscape; None = no se definió en alguno de los dos (se muestra igual); False = distintos."""
    la, lb = (a.landscape or "").strip().lower(), (b.landscape or "").strip().lower()
    if not la or not lb:
        return None
    return la == lb


def cross_system(db: Session, prd_snapshot_id: int | None = None) -> dict[str, Any]:
    """Quién desarrolla en DEV y además tiene permisos críticos en PRD del mismo landscape.

    Usa los hallazgos ya calculados de los últimos snapshots (consultas SQL, sin recalcular): en DEV, la regla
    informativa de desarrollador; en PRD, las reglas de ``landscape.production_rules``."""
    from .engine.rules import norm_env
    rules = get_rules()
    cfg = rules.landscape or {}
    marker, targets = cfg.get("developer_rule"), list(cfg.get("production_rules") or [])
    latest = latest_by_connection(db)
    dev = [s for s in latest.values() if norm_env(s.connection.system.environment) == "DEV"]
    prd = [s for s in latest.values() if norm_env(s.connection.system.environment) == "PRD"
           and (prd_snapshot_id is None or s.id == prd_snapshot_id)]
    out: dict[str, Any] = {"rows": [], "dev": dev, "prd": prd, "configured": bool(marker and targets)}
    if not (dev and prd and marker and targets):
        return out
    developers: dict[str, list[Snapshot]] = {}
    for sid, user in db.execute(select(Finding.snapshot_id, Finding.subject_user).where(
            Finding.snapshot_id.in_([s.id for s in dev]), Finding.rule_id == marker,
            Finding.status != "corregido", Finding.subject_user.is_not(None))):
        developers.setdefault(user, []).append(next(s for s in dev if s.id == sid))
    if not developers:
        return out
    handled = ("corregido", "falso_positivo", "excepcion", "mitigado")
    rows: dict[tuple[str, int], dict[str, Any]] = {}
    sev_rank = {"critico": 4, "alto": 3, "medio": 2, "bajo": 1, "informativo": 0}
    for f in db.scalars(select(Finding).where(Finding.snapshot_id.in_([s.id for s in prd]),
                                              Finding.rule_id.in_(targets), Finding.status.not_in(handled),
                                              Finding.subject_user.in_(list(developers)))):
        p_snap = next(s for s in prd if s.id == f.snapshot_id)
        devs = [d for d in developers[f.subject_user]
                if _same_landscape(d.connection.system, p_snap.connection.system) is not False]
        if not devs:
            continue
        key = (f.subject_user, p_snap.id)
        row = rows.setdefault(key, {"user": f.subject_user, "prd": p_snap, "dev": devs, "items": [],
                                    "severity": "bajo", "same": any(_same_landscape(d.connection.system,
                                                                                    p_snap.connection.system)
                                                                    for d in devs)})
        row["items"].append({"rule_id": f.rule_id, "title": f.title, "severity": f.severity})
        if sev_rank.get(f.severity, 0) > sev_rank.get(row["severity"], 0):
            row["severity"] = f.severity
    out["rows"] = sorted(rows.values(), key=lambda r: (-sev_rank.get(r["severity"], 0), r["user"]))
    return out
