"""Extracciones programadas.

* Las programaciones se definen en la aplicación (hora local, días, ambiente o sistemas).
* Las dispara:
  - la propia aplicación web mientras está abierta (revisión cada minuto), y
  - la tarea de Windows ``sapsec run-due`` (scripts/instalar_tarea_programada.ps1), aunque la aplicación
    esté cerrada.
* Cada franja (fecha + hora) se «reclama» de forma atómica en la base: aunque ambos mecanismos estén
  activos, la misma programación nunca corre dos veces.
* Si el equipo estaba apagado a la hora programada, se ejecuta dentro de la ventana de recuperación
  (por defecto 3 horas); pasado ese plazo, esa ejecución se omite (para no cargar PRD en horario laboral).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Callable

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from .storage.orm import ExtractionSchedule, SapConnection

log = logging.getLogger(__name__)

WINDOW = timedelta(hours=3)
DAY_NAMES = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
DAY_SHORT = ["L", "M", "X", "J", "V", "S", "D"]
STALE = timedelta(hours=12)


def parse_days(days: str) -> list[int]:
    out = sorted({int(x) for x in (days or "").split(",") if x.strip().isdigit() and 0 <= int(x) <= 6})
    return out or list(range(7))


def parse_time(hhmm: str) -> tuple[int, int]:
    try:
        h, m = (int(x) for x in (hhmm or "03:00").split(":", 1))
        if 0 <= h <= 23 and 0 <= m <= 59:
            return h, m
    except ValueError:
        pass
    raise ValueError(f"Hora inválida: {hhmm!r} (formato HH:MM)")


def describe_when(s: ExtractionSchedule) -> str:
    days = parse_days(s.days)
    if days == list(range(7)):
        d = "Todos los días"
    elif days == list(range(5)):
        d = "De lunes a viernes"
    elif days == [5, 6]:
        d = "Sábados y domingos"
    else:
        d = "Los " + ", ".join(DAY_NAMES[i] for i in days)
    return f"{d} a las {s.time_hhmm}"


def slot_for(s: ExtractionSchedule, day: datetime) -> datetime:
    h, m = parse_time(s.time_hhmm)
    return day.replace(hour=h, minute=m, second=0, microsecond=0)


def due_slot(s: ExtractionSchedule, now: datetime | None = None) -> datetime | None:
    """Franja vencida y aún no ejecutada (dentro de la ventana de recuperación), o None."""
    now = now or datetime.now()
    if not s.enabled:
        return None
    days = parse_days(s.days)
    for back in (0, 1):  # la franja de ayer puede caer dentro de la ventana (p. ej. 23:30 → 00:10)
        slot = slot_for(s, now - timedelta(days=back))
        if slot.weekday() in days and slot <= now <= slot + WINDOW:
            if s.last_slot is None or s.last_slot < slot:
                return slot
    return None


def next_run(s: ExtractionSchedule, now: datetime | None = None) -> datetime | None:
    now = now or datetime.now()
    if not s.enabled:
        return None
    days = parse_days(s.days)
    for ahead in range(0, 8):
        slot = slot_for(s, now + timedelta(days=ahead))
        if slot.weekday() in days and slot > now:
            return slot
    return None


def when_label(dt: datetime | None, now: datetime | None = None) -> str:
    """«hoy 22:30», «mañana 03:00» o «jue 05/11 03:00»."""
    if dt is None:
        return "—"
    now = now or datetime.now()
    if dt.date() == now.date():
        return f"hoy {dt:%H:%M}"
    if dt.date() == (now + timedelta(days=1)).date():
        return f"mañana {dt:%H:%M}"
    return f"{['lun', 'mar', 'mié', 'jue', 'vie', 'sáb', 'dom'][dt.weekday()]} {dt:%d/%m %H:%M}"


def is_running(s: ExtractionSchedule, now: datetime | None = None) -> bool:
    now = now or datetime.now()
    return s.state == "en_curso" and s.started_at is not None and now - s.started_at < STALE


def claim(db: Session, schedule_id: int, slot: datetime) -> bool:
    """Reclama la franja de forma atómica: True solo para el primero que la pide."""
    res = db.execute(update(ExtractionSchedule)
                     .where(ExtractionSchedule.id == schedule_id,
                            or_(ExtractionSchedule.last_slot.is_(None), ExtractionSchedule.last_slot < slot))
                     .values(last_slot=slot))
    db.commit()
    return (res.rowcount or 0) == 1


def matching_connections(db: Session, s: ExtractionSchedule) -> list[SapConnection]:
    conns = list(db.scalars(select(SapConnection).where(SapConnection.active.is_(True)).order_by(SapConnection.id)))
    if s.connection_ids:
        wanted = {int(x) for x in s.connection_ids}
        return [c for c in conns if c.id in wanted]
    env = (s.environment or "TODOS").upper()
    if env == "TODOS":
        return conns
    return [c for c in conns if (c.system.environment or "OTRO").upper() == env]


def describe_what(db: Session, s: ExtractionSchedule) -> str:
    n = len(matching_connections(db, s))
    if s.connection_ids:
        return f"{n} sistema(s) elegidos"
    env = (s.environment or "TODOS").upper()
    return f"Todos los sistemas ({n})" if env == "TODOS" else f"Todos los {env} ({n})"


def execute(db: Session, schedule_id: int, trigger: str,
            progress: Callable[[str], None] | None = None) -> list[dict[str, Any]]:
    """Ejecuta una programación: extrae, analiza y aplica retención en cada sistema, de a uno."""
    from .security.audit import audit
    from .services import extract_and_prepare
    progress = progress or (lambda m: None)
    s = db.get(ExtractionSchedule, schedule_id)
    if s is None:
        raise ValueError(f"No existe la programación {schedule_id}")
    conns = [(c.id, c.label) for c in matching_connections(db, s)]
    s.state, s.trigger, s.current = "en_curso", trigger, ""
    s.started_at, s.finished_at, s.last_result = datetime.now(), None, []
    db.commit()
    results: list[dict[str, Any]] = []
    for i, (cid, label) in enumerate(conns, start=1):
        s = db.get(ExtractionSchedule, schedule_id)
        s.current = f"{label} ({i}/{len(conns)})"
        db.commit()
        progress(f"[{i}/{len(conns)}] {label}")
        try:
            conn = db.get(SapConnection, cid)
            snap = extract_and_prepare(db, conn, f"programado:{s.name}", progress=lambda m: progress("    " + m))  # type: ignore[arg-type]
            results.append({"sistema": label, "snapshot": snap.id, "estado": snap.status,
                            "detalle": "; ".join(x.get("message", "") for x in (snap.issues or []))[:300]})
        except Exception as exc:  # noqa: BLE001 - seguir con el próximo sistema
            log.exception("Extracción programada fallida: %s", label)
            results.append({"sistema": label, "snapshot": None, "estado": "error",
                            "detalle": f"{type(exc).__name__}: {exc}"[:300]})
        s = db.get(ExtractionSchedule, schedule_id)
        s.last_result = list(results)
        db.commit()
    s = db.get(ExtractionSchedule, schedule_id)
    failed = sum(1 for r in results if r["estado"] == "error")
    s.state, s.current, s.finished_at = ("error" if failed else "terminado"), "", datetime.now()
    db.commit()
    audit(db, "programado", "extraccion_programada", s.name,
          {"disparador": trigger, "sistemas": len(results), "con_error": failed})
    return results


def run_due_inline(db_factory: Callable[[], Any], trigger: str,
                   progress: Callable[[str], None] | None = None) -> int:
    """Ejecuta en este proceso las programaciones vencidas (usado por la tarea de Windows). Devuelve cuántas."""
    ran = 0
    with db_factory() as db:
        due = [(s.id, slot) for s in db.scalars(select(ExtractionSchedule))
               if (slot := due_slot(s)) is not None and not is_running(s)]
    for sid, slot in due:
        with db_factory() as db:
            if not claim(db, sid, slot):
                continue
            execute(db, sid, trigger, progress)
            ran += 1
    return ran
