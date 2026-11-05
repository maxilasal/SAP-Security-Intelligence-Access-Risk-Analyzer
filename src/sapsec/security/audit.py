"""Registro de auditoría de la propia aplicación (accesos, consultas, extracciones, exportaciones)."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from ..storage.orm import AuditLog

log = logging.getLogger("sapsec.audit")


def audit(db: Session, username: str, action: str, target: str = "", details: dict | None = None,
          ip: str = "") -> None:
    """Registra la acción y la confirma de inmediato (transacción corta)."""
    log.info("AUDIT user=%s action=%s target=%s", username, action, target)
    db.add(AuditLog(username=username, action=action, target=target[:200], details=details or {}, ip=ip))
    db.commit()
