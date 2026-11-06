"""Esquema de base de datos (SQLite para desarrollo, PostgreSQL para producción).

* Tablas de la aplicación: sistemas, conexiones, snapshots, hallazgos,
  mitigaciones, simulaciones, usuarios de la aplicación y auditoría.
* Tablas ``sap_<dataset>``: generadas automáticamente desde el catálogo de
  fuentes; cada fila pertenece a un snapshot inmutable.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import (JSON, Boolean, Column, Date, DateTime, Float, ForeignKey, Index, Integer,
                        MetaData, String, Table, Text, UniqueConstraint)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ..extraction.sources import DATASETS


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    metadata = MetaData()


class SapSystem(Base):
    """Sistema SAP. El SID puede repetirse entre landscapes distintos (p. ej. «PRD» en dos países):
    lo que identifica al sistema en la aplicación es su NOMBRE (único) y, técnicamente, su huella."""

    __tablename__ = "sap_system"
    id: Mapped[int] = mapped_column(primary_key=True)
    sid: Mapped[str] = mapped_column(String(8))
    name: Mapped[str] = mapped_column(String(100), default="")          # p. ej. «PRD Uruguay»
    description: Mapped[str] = mapped_column(String(200), default="")
    environment: Mapped[str] = mapped_column(String(20), default="DEV")  # DEV | QA | PRD | OTRO
    productive: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitivity: Mapped[float] = mapped_column(Float, default=1.0)       # factor del motor de riesgo
    landscape: Mapped[str] = mapped_column(String(100), default="")      # sistemas que comparten transportes
    connections: Mapped[list["SapConnection"]] = relationship(back_populates="system")

    @property
    def label(self) -> str:
        return self.name or self.sid


class SapConnection(Base):
    __tablename__ = "sap_connection"
    id: Mapped[int] = mapped_column(primary_key=True)
    system_id: Mapped[int] = mapped_column(ForeignKey("sap_system.id"))
    client: Mapped[str] = mapped_column(String(3))
    name: Mapped[str] = mapped_column(String(100))
    backend: Mapped[str] = mapped_column(String(20), default="nwrfc")
    ashost: Mapped[str | None] = mapped_column(String(200), nullable=True)
    sysnr: Mapped[str | None] = mapped_column(String(2), nullable=True)
    mshost: Mapped[str | None] = mapped_column(String(200), nullable=True)
    msserv: Mapped[str | None] = mapped_column(String(50), nullable=True)
    logon_group: Mapped[str | None] = mapped_column(String(50), nullable=True)
    saprouter: Mapped[str | None] = mapped_column(String(300), nullable=True)
    rfc_user: Mapped[str] = mapped_column(String(12))
    lang: Mapped[str] = mapped_column(String(2), default="ES")
    snc_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    snc_qop: Mapped[str | None] = mapped_column(String(2), nullable=True)
    snc_myname: Mapped[str | None] = mapped_column(String(200), nullable=True)
    snc_partnername: Mapped[str | None] = mapped_column(String(200), nullable=True)
    snc_lib: Mapped[str | None] = mapped_column(String(300), nullable=True)
    credential_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)  # referencia, no secreto
    fixture_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    user_logon_source: Mapped[str] = mapped_column(String(30), default="usr02_restricted")
    limits: Mapped[dict] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_test_result: Mapped[dict] = mapped_column(JSON, default=dict)
    # Huella del sistema real (SID|host de BD|motor), registrada en la primera extracción. Si cambia, la
    # extracción se cancela: evita mezclar datos de dos sistemas con el mismo SID.
    fingerprint: Mapped[str] = mapped_column(String(300), default="")
    system: Mapped[SapSystem] = relationship(back_populates="connections")

    @property
    def label(self) -> str:
        return f"{self.system.label} · {self.system.sid}/{self.client}"
    __table_args__ = (UniqueConstraint("system_id", "client", "name", name="uq_conn"),)


class Snapshot(Base):
    __tablename__ = "snapshot"
    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int] = mapped_column(ForeignKey("sap_connection.id"))
    sid: Mapped[str] = mapped_column(String(8))
    client: Mapped[str] = mapped_column(String(3))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="en_curso")  # completo | incompleto | error
    is_test_data: Mapped[bool] = mapped_column(Boolean, default=False)
    backend: Mapped[str] = mapped_column(String(20), default="")
    system_info: Mapped[dict] = mapped_column(JSON, default=dict)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    issues: Mapped[list] = mapped_column(JSON, default=list)
    started_by: Mapped[str] = mapped_column(String(50), default="")
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ruleset_hash: Mapped[str] = mapped_column(String(64), default="")
    connection: Mapped[SapConnection] = relationship()

    @property
    def label(self) -> str:
        """Identificación legible: «PRD Uruguay · PRD/300 · 04/11/2026 18:21»."""
        name = self.connection.system.label if self.connection is not None else self.sid
        return f"{name} · {self.sid}/{self.client} · {self.started_at:%d/%m/%Y %H:%M}"


class Finding(Base):
    __tablename__ = "finding"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(40), index=True)        # identificador único visible
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # estable entre snapshots
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))                    # critica | sod | calidad | usuario
    rule_id: Mapped[str] = mapped_column(String(60))
    rule_version: Mapped[str] = mapped_column(String(20), default="")
    rule_status: Mapped[str] = mapped_column(String(20), default="ejemplo")
    severity: Mapped[str] = mapped_column(String(15))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    certainty: Mapped[str] = mapped_column(String(30), default="")
    sid: Mapped[str] = mapped_column(String(8))
    client: Mapped[str] = mapped_column(String(3))
    subject_user: Mapped[str | None] = mapped_column(String(12), nullable=True, index=True)
    subject_role: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    roles_responsible: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    inherent_score: Mapped[float] = mapped_column(Float, default=0)
    residual_score: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String(20), default="abierto")  # abierto|en_revision|mitigado|excepcion|corregido|falso_positivo
    owner: Mapped[str | None] = mapped_column(String(100), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_validated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    exception_justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    exception_expires: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    mitigation_id: Mapped[int | None] = mapped_column(ForeignKey("mitigation.id"), nullable=True)
    # Quién fijó el estado: "" = una persona (o el valor inicial); "emergencia" = la declaración de usuario de
    # emergencia (se recalcula en cada análisis y se revierte sola si el usuario se desbloquea o la declaración vence).
    auto_status: Mapped[str] = mapped_column(String(20), default="")


class Mitigation(Base):
    __tablename__ = "mitigation"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True)
    description: Mapped[str] = mapped_column(Text)
    rule_id: Mapped[str] = mapped_column(String(60))
    scope_user: Mapped[str | None] = mapped_column(String(12), nullable=True)
    scope_role: Mapped[str | None] = mapped_column(String(30), nullable=True)
    sid: Mapped[str | None] = mapped_column(String(8), nullable=True)
    owner: Mapped[str] = mapped_column(String(100))
    approved_by: Mapped[str] = mapped_column(String(100))
    effectiveness: Mapped[float] = mapped_column(Float, default=0.5)  # 0..1 reduce riesgo residual
    valid_from: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    valid_to: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class EmergencyUser(Base):
    """Usuario de emergencia declarado: tiene permisos amplios (p. ej. SAP_ALL) a propósito y se mantiene BLOQUEADO
    salvo durante una emergencia. Mientras esté bloqueado y la declaración vigente, sus alertas quedan controladas
    (no pendientes); si se desbloquea o la declaración vence, vuelven a ser pendientes."""

    __tablename__ = "emergency_user"
    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int | None] = mapped_column(ForeignKey("sap_connection.id"), nullable=True)  # None = todos
    username: Mapped[str] = mapped_column(String(12), index=True)
    responsible: Mapped[str] = mapped_column(String(100))          # quién aprueba su uso
    procedure: Mapped[str] = mapped_column(Text)                   # cuándo y cómo se usa
    review_by: Mapped[date] = mapped_column(Date)                  # fecha de revisión (vence la declaración)
    created_by: Mapped[str] = mapped_column(String(50), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(50), default="")
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    connection: Mapped["SapConnection | None"] = relationship()
    __table_args__ = (UniqueConstraint("connection_id", "username", name="uq_emergency_user"),)


class Simulation(Base):
    __tablename__ = "simulation"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(50))
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("snapshot.id"))
    username: Mapped[str] = mapped_column(String(12))
    scenario: Mapped[dict] = mapped_column(JSON)
    recommendation: Mapped[str] = mapped_column(String(30))
    result: Mapped[dict] = mapped_column(JSON)


class AppUser(Base):
    __tablename__ = "app_user"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(20))   # administrador | auditor | consultor
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    last_failed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    theme: Mapped[str] = mapped_column(String(20), default="")   # tema de colores elegido ("" = el predeterminado)


class ExtractionSchedule(Base):
    """Extracción programada (hora local del equipo). La ejecuta la aplicación mientras está abierta y,
    si está instalada, la tarea de Windows «run-due» aunque la aplicación esté cerrada."""

    __tablename__ = "extraction_schedule"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    time_hhmm: Mapped[str] = mapped_column(String(5), default="03:00")
    days: Mapped[str] = mapped_column(String(20), default="0,1,2,3,4,5,6")   # 0 = lunes … 6 = domingo
    environment: Mapped[str] = mapped_column(String(10), default="TODOS")    # TODOS | PRD | QA | DEV | OTRO
    connection_ids: Mapped[list] = mapped_column(JSON, default=list)        # vacío = todos los del ambiente
    created_by: Mapped[str] = mapped_column(String(50), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_slot: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)   # última franja reclamada (local)
    state: Mapped[str] = mapped_column(String(20), default="")               # en_curso | terminado | error
    current: Mapped[str] = mapped_column(String(200), default="")           # sistema que se está extrayendo
    trigger: Mapped[str] = mapped_column(String(40), default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)   # hora local
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_result: Mapped[list] = mapped_column(JSON, default=list)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(50))
    action: Mapped[str] = mapped_column(String(60))
    target: Mapped[str] = mapped_column(String(200), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")


# --- Tablas de datos SAP generadas desde el catálogo ------------------------------------
SAP_TABLES: dict[str, Table] = {}
for _ds in DATASETS:
    _cols = [Column("id", Integer, primary_key=True),
             Column("snapshot_id", Integer, ForeignKey("snapshot.id", ondelete="CASCADE"), nullable=False)]
    _cols += [Column(f.lower(), String(200), default="") for f in _ds.fields]
    if _ds.name == "usr02":
        _cols.append(Column("fullname", String(200), default=""))
    _t = Table(f"sap_{_ds.name}", Base.metadata, *_cols)
    Index(f"ix_sap_{_ds.name}_snap", _t.c.snapshot_id)
    if _ds.partition_field:
        Index(f"ix_sap_{_ds.name}_key", _t.c.snapshot_id, _t.c[_ds.partition_field.lower()])
    SAP_TABLES[_ds.name] = _t
