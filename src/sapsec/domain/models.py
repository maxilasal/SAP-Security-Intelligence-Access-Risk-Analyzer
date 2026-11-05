"""Modelo de dominio independiente de la persistencia y de la interfaz.

Conceptos clave (ver docs/01_fase1_diseno.md, sección 6):

* Una *instancia de autorización* es el par (objeto, autorización) de UST12 /
  AGR_1251-AUTH. Los valores de campos solo se combinan DENTRO de la misma
  instancia; nunca entre instancias distintas.
* Cada instancia lleva su *procedencia* (rol → perfil generado, perfil directo,
  perfil residual) y un *nivel de certeza*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import Enum


class Certainty(str, Enum):
    """Grado de certeza de una afirmación sobre permisos."""

    DEFINIDO_EN_ROL = "definido_en_rol"          # AGR_1251, aún no necesariamente generado
    EN_PERFIL = "en_perfil"                      # UST10S/UST12 del perfil generado
    ASIGNADO = "asignado"                        # perfil presente en UST04 del usuario
    CAPACIDAD_POTENCIAL = "capacidad_potencial"  # el buffer cubre los chequeos conocidos
    CONFIRMADO_EN_SAP = "confirmado_en_sap"      # verificado en SAP (traza/SU53/SUIM)

    @property
    def label(self) -> str:
        return {
            "definido_en_rol": "Definido en rol (PFCG)",
            "en_perfil": "Presente en perfil",
            "asignado": "Asignado efectivamente",
            "capacidad_potencial": "Capacidad potencial",
            "confirmado_en_sap": "Confirmado en SAP",
        }[self.value]


class Severity(str, Enum):
    CRITICO = "critico"
    ALTO = "alto"
    MEDIO = "medio"
    BAJO = "bajo"
    INFORMATIVO = "informativo"

    @property
    def rank(self) -> int:
        return {"critico": 4, "alto": 3, "medio": 2, "bajo": 1, "informativo": 0}[self.value]

    @property
    def label(self) -> str:
        return {"critico": "Crítico", "alto": "Alto", "medio": "Medio",
                "bajo": "Bajo", "informativo": "Informativo"}[self.value]

    @classmethod
    def max(cls, items: "list[Severity]") -> "Severity":
        return max(items, key=lambda s: s.rank) if items else cls.INFORMATIVO


class RuleStatus(str, Enum):
    """Estado de gobierno de una regla. Nunca presentar reglas 'ejemplo' como oficiales."""

    EJEMPLO = "ejemplo"
    VALIDADA = "validada"     # validada técnicamente por seguridad SAP
    APROBADA = "aprobada"     # aprobada formalmente por la organización (dueño del proceso)


class SourceKind(str, Enum):
    ROL = "rol"                          # perfil generado de un rol vigente asignado
    PERFIL_DIRECTO = "perfil_directo"    # perfil asignado directamente (SU01 / UST04)
    PERFIL_RESIDUAL = "perfil_residual"  # perfil generado en UST04 sin asignación vigente (falta PFUD)
    SIMULADO = "simulado"                # aportado por un escenario de simulación


@dataclass(frozen=True)
class Source:
    """Procedencia de una instancia de autorización para un usuario."""

    kind: SourceKind
    profile: str
    role: str | None = None
    via_composite: str | None = None
    valid_from: date | None = None
    valid_to: date | None = None

    def describe(self) -> str:
        if self.kind is SourceKind.ROL:
            via = f" (vía rol compuesto {self.via_composite})" if self.via_composite else ""
            return f"Rol {self.role}{via} → perfil {self.profile}"
        if self.kind is SourceKind.PERFIL_DIRECTO:
            return f"Perfil asignado directamente {self.profile}"
        if self.kind is SourceKind.PERFIL_RESIDUAL:
            return (f"Perfil {self.profile} del rol {self.role or '?'} presente en UST04 sin "
                    "asignación vigente (comparación de usuarios pendiente)")
        return f"Escenario simulado: rol {self.role} → {self.profile}"


@dataclass
class RoleAssignment:
    role: str
    valid_from: date | None
    valid_to: date | None
    via_composite: str | None = None   # AGR_USERS-COL_FLAG = 'X'
    org_flag: str = ""

    def state(self, as_of: date) -> str:
        if self.valid_from and self.valid_from > as_of:
            return "futura"
        if self.valid_to and self.valid_to < as_of:
            return "vencida"
        return "vigente"


@dataclass
class UserInfo:
    username: str
    user_type: str          # USTYP: A diálogo, B sistema, C comunicación, L referencia, S servicio
    user_group: str
    valid_from: date | None
    valid_to: date | None
    lock_flag: int          # UFLAG
    last_logon: date | None
    full_name: str = ""

    TYPE_LABELS = {"A": "Diálogo", "B": "Sistema", "C": "Comunicación",
                   "L": "Referencia", "S": "Servicio"}

    @property
    def type_label(self) -> str:
        return self.TYPE_LABELS.get(self.user_type, self.user_type or "?")

    @property
    def is_locked(self) -> bool:
        return self.lock_flag != 0

    @property
    def lock_label(self) -> str:
        if self.lock_flag == 0:
            return "Desbloqueado"
        reasons = []
        if self.lock_flag & 32:
            reasons.append("bloqueo global (CUA)")
        if self.lock_flag & 64:
            reasons.append("bloqueo administrador")
        if self.lock_flag & 128:
            reasons.append("intentos fallidos")
        if not reasons:
            reasons.append(f"UFLAG={self.lock_flag}")
        return "Bloqueado: " + ", ".join(reasons)

    def is_valid(self, as_of: date) -> bool:
        if self.valid_from and self.valid_from > as_of:
            return False
        if self.valid_to and self.valid_to < as_of:
            return False
        return True


@dataclass
class Issue:
    """Problema de calidad de datos o de consistencia que afecta la certeza."""

    code: str
    message: str
    severity: Severity = Severity.INFORMATIVO
    details: dict = field(default_factory=dict)
