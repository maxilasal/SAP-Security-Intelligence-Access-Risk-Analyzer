"""Motor de puntuación de riesgos transparente y configurable.

puntos(hallazgo) = puntos_gravedad × factor_sistema × factor_tipo_usuario × factor_certeza
riesgo_inherente  = Σ puntos (potencial; ignora el bloqueo del usuario)
riesgo_actual     = inherente × factor_bloqueo (si el usuario está bloqueado o fuera de validez)
riesgo_residual   = Σ puntos × (1 − eficacia del control mitigante aprobado y vigente)

El nivel se obtiene de umbrales configurables sobre la puntuación. Cada número
va acompañado de su desglose; no hay valores generados por IA.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any

from ..domain.models import Severity, UserInfo

DEFAULT_SCORING: dict[str, Any] = {
    "severity_points": {"critico": 100, "alto": 40, "medio": 15, "bajo": 5, "informativo": 0},
    "user_type_factor": {"A": 1.0, "S": 1.0, "C": 0.9, "B": 0.8, "L": 0.7},
    "certainty_factor": {"definido_en_rol": 0.8, "en_perfil": 0.9, "asignado": 1.0,
                         "capacidad_potencial": 1.0, "confirmado_en_sap": 1.0},
    "inactive_user_factor": 0.2,
    "level_thresholds": {"critico": 100, "alto": 40, "medio": 15, "bajo": 1},
}


@dataclass
class ScoredItem:
    ref: str
    title: str
    severity: Severity
    base: float
    factors: dict[str, float]
    inherent: float
    mitigation: str | None = None
    residual: float = 0.0


@dataclass
class RiskProfile:
    inherent_score: float
    current_score: float
    residual_score: float
    inherent_level: Severity
    current_level: Severity
    residual_level: Severity
    items: list[ScoredItem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class RiskScorer:
    def __init__(self, config: dict[str, Any] | None = None):
        cfg = dict(DEFAULT_SCORING)
        for k, v in (config or {}).items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k] = {**cfg[k], **v}
            else:
                cfg[k] = v
        self.cfg = cfg

    def level(self, score: float) -> Severity:
        th = self.cfg["level_thresholds"]
        for name in ("critico", "alto", "medio", "bajo"):
            if score >= float(th[name]):
                return Severity(name)
        return Severity.INFORMATIVO

    def score(self, findings: list[dict[str, Any]], user: UserInfo | None, system_factor: float,
              as_of: date, mitigations: dict[str, tuple[str, float]] | None = None) -> RiskProfile:
        """``findings``: dicts con ref, title, severity, certainty.
        ``mitigations``: ref → (código de control, eficacia 0..1), solo controles aprobados y vigentes."""
        mitigations = mitigations or {}
        pts = self.cfg["severity_points"]
        utf = self.cfg["user_type_factor"].get(user.user_type, 1.0) if user else 1.0
        items: list[ScoredItem] = []
        for f in findings:
            sev = Severity(f["severity"])
            cf = self.cfg["certainty_factor"].get(f.get("certainty", "asignado"), 1.0)
            factors = {"sistema": system_factor, "tipo_usuario": utf, "certeza": cf}
            inherent = float(pts[sev.value]) * system_factor * utf * cf
            mit = mitigations.get(f["ref"])
            residual = inherent * (1 - mit[1]) if mit else inherent
            items.append(ScoredItem(f["ref"], f["title"], sev, float(pts[sev.value]), factors,
                                    round(inherent, 1), mit[0] if mit else None, round(residual, 1)))
        inherent = round(sum(i.inherent for i in items), 1)
        residual = round(sum(i.residual for i in items), 1)
        notes: list[str] = []
        current = inherent
        if user and (user.is_locked or not user.is_valid(as_of)):
            f = float(self.cfg["inactive_user_factor"])
            current = round(inherent * f, 1)
            notes.append(f"Usuario {'bloqueado' if user.is_locked else 'fuera de validez'}: riesgo actual "
                         f"= inherente × {f}. Los permisos siguen asignados: ante una reactivación el "
                         "riesgo vuelve al nivel inherente (riesgo potencial).")
        return RiskProfile(inherent, current, residual, self.level(inherent), self.level(current),
                           self.level(residual), items, notes)
