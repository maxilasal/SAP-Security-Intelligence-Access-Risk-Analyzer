"""Motor de autorizaciones efectivas.

Reconstruye el conjunto de autorizaciones que un usuario tiene en su maestro
(UST04 → UST10C → UST10S → UST12) y atribuye cada instancia a su procedencia
(rol vigente, perfil directo o perfil residual). Detecta además:

* roles vigentes cuyo perfil NO está en UST04 (comparación de usuarios pendiente),
* perfiles en UST04 de roles sin asignación vigente (perfil residual),
* roles con perfil no generado o desactualizado (AGR_1251 ≠ UST12),
* variables organizativas sin resolver.

La certeza máxima alcanzable solo con tablas es ``ASIGNADO``: lo que el usuario
puede ejecutar depende además de los AUTHORITY-CHECK de cada programa.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date

from ..domain.models import Certainty, Issue, RoleAssignment, Severity, Source, SourceKind, UserInfo
from ..storage.snapshot_data import SnapshotData
from .values import AuthInstance, FieldValue


@dataclass
class EffectiveInstance:
    instance: AuthInstance
    sources: list[Source] = field(default_factory=list)
    certainty: Certainty = Certainty.ASIGNADO

    @property
    def roles(self) -> list[str]:
        return sorted({s.role for s in self.sources if s.role})

    def provenance(self) -> str:
        return "; ".join(s.describe() for s in self.sources)


@dataclass
class EffectiveAuthorizations:
    username: str
    as_of: date
    user: UserInfo | None
    assignments: list[RoleAssignment]
    profiles: list[str]                       # perfiles en UST04 (o escenario)
    instances: dict[tuple[str, str], EffectiveInstance]
    issues: list[Issue] = field(default_factory=list)
    is_simulation: bool = False

    def all_instances(self) -> list[AuthInstance]:
        return [e.instance for e in self.instances.values()]

    def by_object(self, obj: str) -> list[EffectiveInstance]:
        idx = self.__dict__.get("_by_obj")
        if idx is None or self.__dict__.get("_by_obj_n") != len(self.instances):
            idx = {}
            for e in self.instances.values():
                idx.setdefault(e.instance.object, []).append(e)
            self.__dict__["_by_obj"], self.__dict__["_by_obj_n"] = idx, len(self.instances)
        return idx.get(obj, [])

    def objects(self) -> set[str]:
        return {k[0] for k in self.instances}

    def valid_roles(self) -> list[str]:
        return sorted({a.role for a in self.assignments if a.state(self.as_of) == "vigente"})

    def direct_profiles(self) -> list[str]:
        return sorted({s.profile for e in self.instances.values() for s in e.sources
                       if s.kind is SourceKind.PERFIL_DIRECTO} |
                      {p for p in self.profiles if p in self._direct})

    _direct: set[str] = field(default_factory=set)


def _composite_parents(data: SnapshotData, valid_roles: set[str]) -> dict[str, str]:
    """Rol hijo → rol compuesto vigente del usuario que lo contiene."""
    parents: dict[str, str] = {}
    for comp in valid_roles:
        for child in data.composite_children.get(comp, []):
            parents.setdefault(child, comp)
    return parents


def compute_effective(data: SnapshotData, username: str, as_of: date,
                      profiles_override: list[str] | None = None,
                      assignments_override: list[RoleAssignment] | None = None,
                      extra_instances: list[tuple[AuthInstance, Source, Certainty]] | None = None
                      ) -> EffectiveAuthorizations:
    user = data.users.get(username)
    assignments = assignments_override if assignments_override is not None else data.user_assignments(username)
    profiles = profiles_override if profiles_override is not None else list(data.user_profiles.get(username, []))
    issues: list[Issue] = []
    if user is None:
        issues.append(Issue("USUARIO_NO_ENCONTRADO", f"El usuario {username} no existe en el snapshot",
                            Severity.ALTO))

    valid = {a.role: a for a in assignments if a.state(as_of) == "vigente"}
    parents = _composite_parents(data, set(valid))
    instances: dict[tuple[str, str], EffectiveInstance] = {}
    direct: set[str] = set()

    for prof in profiles:
        role = data.profile_role.get(prof)
        if role is None:
            src = [Source(SourceKind.PERFIL_DIRECTO, prof)]
            direct.add(prof)
        elif role in valid:
            a = valid[role]
            src = [Source(SourceKind.ROL, prof, role, parents.get(role), a.valid_from, a.valid_to)]
        else:
            src = [Source(SourceKind.PERFIL_RESIDUAL, prof, role)]
            issues.append(Issue("PERFIL_RESIDUAL",
                                f"El perfil {prof} del rol {role} está en UST04 pero el rol no tiene "
                                "asignación vigente: ejecute la comparación de usuarios (PFUD).",
                                Severity.MEDIO, {"perfil": prof, "rol": role}))
        for inst in data.profile_instances(prof):
            e = instances.get(inst.key)
            if e is None:
                instances[inst.key] = EffectiveInstance(inst, list(src))
            else:
                e.sources.extend(s for s in src if s not in e.sources)

    for inst, src, cert in extra_instances or []:
        e = instances.get(inst.key)
        if e is None:
            instances[inst.key] = EffectiveInstance(inst, [src], cert)
        else:
            e.sources.append(src)

    # Roles vigentes cuyo perfil no está presente
    prof_set = set(profiles)
    for role in valid:
        if data.is_composite(role):
            continue
        rprofs = data.role_profiles.get(role, [])
        if not rprofs:
            issues.append(Issue("ROL_SIN_PERFIL", f"El rol vigente {role} no tiene perfil generado: no "
                                "aporta autorizaciones hasta generarse.", Severity.BAJO, {"rol": role}))
        elif not set(rprofs) & prof_set and profiles_override is None:
            issues.append(Issue("COMPARACION_PENDIENTE",
                                f"El rol {role} está vigente pero su perfil no está en UST04: "
                                "comparación de usuarios pendiente (PFUD).", Severity.MEDIO, {"rol": role}))

    for a in assignments:
        st = a.state(as_of)
        if st == "vencida":
            issues.append(Issue("ROL_VENCIDO", f"Asignación vencida del rol {a.role} ({a.valid_to})",
                                Severity.INFORMATIVO, {"rol": a.role}))
        elif st == "futura":
            issues.append(Issue("ROL_FUTURO", f"Asignación futura del rol {a.role} desde {a.valid_from}",
                                Severity.INFORMATIVO, {"rol": a.role}))

    for e in instances.values():
        for fname, vals in e.instance.fields.items():
            if any(v.is_unresolved_variable for v in vals):
                issues.append(Issue("VARIABLE_ORG_SIN_RESOLVER",
                                    f"{e.instance.object}-{fname} contiene una variable organizativa sin "
                                    f"valor ({', '.join(str(v) for v in vals)}); no autoriza.",
                                    Severity.BAJO, {"roles": e.roles}))

    result = EffectiveAuthorizations(username, as_of, user, assignments, profiles, instances, issues,
                                     is_simulation=profiles_override is not None or bool(extra_instances))
    result._direct = direct
    return result


# --- Consistencia de roles -------------------------------------------------------------
@dataclass
class RoleConsistency:
    role: str
    generated: bool
    profiles: list[str]
    only_in_role: list[str]      # instancias/valores en AGR_1251 ausentes en el perfil
    only_in_profile: list[str]   # valores en el perfil ausentes en AGR_1251
    unresolved_org: list[str]

    @property
    def consistent(self) -> bool:
        return self.generated and not self.only_in_role and not self.only_in_profile


def _signature(inst: AuthInstance) -> set[str]:
    return {f"{inst.object}|{inst.auth}|{f}|{v.low}|{v.high}" for f, vals in inst.fields.items() for v in vals}


def role_consistency(data: SnapshotData, role: str) -> RoleConsistency:
    defined = data.role_defined_instances(role)
    profiles = data.role_profiles.get(role, [])
    in_profile: list[AuthInstance] = []
    for p in profiles:
        in_profile += data.profile_instances(p)
    def_sig = set().union(*(_signature(i) for i in defined)) if defined else set()
    prof_sig = set().union(*(_signature(i) for i in in_profile)) if in_profile else set()
    unresolved = sorted({f"{i.object}-{f}={v}" for i in defined for f, vs in i.fields.items()
                         for v in vs if v.is_unresolved_variable})
    # Las variables sin resolver no se generan en el perfil: no cuentan como desajuste.
    def_sig_cmp = {s for s in def_sig if not s.split("|")[3].startswith("$")}
    return RoleConsistency(role, bool(profiles), profiles,
                           sorted(def_sig_cmp - prof_sig)[:200], sorted(prof_sig - def_sig)[:200], unresolved)


def role_instances_for_simulation(data: SnapshotData, role: str
                                  ) -> tuple[list[tuple[AuthInstance, Certainty, str]], list[Issue]]:
    """Instancias que aportaría un rol (simple o compuesto) si se asigna.

    Si el rol tiene perfil generado y consistente se usa el perfil (certeza EN_PERFIL);
    si no, la definición PFCG (DEFINIDO_EN_ROL) y se informa la diferencia.
    """
    issues: list[Issue] = []
    out: list[tuple[AuthInstance, Certainty, str]] = []
    roles = data.composite_children.get(role, []) if data.is_composite(role) else [role]
    if data.is_composite(role) and not roles:
        issues.append(Issue("COMPUESTO_VACIO", f"El rol compuesto {role} no tiene roles componentes",
                            Severity.BAJO))
    for r in roles:
        if r not in data.role_names:
            issues.append(Issue("ROL_INEXISTENTE", f"El rol {r} no existe en el snapshot", Severity.ALTO))
            continue
        cons = role_consistency(data, r)
        if cons.generated and cons.consistent:
            for p in cons.profiles:
                out += [(i, Certainty.EN_PERFIL, r) for i in data.profile_instances(p)]
        else:
            msg = ("no tiene perfil generado" if not cons.generated else
                   "tiene un perfil desactualizado respecto de PFCG")
            issues.append(Issue("ROL_PERFIL_INCONSISTENTE",
                                f"El rol {r} {msg}: la simulación usa la definición PFCG (AGR_1251). "
                                "El resultado real depende de la generación del perfil.",
                                Severity.MEDIO, {"rol": r}))
            out += [(i, Certainty.DEFINIDO_EN_ROL, r) for i in data.role_defined_instances(r)]
    return out, issues


def tcode_executable(eff: EffectiveAuthorizations, data: SnapshotData, tcode: str
                     ) -> tuple[bool, list[EffectiveInstance], list[str]]:
    """¿Cubre el buffer el inicio de la transacción? (S_TCODE + chequeo de inicio TSTCA)."""
    notes: list[str] = []
    s_tcode = [e for e in eff.by_object("S_TCODE") if e.instance.field_covers("TCD", tcode)]
    if not s_tcode:
        return False, [], notes
    evidence = list(s_tcode)
    checks = data.tcode_start_checks.get(tcode)
    if checks:
        for obj, fields in checks.items():
            matching = [e for e in eff.by_object(obj) if e.instance.check(dict(fields))]
            if not matching:
                notes.append(f"Falla el chequeo de inicio {obj} {fields} (TSTCA)")
                return False, evidence, notes
            evidence.append(matching[0])
    elif tcode not in data.tcode_program:
        notes.append("Sin datos TSTC/TSTCA para la transacción: chequeo de inicio no verificado")
    return True, evidence, notes


def group_values(instances: list[EffectiveInstance], field_name: str) -> list[FieldValue]:
    vals: dict[str, FieldValue] = {}
    for e in instances:
        for v in e.instance.values(field_name):
            vals[str(v)] = v
    return list(vals.values())


def summarize_objects(eff: EffectiveAuthorizations) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for k in eff.instances:
        counts[k[0]] += 1
    return dict(counts)


def role_as_effective(data: SnapshotData, role: str, as_of: date) -> EffectiveAuthorizations:
    """Autorizaciones que aporta un rol aislado (para auditoría de roles y SoD intra-rol)."""
    items, issues = role_instances_for_simulation(data, role)
    instances: dict[tuple[str, str], EffectiveInstance] = {}
    for inst, cert, r in items:
        src = Source(SourceKind.ROL, ",".join(data.role_profiles.get(r, [])) or "(sin perfil)", r,
                     role if r != role else None)
        e = instances.setdefault(inst.key, EffectiveInstance(inst, [], cert))
        if src not in e.sources:
            e.sources.append(src)
    profiles = [p for r in ([role] + data.composite_children.get(role, [])) for p in data.role_profiles.get(r, [])]
    return EffectiveAuthorizations(f"ROL:{role}", as_of, None, [RoleAssignment(role, None, None)],
                                   profiles, instances, issues)
