"""La RECOMENDACIÓN de cada pantalla: una frase imperativa, por qué, pasos numerados y dónde en SAP.

Todo sale de los hallazgos y de las reglas cargadas. Los pasos nombran transacciones estándar de SAP
(PFCG, SU01, SU10, PFUD, SUPC) y nunca inventan objetos ni valores: lo concreto a cambiar (objeto,
campo, valor) está en la lista de puntos de cada tarea, que proviene de la evidencia.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .actions import SEV_RANK, Task


@dataclass
class Step:
    text: str
    link: str = ""
    link_text: str = ""


@dataclass
class Advice:
    level: str                       # critico | alto | medio | bajo | ok  (color del recuadro)
    headline: str                    # UNA frase: lo que hay que hacer
    why: str = ""                    # por qué, en una frase
    steps: list[Step] = field(default_factory=list)
    where: str = ""                  # dónde, en SAP
    impact: str = ""                 # a quién afecta
    note: str = ""                   # aviso adicional
    action: tuple[str, str] | None = None   # botón principal (texto, url)
    verdict: str = ""                # simulador: etiqueta corta (NO RECOMENDADO…)


def _n(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _join(items: list[str], last: str = " y ") -> str:
    items = [x for x in items if x]
    if not items:
        return ""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + last + items[-1]


def _resync() -> Step:
    return Step("Volver a extraer el sistema: lo corregido pasa a «resuelto» solo, sin cargar nada a mano.")


def _transport(env: str) -> str:
    if env == "PRD":
        return "Hacer el cambio en desarrollo y transportarlo a producción (no modificar roles directamente en PRD)."
    if env == "DEV":
        return "Después, transportarlo a calidad y producción según el procedimiento habitual."
    return "Transportar el cambio según el procedimiento habitual de la empresa."


def _lcfirst(text: str) -> str:
    return text[:1].lower() + text[1:] if text[:2] != text[:2].upper() else text


def _level(sev: str) -> str:
    return sev if sev in SEV_RANK and sev != "informativo" else "bajo"


# ------------------------------------------------------------------------------------------- tareas
def task_advice(t: Task, data: Any = None, env: str = "") -> Advice:
    vp = t.visible_problems
    n_users = t.n_users
    mp = t.main_problem
    one = n_users == 1
    first_user = t.users[0] if t.users else ""
    impact = f"Afecta a {_n(n_users, 'usuario')}" if n_users else ""
    if t.n_critical:
        impact += f"{' · ' if impact else ''}{t.n_critical} de gravedad crítica"
    adv = Advice(level=_level(t.severity), headline=t.title, why=mp.why, where=t.where, impact=impact)

    if t.kind == "perfil":
        prof = t.profile or t.title.replace("Quitar el perfil ", "")
        who = f"a {first_user}" if one and first_user else f"a estos {n_users} usuarios"
        adv.headline = (f"Quitar el perfil {prof} {who} y {'asignarle' if one else 'asignarles'} solo los roles "
                        f"que {'necesita' if one else 'necesitan'}.")
        others = len(vp) - 1
        if others > 0:
            rest = "el otro riesgo de la lista" if others == 1 else f"los otros {others} riesgos de la lista"
            adv.why = (mp.why + f" Al quitarlo desaparece también {rest}." if others == 1 else
                       mp.why + f" Al quitarlo desaparecen también {rest}.").strip()
        steps = [Step(f"Confirmar con el responsable qué tareas hace {'el usuario' if one else 'cada usuario'}.")]
        if prof == "SAP_ALL":
            steps.append(Step("Si se usa para emergencias: un usuario de emergencia, bloqueado, que se habilita solo con "
                              "aprobación y cuyo uso queda registrado y se revisa."))
        steps += [Step(f"SU01 › usuario › Modificar › pestaña Perfiles › borrar {prof} › Grabar. "
                       "Para varios usuarios a la vez: SU10."),
                  Step("Asignar en la pestaña Roles solo los roles que necesita (probarlo antes en el simulador).",
                       f"/simulador?usuario={first_user}" if first_user else "/simulador", "Simular"),
                  _resync()]
        adv.steps = steps
    elif t.kind == "rol":
        r = t.roles[0] if t.roles else ""
        parent = (data.role_parent.get(r, "") if data is not None else "") or ""
        sod = [p for p in vp if p.kind == "sod"]
        crit = [p for p in vp if p.kind != "sod"]
        if sod and crit:
            adv.headline = (f"Corregir el rol {r}: quitar o restringir {_n(len(crit), 'permiso de riesgo', 'permisos de riesgo')} "
                            "y separar las funciones incompatibles que combina.")
        elif sod:
            adv.headline = (f"Dividir el rol {r}: por sí solo permite «{sod[0].title}»." if len(sod) == 1 else
                            f"Dividir el rol {r}: por sí solo combina {len(sod)} pares de funciones incompatibles.")
        else:
            adv.headline = (f"Quitar o restringir en el rol {r} "
                            + ("el permiso de riesgo que se detalla abajo." if len(crit) == 1 else
                               f"los {len(crit)} permisos de riesgo que se detallan abajo."))
        composite = data is not None and data.role_type(r) == "compuesto"
        if composite:
            children = list(data.composite_children.get(r, []))
            steps = [Step(f"Es un rol compuesto: no tiene permisos propios, los recibe de sus roles simples"
                          f"{' (' + _join(children[:4]) + ')' if children else ''}."),
                     Step("Quitar del compuesto el rol simple que aporta una de las funciones incompatibles, o "
                          "corregir ese rol simple (ver «Aportado por» en la ficha del rol)."),
                     Step(_transport(env)), _resync()]
        else:
            steps = [Step(f"El rol es derivado de {parent}: los permisos se cambian en {parent} (PFCG) y se "
                          "transfieren a sus derivados.", f"/roles/{parent}", f"Ver {parent}") if parent else
                     Step(f"PFCG › {r} › Modificar › pestaña Autorizaciones › Modificar datos de autorización.")]
            if crit:
                steps.append(Step("En cada punto de la lista de abajo: borrar el valor indicado o cambiar el comodín "
                                  "(*) por los valores que el puesto realmente necesita."))
            if sod:
                steps.append(Step("Para las funciones incompatibles: pasar una de ellas a un rol nuevo y asignarlo "
                                  "solo a quien la necesite."))
            steps += [Step("Generar el perfil (botón Generar). " + _transport(env)), _resync()]
        adv.steps = steps
        adv.where = f"PFCG › {parent or r} › {'Roles (del compuesto)' if composite else 'Autorizaciones'}"
        if n_users:
            adv.note = ("Antes de cambiarlo, avisar al responsable del usuario que tiene el rol: perderá esos permisos."
                        if one else f"Antes de cambiarlo, avisar al responsable de los {n_users} usuarios que tienen el "
                                    "rol: perderán esos permisos.")
    elif t.kind == "combinacion":
        roles = t.roles
        pair = f"los roles {_join(roles)}" if len(roles) <= 3 else f"estos {len(roles)} roles"
        who = f"a {first_user}" if one and first_user else f"a cada uno de los {n_users} usuarios"
        adv.headline = f"No dejar {pair} juntos en un mismo usuario: quitarle uno {who}."
        adv.steps = [
            Step("Decidir con el responsable del proceso qué rol necesita realmente cada usuario "
                 "(la tabla de abajo muestra cuáles tiene)."),
            Step("Probar el cambio con «Simular quitar…» en la tabla: confirma que el conflicto desaparece."),
            Step("SU01 › usuario › Modificar › pestaña Roles › borrar el rol que sobra › Grabar. "
                 "Para varios usuarios a la vez: SU10."),
            Step("Si alguien necesita los dos (por ejemplo, en un equipo chico): registrar abajo la decisión con un "
                 "control mitigante y fecha de vencimiento."),
            _resync()]
        adv.where = "SU01 / SU10 › pestaña Roles de cada usuario"
    elif t.kind == "usuarios":
        if t.rule_id == "CRIT-STD-001":
            adv.headline = (f"Bloquear o asegurar {_n(n_users, 'usuario estándar', 'usuarios estándar')} de SAP que "
                            f"hoy {'puede' if one else 'pueden'} ingresar.")
            adv.steps = [Step("Revisar con Basis cada usuario: bloquear los que no se usan (SU01 › Bloquear/Desbloquear "
                              "› Bloquear)."),
                         Step("A los que se usan para tareas técnicas: cambiarles la contraseña por una larga y "
                              "desconocida, y dejarlos con el tipo de usuario adecuado (no de diálogo si no hace falta)."),
                         _resync()]
        elif t.rule_id == "CRIT-USR-INA-001":
            adv.headline = (f"Bloquear {_n(n_users, 'usuario')} que no "
                            f"{'ingresa' if one else 'ingresan'} hace mucho tiempo, si ya no se "
                            f"{'usa' if one else 'usan'}.")
            adv.steps = [Step("Confirmar con cada área si el usuario sigue en uso."),
                         Step("SU01 › Bloquear; y en la pestaña Datos de logon, fijar «Válido hasta» con la fecha de "
                              "baja. Para varios a la vez: SU10."),
                         _resync()]
        else:
            adv.headline = t.what or t.title
            adv.steps = [Step(t.what), _resync()] if t.what else [_resync()]
        adv.where = "SU01 / SU10"
    elif t.kind == "calidad":
        k = len(vp)
        adv.headline = (f"Generar el perfil de {_n(k, 'rol', 'roles')} y actualizar a sus usuarios "
                        "(comparación de usuarios).")
        adv.why = ("Lo definido en PFCG no es lo que los usuarios tienen realmente: pueden tener más o menos permisos "
                   "que los esperados.")
        adv.impact = _n(k, "rol", "roles")
        adv.steps = [Step("PFCG › rol › pestaña Autorizaciones › Generar perfil. Para muchos roles a la vez: SUPC."),
                     Step("Ejecutar PFUD (comparación de usuarios) para que cada usuario reciba el perfil actualizado.")]
        if env == "PRD":
            adv.steps.append(Step(_transport(env)))
        adv.steps.append(_resync())
    else:  # perfil_otro
        adv.headline = (f"Quitar los perfiles asignados a mano a {_n(n_users, 'usuario')} y "
                        f"{'darle' if one else 'darles'} roles en su lugar.")
        adv.steps = [Step("Abrir cada usuario de la tabla: en «Qué corregir» figura qué perfil le da el permiso."),
                     Step("Si el perfil es de un rol vencido o quitado (perfil residual), ejecutar PFUD; si fue "
                          "asignado a mano, borrarlo en SU01 › pestaña Perfiles."),
                     Step("Si necesita el permiso, asignarle el rol que corresponda (probarlo antes en el simulador).",
                          "/simulador", "Simular"),
                     _resync()]
    if not t.pending:
        adv.level = "ok"
        adv.note = "Esta tarea ya está resuelta o tiene una decisión registrada (excepción, control mitigante…)."
    return adv


def home_advice(t: Task | None, data: Any = None, env: str = "") -> Advice:
    if t is None:
        return Advice("ok", "No hay nada urgente para corregir según las reglas evaluadas.",
                      why="No se detectaron permisos críticos ni conflictos de funciones abiertos.",
                      steps=[Step("Antes de asignar un rol nuevo a alguien, simularlo.", "/simulador", "Simular")])
    adv = task_advice(t, data, env)
    adv.steps = []          # en el inicio, solo la frase: los pasos están en la tarea
    adv.note = ""
    adv.action = ("Ver cómo hacerlo ›", f"/acciones/{t.key}")
    return adv


# ---------------------------------------------------------------------------------- ficha de usuario
def user_advice(username: str, user: Any, fixes: list[dict[str, Any]], profiles: list[str], inactive_days: int | None,
                inactivity_limit: int) -> Advice:
    if not fixes:
        adv = Advice("ok", f"{username} no requiere cambios según las reglas evaluadas.",
                     why="No tiene permisos críticos ni combinaciones de funciones incompatibles.",
                     steps=[Step("Antes de asignarle un rol nuevo, simularlo (o revisar la lista «Antes de asignarle un "
                                 "rol nuevo»).", f"/simulador?usuario={username}", "Simular")])
    else:
        groups: dict[str, dict[str, Any]] = {}
        for f in fixes:  # ya vienen ordenados por gravedad
            g = groups.setdefault(f.get("task") or f["title"], {"items": [], "f": f})
            g["items"].append(f)
        ordered = sorted(groups.values(), key=lambda g: (-max(SEV_RANK.get(x["severity"], 0) for x in g["items"]),
                                                         -len(g["items"])))

        def sentence(g: dict[str, Any]) -> str:
            f, n = g["f"], len(g["items"])
            cause, roles = f.get("cause", ""), f.get("roles") or []
            if cause == "perfil" and f.get("profile"):
                return f"Quitarle el perfil {f['profile']} y asignarle solo los roles que necesita"
            if cause == "perfil" or cause == "perfil_otro":
                return "Quitarle los perfiles asignados a mano" + (f" ({', '.join(profiles[:3])})" if profiles else "") \
                    + " y darle roles en su lugar"
            if cause == "combinacion" and roles:
                return f"Quitarle uno de estos roles: {_join(roles, ' o ')} (juntos le permiten «{f['title']}»)"
            if cause == "rol" and roles:
                extra = f" y {_n(n - 1, 'punto más', 'puntos más')}" if n > 1 else ""
                return f"Corregir el rol {roles[0]}, que le da «{f['title']}»{extra} (o quitárselo si no lo necesita)"
            return f.get("change") or f["title"]

        top = ordered[0]
        adv = Advice(_level(top["f"]["severity"]), f"{sentence(top)}.",
                     why=top["f"].get("why", ""),
                     impact=f"{_n(len(fixes), 'punto', 'puntos')} a corregir en {_n(len(ordered), 'cambio', 'cambios')}")
        adv.steps = [Step(f"{sentence(g)}.", f"/acciones/{g['f']['task']}" if g["f"].get("task") else "",
                          "Ver cómo") for g in ordered[:4]]
        if len(ordered) > 4:
            adv.steps.append(Step(f"…y {_n(len(ordered) - 4, 'cambio más', 'cambios más')} (lista completa abajo)."))
        if len(ordered) == 1:
            adv.steps = adv.steps[:1] + [_resync()]
        causes = {g["f"].get("cause", "") for g in ordered}
        where = []
        if "combinacion" in causes:
            where.append("SU01 › pestaña Roles")
        if causes & {"perfil", "perfil_otro"}:
            where.append("SU01 › pestaña Perfiles")
        if "rol" in causes:
            where.append("PFCG (el rol)")
        if "usuarios" in causes:
            where.append("SU01")
        adv.where = " · ".join(dict.fromkeys(where))
    notes = []
    if getattr(user, "is_locked", False):
        notes.append("Está bloqueado: hoy no puede ingresar. Igual conviene corregirlo para que no recupere estos "
                     "permisos si lo desbloquean.")
    if inactive_days is not None and inactive_days > inactivity_limit and not getattr(user, "is_locked", False):
        notes.append(f"No ingresa hace {inactive_days} días: si ya no lo usa, alcanza con bloquearlo y quitarle los "
                     "roles.")
    adv.note = " ".join(notes)
    return adv


# ------------------------------------------------------------------------------------- ficha de rol
def role_advice(role: str, role_type: str, fixes: list[dict[str, Any]], parent: str, n_users: int, env: str,
                task_key: str | None) -> Advice:
    crit = [f for f in fixes if f.get("cause") == "critica"]
    sod = [f for f in fixes if f.get("cause") == "sod"]
    quality = [f for f in fixes if f.get("cause") == "calidad"]
    impact = f"{_n(n_users, 'usuario tiene', 'usuarios tienen')} este rol" if n_users else "Ningún usuario tiene este rol"
    if crit or sod:
        if sod and crit:
            head = (f"Corregir este rol: quitar o restringir {_n(len(crit), 'permiso de riesgo', 'permisos de riesgo')} y "
                    "separar las funciones incompatibles que combina.")
        elif sod:
            head = (f"Dividir este rol: por sí solo permite «{sod[0]['title']}»." if len(sod) == 1 else
                    f"Dividir este rol: por sí solo combina {len(sod)} pares de funciones incompatibles.")
        else:
            head = ("Quitar o restringir el permiso de riesgo de este rol (detalle abajo)." if len(crit) == 1 else
                    f"Quitar o restringir los {len(crit)} permisos de riesgo de este rol (detalle abajo).")
        sev = max((f["severity"] for f in crit + sod), key=lambda s: SEV_RANK.get(s, 0))
        if role_type == "compuesto":
            steps = [Step("Es un rol compuesto: no tiene permisos propios, los recibe de sus roles simples "
                          "(ver «Aportado por» en el detalle técnico)."),
                     Step("Quitar del compuesto el rol simple que aporta el problema, o corregir ese rol simple."),
                     Step(_transport(env)), _resync()]
        else:
            steps = [Step(f"El rol es derivado de {parent}: los permisos se cambian en {parent} y se transfieren a "
                          "sus derivados.", f"/roles/{parent}", f"Ver {parent}") if parent else
                     Step(f"PFCG › {role} › Modificar › pestaña Autorizaciones › Modificar datos de autorización.")]
            if crit:
                steps.append(Step("Borrar el valor indicado en cada punto de «Qué corregir en este rol» o cambiar el "
                                  "comodín (*) por los valores necesarios."))
            if sod:
                steps.append(Step("Pasar una de las funciones incompatibles a un rol nuevo y asignarlo solo a quien la "
                                  "necesite."))
            steps += [Step("Generar el perfil. " + _transport(env)), _resync()]
        adv = Advice(_level(sev), head, why=(crit + sod)[0].get("why", ""), steps=steps,
                     where=f"PFCG › {parent or role} › {'Roles' if role_type == 'compuesto' else 'Autorizaciones'}",
                     impact=impact)
        if task_key:
            adv.action = ("Ver la tarea completa, con los usuarios afectados ›", f"/acciones/{task_key}")
    elif quality:
        adv = Advice("medio" if any(q["severity"] == "medio" for q in quality) else "bajo",
                     f"Mejorar el rol: {_lcfirst(quality[0]['change'].rstrip('.'))}.",
                     why="No es un riesgo directo, pero dificulta saber qué permisos da el rol.",
                     steps=[Step(q["change"]) for q in quality[:4] if q.get("change")], where=f"PFCG › {role}",
                     impact=impact)
    else:
        adv = Advice("ok", "Este rol no tiene problemas según las reglas evaluadas.",
                     why="No da permisos críticos ni combina funciones incompatibles por sí solo.",
                     steps=[Step("Antes de asignarlo a alguien, revisar «No combinar con» o simular la asignación.",
                                 f"/simulador?agregar={role}", "Simular")], impact=impact)
    if role_type == "compuesto" and not (crit or sod):
        adv.note = "Rol compuesto: los permisos vienen de sus roles simples; las correcciones se hacen en cada uno."
    return adv


# ------------------------------------------------------------------------------------------ simulador
def simulation_advice(r: Any) -> Advice:
    from .engine.simulator import APROBACION, LABELS, NO_RECOMENDADO
    add, rem = r.scenario.add_roles, r.scenario.remove_roles
    user, roles = r.username, _join(add)
    risks = [f"Le permitiría «{h.title}»: tendría a la vez " + _join([f"«{m.title}»" for m in h.functions])
             for h in r.new_sod]
    risks += [f"Le daría un permiso crítico: «{h.title}»" for h in r.new_critical]
    quality = [x.replace("[Calidad de datos] ", "") for x in r.reasons if x.startswith("[Calidad")]
    if r.recommendation == NO_RECOMENDADO:
        adv = Advice("critico", f"No asignar {roles} a {user}." if add else "No aplicar este cambio.")
    elif r.recommendation == APROBACION:
        if add:
            head = f"Se puede asignar {roles} a {user}: no le agrega riesgos según las reglas evaluadas."
        elif rem:
            k = len(r.resolved_sod) + len(r.resolved_critical)
            head = f"Se puede quitar {_join(rem)} a {user}" + (f": elimina {_n(k, 'riesgo')}." if k else
                                                                 ": no le agrega riesgos.")
        else:
            head = "No hay cambios para evaluar."
        adv = Advice("ok", head)
    else:
        adv = Advice("medio", f"Asignar {roles} a {user} solo con la aprobación del responsable del proceso." if add
                     else "Aplicar el cambio solo con la aprobación del responsable del proceso.")
    adv.verdict = LABELS[r.recommendation]
    adv.why = (risks[0] + (f", y {_n(len(risks) - 1, 'riesgo nuevo más', 'riesgos nuevos más')}" if len(risks) > 1
                           else "") + ".") if risks else (quality[0] if quality else "")
    steps: list[Step] = []
    if r.recommendation != APROBACION:
        safe = [a for a in r.alternatives if a.new_sod == 0 and a.new_critical == 0 and a.tcode_coverage >= 0.5]
        if safe:
            a = safe[0]
            steps.append(Step(f"En su lugar, evaluar el rol {a.role}: cubre el {round(a.tcode_coverage * 100)}% de las "
                              "transacciones pedidas sin riesgos nuevos (confirmarlo con el dueño del proceso).",
                              f"/roles/{a.role}", f"Ver {a.role}"))
        if r.new_sod:
            brought = [m.title for h in r.new_sod for m in h.functions if set(m.roles) & set(add)]
            steps.append(Step("Confirmar con el responsable del proceso si la persona realmente necesita las dos "
                              "funciones" + (f"; si no, pedir un rol que no incluya «{brought[0]}»." if brought else ".")))
            steps.append(Step("Si es indispensable: asignarlo con un control mitigante documentado y con vencimiento."))
        elif r.new_critical:
            steps.append(Step("Pedir un rol sin ese permiso crítico, o restringirlo en PFCG a lo que el puesto necesita."))
        if quality:
            steps.append(Step("Actualizar los datos (nueva extracción) antes de decidir."))
    else:
        if add:
            steps.append(Step("Asignarlo en SU01 › pestaña Roles (o por el circuito habitual de altas)."))
        elif rem:
            steps.append(Step("Quitarlo en SU01 › pestaña Roles (para varios usuarios: SU10)."))
        steps.append(_resync())
    adv.steps = steps
    adv.where = "SU01 › pestaña Roles"
    return adv


# ------------------------------------------------------------------------------ entre sistemas (DEV ↔ PRD)
def cross_advice(x: dict[str, Any]) -> Advice:
    rows = x.get("rows", [])
    if not x.get("dev") or not x.get("prd"):
        return Advice("bajo", "Para este control hace falta al menos un sistema DEV y uno PRD extraídos.",
                      why="Compara quién desarrolla en DEV con lo que esa misma persona puede hacer en producción.",
                      steps=[Step("Registrar los sistemas de desarrollo con ambiente DEV y el mismo «landscape» que su "
                                  "producción (Conexiones SAP).", "/conexiones", "Conexiones"),
                             Step("Extraer los dos sistemas.")])
    if not rows:
        return Advice("ok", "Ningún desarrollador de DEV tiene permisos críticos en producción.",
                      why="Es el control más importante entre ambientes: quien escribe el código no debería poder "
                          "llevarlo a producción ni saltear controles allí.")
    users = sorted({r["user"] for r in rows})
    n = len(users)
    head = (f"Quitar en producción los permisos críticos a {users[0]}, que también desarrolla en DEV." if n == 1 else
            f"Quitar en producción los permisos críticos a estos {n} desarrolladores de DEV.")
    worst = max(rows, key=lambda r: SEV_RANK.get(r["severity"], 0))["severity"]
    return Advice(_level(worst), head,
                  why="Quien escribe código en DEV y además puede importar, depurar con modificación o administrar en "
                      "PRD podría llevar a producción un cambio propio sin control de un tercero.",
                  steps=[Step("Revisar con cada persona si necesita ese acceso en PRD (en general, no)."),
                         Step("En PRD: SU01 › usuario › pestaña Roles/Perfiles › quitar el rol o perfil que da el "
                              "permiso (en la ficha del usuario figura cuál es)."),
                         Step("Si hace falta para urgencias: un usuario de emergencia aparte, bloqueado, que se "
                              "habilita con aprobación y deja registro."),
                         Step("Volver a extraer PRD: el caso desaparece de esta lista solo.")],
                  where="SU01 en el sistema productivo", impact=f"{_n(n, 'persona', 'personas')}")
