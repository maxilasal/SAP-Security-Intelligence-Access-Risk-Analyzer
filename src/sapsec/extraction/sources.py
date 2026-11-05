"""Catálogo de fuentes SAP (única fuente de verdad para extracción, almacenamiento y documentación).

Cada dataset declara EXACTAMENTE qué tabla y qué campos se leen. El lector de
tablas rechaza cualquier tabla o campo fuera de esta lista (lista permitida).
Los campos de contraseñas/hashes de USR02 están explícitamente prohibidos.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Dataset:
    name: str
    table: str
    fields: tuple[str, ...]
    description: str
    client_dependent: bool
    partition_field: str | None = None    # campo usado para lotes (WHERE ... IN (...))
    partition_by: str | None = None       # dataset/columna que provee las claves de partición
    fixed_where: tuple[str, ...] = ()     # condiciones fijas (sintaxis Open SQL de RFC_READ_TABLE)
    required: bool = True                 # si falta, el snapshot queda marcado como incompleto
    sensitive: bool = False               # requiere aprobación explícita de lectura
    authorization: str = ""               # autorización de lectura necesaria (documentación)
    limitations: str = ""


# Campos que NUNCA deben leerse, aunque la tabla esté permitida.
FORBIDDEN_FIELDS: dict[str, frozenset[str]] = {
    "USR02": frozenset({"BCODE", "PASSCODE", "PWDSALTEDHASH", "CODVN", "CODVC", "CODVS",
                        "OCOD1", "OCOD2", "OCOD3", "OCOD4", "OCOD5", "PWDINITIAL",
                        "PWDHISTORY", "SECURITY_POLICY"}),
    "USH02": frozenset({"BCODE", "PASSCODE", "PWDSALTEDHASH", "OCOD1", "OCOD2", "OCOD3",
                        "OCOD4", "OCOD5"}),
    "USRPWDHISTORY": frozenset({"*"}),
}

# Tablas cuya lectura nunca se permite (contienen secretos o datos innecesarios).
FORBIDDEN_TABLES = frozenset({"USRPWDHISTORY", "RFCDES", "RSECTAB", "USR02_CHANGES", "SNCSYSACL"})

_AUTH_TABU = "S_TABU_NAM ACTVT=03 TABLE={t} (sin S_TABU_DIS amplio)"

DATASETS: tuple[Dataset, ...] = (
    Dataset("usr02", "USR02",
            ("BNAME", "USTYP", "CLASS", "GLTGV", "GLTGB", "UFLAG", "TRDAT", "LTIME", "ERDAT", "ANAME"),
            "Datos de logon: tipo, grupo, validez, bloqueo, último acceso.", True,
            sensitive=True, authorization=_AUTH_TABU.format(t="USR02"),
            limitations="Tabla con hashes de contraseña: solo se leen campos permitidos. "
                        "Alternativa sin S_TABU_NAM: BAPI_USER_GET_DETAIL por usuario (sin último acceso)."),
    Dataset("agr_define", "AGR_DEFINE",
            ("AGR_NAME", "PARENT_AGR", "CREATE_USR", "CREATE_DAT", "CHANGE_USR", "CHANGE_DAT"),
            "Definición de roles y rol padre (derivados).", True,
            authorization=_AUTH_TABU.format(t="AGR_DEFINE")),
    Dataset("agr_texts", "AGR_TEXTS", ("AGR_NAME", "SPRAS", "LINE", "TEXT"),
            "Textos de roles (solo línea 00000 = descripción breve).", True,
            fixed_where=("LINE = '00000'",), authorization=_AUTH_TABU.format(t="AGR_TEXTS")),
    Dataset("agr_flags", "AGR_FLAGS", ("AGR_NAME", "FLAG_TYPE", "FLAG_VALUE"),
            "Atributos de roles (COLL_AGR = rol compuesto).", True,
            fixed_where=("FLAG_TYPE = 'COLL_AGR'",), required=False,
            authorization=_AUTH_TABU.format(t="AGR_FLAGS"),
            limitations="Si no está disponible, la composición se deduce de AGR_AGRS."),
    Dataset("agr_agrs", "AGR_AGRS", ("AGR_NAME", "CHILD_AGR"),
            "Roles compuestos → roles simples componentes.", True,
            authorization=_AUTH_TABU.format(t="AGR_AGRS")),
    Dataset("agr_users", "AGR_USERS",
            ("AGR_NAME", "UNAME", "FROM_DAT", "TO_DAT", "EXCLUDE", "CHANGE_DAT", "ORG_FLAG", "COL_FLAG"),
            "Asignación de roles a usuarios con validez.", True,
            partition_field="UNAME", partition_by="usr02.BNAME",
            authorization=_AUTH_TABU.format(t="AGR_USERS"),
            limitations="COL_FLAG='X' indica asignación heredada de un rol compuesto."),
    Dataset("agr_1016", "AGR_1016", ("AGR_NAME", "COUNTER", "PROFILE", "VARIANT", "GENERATED", "PSTATE"),
            "Perfiles generados de cada rol.", True,
            authorization=_AUTH_TABU.format(t="AGR_1016")),
    Dataset("agr_1251", "AGR_1251",
            ("AGR_NAME", "COUNTER", "OBJECT", "AUTH", "VARIANT", "FIELD", "LOW", "HIGH", "MODIFIED", "DELETED"),
            "Valores de autorización definidos en PFCG.", True,
            partition_field="AGR_NAME", partition_by="agr_define.AGR_NAME",
            authorization=_AUTH_TABU.format(t="AGR_1251"),
            limitations="Es la definición del rol, no lo que el usuario tiene: puede diferir del perfil."),
    Dataset("agr_1252", "AGR_1252", ("AGR_NAME", "COUNTER", "VARBL", "LOW", "HIGH"),
            "Niveles organizativos de roles.", True, authorization=_AUTH_TABU.format(t="AGR_1252")),
    Dataset("agr_tcodes", "AGR_TCODES", ("AGR_NAME", "TYPE", "TCODE", "EXCLUDE", "DIRECT", "INHERITED"),
            "Menú del rol (transacciones, servicios, catálogos).", True,
            authorization=_AUTH_TABU.format(t="AGR_TCODES"),
            limitations="El menú no autoriza: la autorización real es S_TCODE en el perfil."),
    Dataset("ust04", "UST04", ("BNAME", "PROFILE"),
            "Perfiles asignados al usuario (directos y generados tras comparación).", True,
            partition_field="BNAME", partition_by="usr02.BNAME",
            authorization=_AUTH_TABU.format(t="UST04")),
    Dataset("ust10c", "UST10C", ("PROFN", "AKTPS", "SUBPROF"),
            "Perfiles compuestos → subperfiles.", True, fixed_where=("AKTPS = 'A'",),
            authorization=_AUTH_TABU.format(t="UST10C")),
    Dataset("ust10s", "UST10S", ("PROFN", "AKTPS", "OBJCT", "AUTH"),
            "Perfiles simples → autorizaciones (objeto, autorización).", True,
            fixed_where=("AKTPS = 'A'",), authorization=_AUTH_TABU.format(t="UST10S")),
    Dataset("ust12", "UST12", ("OBJCT", "AUTH", "AKTPS", "FIELD", "VON", "BIS"),
            "Valores de campos de cada autorización activa.", True,
            fixed_where=("AKTPS = 'A'",), partition_field="OBJCT", partition_by="ust10s.OBJCT",
            authorization=_AUTH_TABU.format(t="UST12"),
            limitations="Tabla de gran volumen: se lee particionada por objeto."),
    Dataset("tobj", "TOBJ",
            ("OBJCT", "OCLSS", "FIEL1", "FIEL2", "FIEL3", "FIEL4", "FIEL5", "FIEL6", "FIEL7",
             "FIEL8", "FIEL9", "FIEL0"),
            "Objetos de autorización y sus campos.", False,
            authorization=_AUTH_TABU.format(t="TOBJ")),
    Dataset("tobjt", "TOBJT", ("OBJECT", "LANGU", "TTEXT"), "Textos de objetos.", False,
            required=False, authorization=_AUTH_TABU.format(t="TOBJT")),
    Dataset("tact", "TACTT", ("SPRAS", "ACTVT", "LTEXT"), "Textos de actividades ACTVT.", False,
            required=False, authorization=_AUTH_TABU.format(t="TACTT")),
    Dataset("tstc", "TSTC", ("TCODE", "PGMNA"), "Transacciones → programa.", False,
            required=False, authorization=_AUTH_TABU.format(t="TSTC")),
    Dataset("tstct", "TSTCT", ("SPRSL", "TCODE", "TTEXT"), "Textos de transacciones.", False,
            required=False, authorization=_AUTH_TABU.format(t="TSTCT")),
    Dataset("tstca", "TSTCA", ("TCODE", "OBJCT", "FIELD", "VALUE"),
            "Chequeo de autorización de inicio de transacción (SE93).", False,
            required=False, authorization=_AUTH_TABU.format(t="TSTCA")),
    Dataset("usobhash", "USOBHASH", ("NAME", "PGMID", "OBJECT", "OBJ_NAME", "TYPE"),
            "Hash de S_SERVICE → servicio OData/ICF real.", False,
            required=False, authorization=_AUTH_TABU.format(t="USOBHASH"),
            limitations="Necesario para interpretar SRV_NAME de S_SERVICE (Fiori/OData)."),
    Dataset("usobx_c", "USOBX_C", ("NAME", "TYPE", "OBJECT", "OKFLAG"),
            "SU24: indicador de verificación transacción/servicio → objeto (X/Y = se verifica).", False,
            required=False, authorization=_AUTH_TABU.format(t="USOBX_C"),
            limitations="Se lee solo para las transacciones de las reglas (TYPE TR) y, en sistemas con Fiori, para "
                        "los servicios OData (TYPE HT) que verifican los objetos de las reglas."),
    Dataset("usobt_c", "USOBT_C", ("NAME", "TYPE", "OBJECT", "FIELD", "LOW", "HIGH"),
            "SU24: valores propuestos por transacción o servicio.", False,
            required=False, authorization=_AUTH_TABU.format(t="USOBT_C")),
    Dataset("cvers", "CVERS", ("COMPONENT", "RELEASE", "EXTRELEASE", "COMP_TYPE"),
            "Componentes de software (S/4HANA, ECC, Gateway, Fiori) para identificar el producto.", False,
            required=False, authorization=_AUTH_TABU.format(t="CVERS"),
            limitations="Solo identifica el producto; si no se puede leer, se informa como desconocido."),
)

DATASETS_BY_NAME: dict[str, Dataset] = {d.name: d for d in DATASETS}


def allowed_tables() -> dict[str, frozenset[str]]:
    """Tabla → campos permitidos (unión de todos los datasets)."""
    result: dict[str, set[str]] = {}
    for d in DATASETS:
        result.setdefault(d.table, set()).update(d.fields)
    return {t: frozenset(f) for t, f in result.items()}


@dataclass
class DatasetStats:
    dataset: str
    rows: int = 0
    calls: int = 0
    status: str = "pendiente"   # ok | incompleto | sin_autorizacion | error | omitido
    message: str = ""
    method: str = ""
    extra: dict = field(default_factory=dict)
