"""Genera tests/fixtures/demo_system.json: un sistema SAP FICTICIO para pruebas.

Todos los usuarios, roles y valores son inventados para cubrir escenarios de
prueba (SAP_ALL, compuestos, derivados, perfiles directos, vencidos, comodines,
bloqueados, SoD entre roles, perfiles no generados, etc.).

Uso:  python scripts/build_demo_fixture.py
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "demo_system.json"

TOBJ = {
    "S_TCODE": ["TCD"], "S_USER_GRP": ["ACTVT", "CLASS"], "S_USER_AGR": ["ACTVT", "ACT_GROUP"],
    "S_USER_PRO": ["ACTVT", "PROFILE"], "S_USER_AUT": ["ACTVT", "OBJECT", "AUTH"],
    "S_DEVELOP": ["ACTVT", "DEVCLASS", "OBJTYPE", "OBJNAME", "P_GROUP"],
    "S_TABU_DIS": ["ACTVT", "DICBERCLS"], "S_TABU_NAM": ["ACTVT", "TABLE"],
    "S_RFC": ["ACTVT", "RFC_NAME", "RFC_TYPE"], "S_RFCACL": ["RFC_SYSID", "RFC_CLIENT", "RFC_USER", "ACTVT"],
    "S_PROGRAM": ["P_ACTION", "P_GROUP"], "S_DATASET": ["ACTVT", "FILENAME", "PROGRAM"],
    "S_ADMI_FCD": ["S_ADMI_FCD"], "S_BTCH_ADM": ["BTCADMIN"], "S_BTCH_NAM": ["BTCUNAME"],
    "S_TRANSPRT": ["ACTVT", "TTYPE"], "S_CTS_ADMI": ["CTS_ADMFCT"], "S_SERVICE": ["SRV_NAME", "SRV_TYPE"],
    "S_ICF": ["ICF_FIELD", "ICF_VALUE"], "S_LOG_COM": ["COMMAND", "OPSYSTEM", "HOST"],
    "S_TABU_CLI": ["CLIIDMAINT"], "S_START": ["AUTHPGMID", "AUTHOBJTYP", "AUTHOBJNAM"],
    "F_REGU_BUK": ["FBTCH", "BUKRS"], "F_BKPF_BUK": ["ACTVT", "BUKRS"], "F_BKPF_KOA": ["ACTVT", "KOART"],
    "F_LFA1_APP": ["ACTVT", "APPKZ"], "B_BUPA_RLT": ["ACTVT", "RELTYP"],
    "M_BEST_BSA": ["ACTVT", "BSART"], "M_BEST_EKO": ["ACTVT", "EKORG"], "M_EINK_FRG": ["FRGGR", "FRGCO"],
    "M_BANF_BSA": ["ACTVT", "BSART"], "M_RECH_WRK": ["ACTVT", "WERKS"], "M_MSEG_BWA": ["ACTVT", "BWART"],
    "M_ISEG_WDB": ["ACTVT", "WERKS"],
}

TCODES = {"F110": "Pagos automáticos", "F-53": "Contabilizar salida de pagos", "F-58": "Pago con impresión",
          "FB60": "Registrar factura de acreedor", "MIRO": "Registrar factura recibida", "BP": "Interlocutor comercial",
          "FK02": "Modificar acreedor", "FK03": "Visualizar acreedor", "ME21N": "Crear pedido", "ME22N": "Modificar pedido",
          "ME23N": "Visualizar pedido", "ME29N": "Liberar pedido", "ME28": "Liberar pedidos (colectivo)",
          "ME51N": "Crear solicitud de pedido", "ME54N": "Liberar solicitud de pedido", "MIGO": "Movimiento de mercancías",
          "MI07": "Contabilizar diferencias de inventario", "SU01": "Mantenimiento de usuarios", "PFCG": "Mantenimiento de roles",
          "SE38": "Editor ABAP", "SE80": "Object Navigator", "STMS": "Sistema de transporte", "SM30": "Mantener vistas",
          "SE16N": "Visualizar tablas", "ZFI_REP_PAGOS": "Reporte Z de pagos", "SM18": "Borrar Security Audit Log",
          "SUIM": "Sistema de información de usuarios"}

ROLES: dict[str, dict] = {}


def role(name: str, text: str, insts: list[tuple[str, dict[str, list]]], *, generated: bool = True,
         parent: str = "", children: list[str] | None = None, stale_profile: bool = False,
         org: list[tuple[str, str]] | None = None, menu: list[str] | None = None) -> None:
    ROLES[name] = dict(text=text, insts=insts, generated=generated, parent=parent, children=children or [],
                       stale=stale_profile, org=org or [], menu=menu or [])


# ----------------------------------------------------------------------------- Roles
role("Z_FI_PROVEEDORES", "FI: mantenimiento de proveedores (BP)", [
    ("S_TCODE", {"TCD": ["BP", "FK02", "FK03"]}),
    ("B_BUPA_RLT", {"ACTVT": ["01", "02", "03"], "RELTYP": ["FLVN00", "FLVN01"]}),
    ("F_LFA1_APP", {"ACTVT": ["01", "02", "03"], "APPKZ": ["F"]}),
], menu=["BP", "FK02", "FK03"])
role("Z_FI_PAGOS", "FI: ejecución de pagos", [
    ("S_TCODE", {"TCD": ["F110", "F-53"]}),
    ("F_REGU_BUK", {"FBTCH": ["*"], "BUKRS": ["1000"]}),
    ("F_BKPF_BUK", {"ACTVT": ["01", "03"], "BUKRS": ["1000"]}),
    ("F_BKPF_KOA", {"ACTVT": ["01", "03"], "KOART": ["K"]}),
], menu=["F110", "F-53"])
role("Z_FI_PAGOS_CONSULTA", "FI: consulta de pagos", [
    ("S_TCODE", {"TCD": ["F110", "FK03"]}),
    ("F_BKPF_BUK", {"ACTVT": ["03"], "BUKRS": ["1000"]}),
], menu=["F110"])
role("Z_FI_FACTURAS", "FI: registro de facturas de acreedor", [
    ("S_TCODE", {"TCD": ["FB60"]}),
    ("F_BKPF_BUK", {"ACTVT": ["01", "02", "03"], "BUKRS": ["1000"]}),
    ("F_BKPF_KOA", {"ACTVT": ["01", "02", "03"], "KOART": ["K"]}),
])
role("Z_FI_PAGOS_2000", "FI: pagos manuales sociedad 2000", [
    ("S_TCODE", {"TCD": ["F-53"]}),
    ("F_BKPF_BUK", {"ACTVT": ["01"], "BUKRS": ["2000"]}),
    ("F_BKPF_KOA", {"ACTVT": ["01"], "KOART": ["K"]}),
])
role("Z_FI_NO_GENERADO", "FI: rol de prueba sin perfil generado", [
    ("S_TCODE", {"TCD": ["FB60"]}),
    ("F_BKPF_BUK", {"ACTVT": ["01"], "BUKRS": ["1000"]}),
], generated=False)
role("Z_FI_DESACTUALIZADO", "FI: perfil desactualizado respecto de PFCG", [
    ("S_TCODE", {"TCD": ["FK03"]}),
    ("F_LFA1_APP", {"ACTVT": ["03"], "APPKZ": ["F"]}),
], stale_profile=True)
role("Z_MM_CONSULTA", "MM: consultas", [
    ("S_TCODE", {"TCD": ["ME23N", "FK03"]}),
    ("M_BEST_BSA", {"ACTVT": ["03"], "BSART": ["NB"]}),
])
role("Z_MM_PEDIDOS", "MM: creación de pedidos org. 1000", [
    ("S_TCODE", {"TCD": ["ME21N", "ME22N", "ME23N"]}),
    ("M_BEST_BSA", {"ACTVT": ["01", "02", "03"], "BSART": ["NB"]}),
    ("M_BEST_EKO", {"ACTVT": ["01", "02", "03"], "EKORG": ["1000"]}),
])
role("Z_MM_LIBERADOR", "MM: liberación de pedidos", [
    ("S_TCODE", {"TCD": ["ME29N", "ME28"]}),
    ("M_EINK_FRG", {"FRGGR": ["01"], "FRGCO": ["A1"]}),
])
role("Z_MM_COMPRADOR_C", "MM: comprador (compuesto)", [], children=["Z_MM_PEDIDOS", "Z_MM_LIBERADOR"])
# Rol de negocio Fiori (S/4HANA): app de pedidos por servicio OData, SIN transacción ME21N
FIORI_PO_HASH = "DEMO0FIORI0PEDIDOS0HASH0000001"   # ficticio (SRV_NAME de S_SERVICE = hash de USOBHASH)
FIORI_PO_VIEW_HASH = "DEMO0FIORI0PEDIDOS0VER00000002"
role("Z_MM_PEDIDOS_FIORI", "MM: gestionar pedidos de compra (app Fiori)", [
    ("S_SERVICE", {"SRV_NAME": [FIORI_PO_HASH, FIORI_PO_VIEW_HASH], "SRV_TYPE": ["HT"]}),
    ("M_BEST_BSA", {"ACTVT": ["01", "02", "03"], "BSART": ["NB"]}),
    ("M_BEST_EKO", {"ACTVT": ["01", "02", "03"], "EKORG": ["1000"]}),
])
role("Z_MM_COMPRAS_APROBADOR", "MM: aprobador de compras", [
    ("S_TCODE", {"TCD": ["ME29N", "ME54N", "ME23N"]}),
    ("M_EINK_FRG", {"FRGGR": ["01"], "FRGCO": ["A1", "A2"]}),
])
role("Z_MM_PEDIDOS_PADRE", "MM: pedidos (rol padre)", [
    ("S_TCODE", {"TCD": ["ME21N"]}),
    ("M_BEST_EKO", {"ACTVT": ["01"], "EKORG": ["$EKORG"]}),
], org=[("$EKORG", "")])
role("Z_MM_DERIVADO_1000", "MM: pedidos org 1000 (derivado)", [
    ("S_TCODE", {"TCD": ["ME21N"]}),
    ("M_BEST_EKO", {"ACTVT": ["01"], "EKORG": ["1000"]}),
], parent="Z_MM_PEDIDOS_PADRE", org=[("$EKORG", "1000")])
role("Z_MM_ALMACEN", "MM: movimientos de almacén", [
    ("S_TCODE", {"TCD": ["MIGO", "MI07"]}),
    ("M_MSEG_BWA", {"ACTVT": ["01"], "BWART": ["*"]}),
    ("M_ISEG_WDB", {"ACTVT": ["01"], "WERKS": ["1000"]}),
])
role("Z_SEC_ROLES", "SEG: mantenimiento de roles", [
    ("S_TCODE", {"TCD": ["PFCG", "SUIM"]}),
    ("S_USER_AGR", {"ACTVT": ["01", "02", "03"], "ACT_GROUP": ["*"]}),
])
role("Z_SEC_USUARIOS", "SEG: administración de usuarios", [
    ("S_TCODE", {"TCD": ["SU01", "SUIM"]}),
    ("S_USER_GRP", {"ACTVT": ["01", "02", "03", "05"], "CLASS": ["*"]}),
    ("S_USER_AGR", {"ACTVT": ["22"], "ACT_GROUP": ["Z*"]}),
])
role("Z_BC_DESARROLLO", "BC: desarrollo ABAP", [
    ("S_TCODE", {"TCD": ["SE38", "SE80"]}),
    ("S_DEVELOP", {"ACTVT": ["01", "02", "03"], "DEVCLASS": ["Z*"], "OBJTYPE": ["PROG", "CLAS", "FUGR"],
                   "OBJNAME": ["Z*"], "P_GROUP": ["*"]}),
])
role("Z_BC_TRANSPORTES", "BC: gestión de transportes", [
    ("S_TCODE", {"TCD": ["STMS"]}),
    ("S_CTS_ADMI", {"CTS_ADMFCT": ["IMPA", "IMPS", "TABL"]}),
])
role("Z_BC_RFC_TOTAL", "BC: usuario técnico RFC amplio", [
    ("S_RFC", {"ACTVT": ["16"], "RFC_NAME": ["*"], "RFC_TYPE": ["FUGR", "FUNC"]}),
    ("S_SERVICE", {"SRV_NAME": ["*"], "SRV_TYPE": ["HT"]}),
])
role("Z_BC_ADMIN_TOTAL", "BC: administración total (amplia)", [
    ("S_TCODE", {"TCD": ["*"]}),
    ("S_USER_GRP", {"ACTVT": ["*"], "CLASS": ["*"]}),
    ("S_USER_AGR", {"ACTVT": ["*"], "ACT_GROUP": ["*"]}),
    ("S_USER_PRO", {"ACTVT": ["*"], "PROFILE": ["*"]}),
    ("S_USER_AUT", {"ACTVT": ["*"], "OBJECT": ["*"], "AUTH": ["*"]}),
    ("S_DEVELOP", {"ACTVT": ["*"], "DEVCLASS": ["*"], "OBJTYPE": ["*"], "OBJNAME": ["*"], "P_GROUP": ["*"]}),
    ("S_TABU_DIS", {"ACTVT": ["*"], "DICBERCLS": ["*"]}),
    ("S_TABU_NAM", {"ACTVT": ["*"], "TABLE": ["*"]}),
    ("S_RFC", {"ACTVT": ["*"], "RFC_NAME": ["*"], "RFC_TYPE": ["*"]}),
    ("S_PROGRAM", {"P_ACTION": ["*"], "P_GROUP": ["*"]}),
    ("S_ADMI_FCD", {"S_ADMI_FCD": ["*"]}),
    ("S_BTCH_ADM", {"BTCADMIN": ["*"]}),
    ("S_BTCH_NAM", {"BTCUNAME": ["*"]}),
    ("S_TRANSPRT", {"ACTVT": ["*"], "TTYPE": ["*"]}),
    ("S_CTS_ADMI", {"CTS_ADMFCT": ["*"]}),
    ("S_DATASET", {"ACTVT": ["*"], "FILENAME": ["*"], "PROGRAM": ["*"]}),
])
role("Z_SIN_USUARIOS", "", [("S_TCODE", {"TCD": ["SE16N"]}), ("S_TABU_DIS", {"ACTVT": ["03"], "DICBERCLS": ["*"]})])
role("Z_FI_REPORTE", "FI: reporte Z con chequeo de inicio", [
    ("S_TCODE", {"TCD": ["ZFI_REP_PAGOS"]}),
])

# ----------------------------------------------------------------------------- Usuarios
USERS = [
    # BNAME, USTYP, CLASS, UFLAG, TRDAT, GLTGB, fullname
    ("USUARIO_TEST", "A", "FINANZAS", "0", "20261102", "", "Usuario de prueba"),
    ("ADMIN_BASIS", "A", "SUPER", "0", "20261103", "", "Administrador Basis (ficticio)"),
    ("ADMIN_EQUIV", "A", "SUPER", "0", "20261101", "", "Administrador con permisos amplios"),
    ("SEG_ADMIN", "A", "SEGURIDAD", "0", "20261030", "", "Administrador de seguridad"),
    ("COMPRADOR1", "A", "COMPRAS", "0", "20261103", "", "Comprador"),
    ("DEV_USER", "A", "DESARROLLO", "0", "20261020", "", "Desarrollador"),
    ("USUARIO_BLOQ", "A", "FINANZAS", "64", "20260115", "", "Usuario bloqueado"),
    ("USUARIO_VENC", "A", "FINANZAS", "0", "20261001", "", "Usuario con rol vencido"),
    ("RFC_TECH", "B", "TECNICOS", "0", "20261104", "", ""),
    ("DDIC", "A", "SUPER", "0", "20260601", "", ""),
    ("SAP*", "A", "SUPER", "64", "", "", ""),
    ("CONTADOR1", "A", "FINANZAS", "0", "20261101", "", "Contador"),
    ("INACTIVO1", "A", "FINANZAS", "0", "20250101", "", "Usuario inactivo"),
    ("ALMACEN1", "A", "LOGISTICA", "0", "20261102", "", "Almacenero"),
    ("REPORTE1", "A", "FINANZAS", "0", "20261102", "", "Usuario de reportes"),
    ("COMPRA_FIORI", "A", "COMPRAS", "0", "20261103", "", "Compradora que usa Fiori"),
]

ASSIGN = [
    # usuario, rol, desde, hasta, col_flag
    ("USUARIO_TEST", "Z_FI_PROVEEDORES", "20250101", "99991231", ""),
    ("USUARIO_TEST", "Z_MM_CONSULTA", "20250101", "99991231", ""),
    ("ADMIN_EQUIV", "Z_BC_ADMIN_TOTAL", "20250101", "99991231", ""),
    ("SEG_ADMIN", "Z_SEC_ROLES", "20250101", "99991231", ""),
    ("SEG_ADMIN", "Z_SEC_USUARIOS", "20250101", "99991231", ""),
    ("COMPRADOR1", "Z_MM_COMPRADOR_C", "20250101", "99991231", ""),
    ("COMPRADOR1", "Z_MM_PEDIDOS", "20250101", "99991231", "X"),
    ("COMPRADOR1", "Z_MM_LIBERADOR", "20250101", "99991231", "X"),
    ("DEV_USER", "Z_BC_DESARROLLO", "20250101", "99991231", ""),
    ("DEV_USER", "Z_BC_TRANSPORTES", "20250101", "99991231", ""),
    ("USUARIO_BLOQ", "Z_FI_PROVEEDORES", "20250101", "99991231", ""),
    ("USUARIO_BLOQ", "Z_FI_PAGOS", "20250101", "99991231", ""),
    ("USUARIO_VENC", "Z_FI_PAGOS", "20250101", "20260630", ""),
    ("USUARIO_VENC", "Z_MM_CONSULTA", "20270101", "99991231", ""),
    ("USUARIO_VENC", "Z_FI_NO_GENERADO", "20250101", "99991231", ""),
    ("RFC_TECH", "Z_BC_RFC_TOTAL", "20250101", "99991231", ""),
    ("CONTADOR1", "Z_FI_FACTURAS", "20250101", "99991231", ""),
    ("CONTADOR1", "Z_FI_PAGOS_2000", "20250101", "99991231", ""),
    ("INACTIVO1", "Z_MM_CONSULTA", "20250101", "99991231", ""),
    ("ALMACEN1", "Z_MM_ALMACEN", "20250101", "99991231", ""),
    ("ALMACEN1", "Z_FI_DESACTUALIZADO", "20250101", "99991231", ""),
    ("REPORTE1", "Z_FI_REPORTE", "20250101", "99991231", ""),
    ("COMPRA_FIORI", "Z_MM_PEDIDOS_FIORI", "20250101", "99991231", ""),
    ("COMPRA_FIORI", "Z_MM_LIBERADOR", "20250101", "99991231", ""),
]

# Perfiles directos (UST04 sin rol): SAP_ALL a ADMIN_BASIS, SAP_NEW a DDIC
DIRECT_PROFILES = [("ADMIN_BASIS", "SAP_ALL"), ("DDIC", "SAP_NEW")]


def build() -> dict:
    t: dict[str, list[dict]] = {k: [] for k in (
        "USR02", "AGR_DEFINE", "AGR_TEXTS", "AGR_FLAGS", "AGR_AGRS", "AGR_USERS", "AGR_1016", "AGR_1251",
        "AGR_1252", "AGR_TCODES", "UST04", "UST10C", "UST10S", "UST12", "TOBJ", "TOBJT", "TACTT", "TSTC",
        "TSTCT", "TSTCA", "USOBHASH", "USOBX_C", "USOBT_C", "CVERS")}
    profile_of: dict[str, str] = {}
    for n, (name, r) in enumerate(sorted(ROLES.items()), start=1):
        t["AGR_DEFINE"].append({"AGR_NAME": name, "PARENT_AGR": r["parent"], "CREATE_USR": "SEG_ADMIN",
                                "CREATE_DAT": "20250101", "CHANGE_USR": "SEG_ADMIN", "CHANGE_DAT": "20260301"})
        if r["text"]:
            t["AGR_TEXTS"].append({"AGR_NAME": name, "SPRAS": "S", "LINE": "00000", "TEXT": r["text"]})
        if r["children"]:
            t["AGR_FLAGS"].append({"AGR_NAME": name, "FLAG_TYPE": "COLL_AGR", "FLAG_VALUE": "X"})
            for c in r["children"]:
                t["AGR_AGRS"].append({"AGR_NAME": name, "CHILD_AGR": c})
            continue
        prof = f"T-DM{n:06d}"
        for mt in r["menu"]:
            t["AGR_TCODES"].append({"AGR_NAME": name, "TYPE": "TR", "TCODE": mt, "EXCLUDE": "", "DIRECT": "X",
                                    "INHERITED": ""})
        for var, low in r["org"]:
            t["AGR_1252"].append({"AGR_NAME": name, "COUNTER": "000001", "VARBL": var, "LOW": low, "HIGH": ""})
        if r["generated"]:
            profile_of[name] = prof
            t["AGR_1016"].append({"AGR_NAME": name, "COUNTER": "000001", "PROFILE": prof, "VARIANT": "",
                                  "GENERATED": "X", "PSTATE": "A"})
        counter = 0
        for i, (obj, fields) in enumerate(r["insts"], start=1):
            auth = f"{prof}{i:02d}"[:12]
            if r["generated"]:
                t["UST10S"].append({"PROFN": prof, "AKTPS": "A", "OBJCT": obj, "AUTH": auth})
            for fname, vals in fields.items():
                for v in vals:
                    counter += 1
                    low, high = (v if isinstance(v, tuple) else (v, ""))
                    t["AGR_1251"].append({"AGR_NAME": name, "COUNTER": f"{counter:06d}", "OBJECT": obj,
                                          "AUTH": auth, "VARIANT": "", "FIELD": fname, "LOW": low, "HIGH": high,
                                          "MODIFIED": "", "DELETED": ""})
                    if r["generated"] and not low.startswith("$"):
                        von = low
                        if r["stale"] and obj == "F_LFA1_APP" and fname == "ACTVT":
                            von = "02"  # el perfil generado tiene un valor distinto al de PFCG
                        t["UST12"].append({"OBJCT": obj, "AUTH": auth, "AKTPS": "A", "FIELD": fname,
                                           "VON": von, "BIS": high})

    # SAP_ALL / SAP_NEW
    t["UST10C"].append({"PROFN": "SAP_ALL", "AKTPS": "A", "SUBPROF": "&_SAP_ALL_1"})
    for obj, fields in TOBJ.items():
        auth = "&_SAP_ALL"
        t["UST10S"].append({"PROFN": "&_SAP_ALL_1", "AKTPS": "A", "OBJCT": obj, "AUTH": auth})
        for f in fields:
            t["UST12"].append({"OBJCT": obj, "AUTH": auth, "AKTPS": "A", "FIELD": f, "VON": "*", "BIS": ""})
    t["UST10S"].append({"PROFN": "SAP_NEW", "AKTPS": "A", "OBJCT": "S_RFC", "AUTH": "&_SAP_NEW_RFC"})
    for f, v in (("ACTVT", "16"), ("RFC_NAME", "*"), ("RFC_TYPE", "FUGR")):
        t["UST12"].append({"OBJCT": "S_RFC", "AUTH": "&_SAP_NEW_RFC", "AKTPS": "A", "FIELD": f, "VON": v, "BIS": ""})

    for bname, ustyp, cls, uflag, trdat, gltgb, full in USERS:
        t["USR02"].append({"BNAME": bname, "USTYP": ustyp, "CLASS": cls, "GLTGV": "20250101", "GLTGB": gltgb,
                           "UFLAG": uflag, "TRDAT": trdat, "LTIME": "080000" if trdat else "", "ERDAT": "20250101",
                           "ANAME": "SEG_ADMIN", "_FULLNAME": full,
                           # Campos sensibles presentes en la tabla ficticia para verificar que NUNCA se leen:
                           "BCODE": "DEADBEEFDEADBEEF", "PWDSALTEDHASH": "{x-issha, 1024}FICTICIO"})
    for u, r, f, to, col in ASSIGN:
        t["AGR_USERS"].append({"AGR_NAME": r, "UNAME": u, "FROM_DAT": f, "TO_DAT": to, "EXCLUDE": "",
                               "CHANGE_DAT": "20250101", "ORG_FLAG": "", "COL_FLAG": col})
        prof = profile_of.get(r)
        # Comparación de usuarios: el perfil está en UST04 aunque la asignación haya vencido
        # (USUARIO_VENC/Z_FI_PAGOS → perfil residual, falta PFUD).
        if prof and f <= "20261104":
            t["UST04"].append({"BNAME": u, "PROFILE": prof})
    for u, p in DIRECT_PROFILES:
        t["UST04"].append({"BNAME": u, "PROFILE": p})

    for obj, fields in TOBJ.items():
        row = {"OBJCT": obj, "OCLSS": obj.split("_")[0]}
        for i, f in enumerate(fields, start=1):
            row["FIEL0" if i == 10 else f"FIEL{i}"] = f
        t["TOBJ"].append(row)
        t["TOBJT"].append({"OBJECT": obj, "LANGU": "S", "TTEXT": f"Objeto {obj}"})
    for code, txt in (("01", "Crear o generar"), ("02", "Modificar"), ("03", "Visualizar"), ("05", "Bloquear"),
                      ("06", "Borrar"), ("16", "Ejecutar"), ("22", "Introducir, incluir, asignar"),
                      ("34", "Grabar"), ("43", "Liberar")):
        t["TACTT"].append({"SPRAS": "S", "ACTVT": code, "LTEXT": txt})
    for tc, txt in TCODES.items():
        t["TSTC"].append({"TCODE": tc, "PGMNA": f"PROG_{tc.replace('-', '_')}"})
        t["TSTCT"].append({"SPRSL": "S", "TCODE": tc, "TTEXT": txt})
    # SU24 ficticia: confirma algunas relaciones transacción → objeto (OKFLAG X = se verifica)
    for tc, obj in (("ME21N", "M_BEST_BSA"), ("ME21N", "M_BEST_EKO"), ("ME29N", "M_EINK_FRG"),
                    ("PFCG", "S_USER_AGR"), ("SU01", "S_USER_GRP"), ("SU01", "S_USER_AGR")):
        t["USOBX_C"].append({"NAME": tc, "TYPE": "TR", "OBJECT": obj, "OKFLAG": "X"})
    t["USOBX_C"].append({"NAME": "F110", "TYPE": "TR", "OBJECT": "F_REGU_BUK", "OKFLAG": "N"})
    # Fiori ficticio: nombre de los servicios (USOBHASH) y su SU24 (TYPE HT): el de gestión verifica M_BEST_BSA
    # para crear/modificar; el de visualización solo para visualizar (no debe contar como «crear pedidos»).
    t["USOBHASH"] += [
        {"NAME": FIORI_PO_HASH, "PGMID": "R3TR", "OBJECT": "IWSG", "OBJ_NAME": "ZMM_PEDIDOS_DEMO_SRV 0001", "TYPE": "HT"},
        {"NAME": FIORI_PO_VIEW_HASH, "PGMID": "R3TR", "OBJECT": "IWSG", "OBJ_NAME": "ZMM_PEDIDOS_VER_DEMO_SRV 0001",
         "TYPE": "HT"}]
    for h, acts in ((FIORI_PO_HASH, ("01", "02", "03")), (FIORI_PO_VIEW_HASH, ("03",))):
        for obj in ("M_BEST_BSA", "M_BEST_EKO"):
            t["USOBX_C"].append({"NAME": h, "TYPE": "HT", "OBJECT": obj, "OKFLAG": "X"})
            for a in acts:
                t["USOBT_C"].append({"NAME": h, "TYPE": "HT", "OBJECT": obj, "FIELD": "ACTVT", "LOW": a, "HIGH": ""})
    # Componentes ficticios de un S/4HANA con Fiori embebido
    t["CVERS"] += [{"COMPONENT": c, "RELEASE": r, "EXTRELEASE": "0001", "COMP_TYPE": "S"}
                   for c, r in (("SAP_BASIS", "758"), ("S4CORE", "108"), ("SAP_GWFND", "758"), ("SAP_UI", "758"))]
    # Chequeo de inicio ficticio: la transacción Z exige F_BKPF_BUK ACTVT=03 (que REPORTE1 no tiene)
    t["TSTCA"].append({"TCODE": "ZFI_REP_PAGOS", "OBJCT": "F_BKPF_BUK", "FIELD": "ACTVT", "VALUE": "03"})

    return {
        "_comment": "SISTEMA SAP FICTICIO PARA PRUEBAS. Ningún dato corresponde a un sistema real.",
        "system": {"RFCSYSID": "DMO", "RFCDBSYS": "HDB", "RFCSAPRL": "758", "RFCHOST": "demo-host",
                   "RFCOPSYS": "Linux", "RFCKERNRL": "793"},
        "missing_functions": ["SUSR_GET_ADMIN_USER_LOGIN_INFO", "Z_SECX_READ"],
        "unauthorized_tables": [],
        "tables": t,
    }


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"Generado {OUT}")
