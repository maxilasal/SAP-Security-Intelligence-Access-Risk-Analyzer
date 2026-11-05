# Usuario técnico RFC y rol de solo lectura

## Usuario

* Nombre sugerido: `SECX_READ` (uno por sistema/mandante).
* **Tipo: Sistema (B)** — no permite logon de diálogo; política de contraseñas de sistema.
* Grupo de usuarios propio (p. ej. `TECNICOS_SEC`) para que el administrador de usuarios pueda restringirlo.
* En PRD: preferir **SNC** (cifrado y autenticación por certificado) y validez temporal acotada.
* Registrar en el Security Audit Log (SM19/RSAU_CONFIG) los eventos RFC de este usuario.

## Rol PFCG `Z_SECX_RFC_READ` (sin transacciones)

| Objeto | Campo | Valores | Motivo |
|---|---|---|---|
| `S_RFC` | ACTVT | 16 | Ejecutar |
| | RFC_TYPE | FUNC | Autorización por módulo de función (granular) |
| | RFC_NAME | RFC_PING, RFC_SYSTEM_INFO, RFC_GET_FUNCTION_INTERFACE, RFC_READ_TABLE, BAPI_USER_GETLIST, BAPI_USER_GET_DETAIL, DDIF_FIELDINFO_GET | Lista exacta de `ALLOWED_FUNCTIONS` |
| `S_TABU_NAM` | ACTVT | 03 | Solo visualizar |
| | TABLE | AGR_DEFINE, AGR_TEXTS, AGR_FLAGS, AGR_AGRS, AGR_USERS, AGR_1016, AGR_1251, AGR_1252, AGR_TCODES, UST04, UST10C, UST10S, UST12, TOBJ, TOBJT, TACTT, TSTC, TSTCT, TSTCA, USOBHASH, USOBX_C, USOBT_C, CVERS, *(USR02 solo si se acepta el riesgo)* | Lista exacta del catálogo de fuentes |
| `S_USER_GRP` | ACTVT | 03 | Leer maestro de usuarios vía BAPI |
| | CLASS | `*` o lista de grupos auditados | |
| `S_USER_AGR` | ACTVT | 03 | Solo si la traza lo requiere para BAPI_USER_GET_DETAIL |
| `S_USER_PRO` | ACTVT | 03 | Ídem |

**No asignar**: `S_TABU_DIS`, `S_TCODE`, `S_DEVELOP`, ninguna actividad distinta de 03/16, ni SAP_ALL/SAP_NEW.

### Cómo afinarlo (recomendado antes de PRD)

1. Asignar el rol en QA, ejecutar `sapsec test-connection <id>` y una extracción completa.
2. Activar la traza de autorizaciones (STAUTHTRACE) para el usuario técnico durante la extracción.
3. Ajustar `S_RFC`: algunas releases verifican también por grupo de funciones (`RFC_TYPE=FUGR`); agregar el grupo **solo** si la traza lo muestra (p. ej. SYST, RFC1, SDTX, SU_USER) **[verificar en su release]**.
4. Activar UCON (Unified Connectivity) en PRD y permitir solo los módulos de la lista.
5. Repetir en PRD y guardar la evidencia de la traza junto con la aprobación del rol.

### Sobre `USR02`

`USR02` contiene hashes de contraseñas. La herramienta **nunca** solicita esos campos (bloqueo en
`FORBIDDEN_FIELDS`), pero `S_TABU_NAM` sobre USR02 permitiría a quien obtenga las credenciales del
usuario técnico leerlos con otra herramienta. Opciones, de menor a mayor exposición:

1. Modo `bapi` en la conexión (sin S_TABU_NAM sobre USR02; no hay fecha de último acceso).
2. Extractor Z con lista blanca de campos (ver `04_extractor_z_opcional.md`).
3. `S_TABU_NAM` sobre USR02 con aceptación formal del riesgo, SNC y monitoreo del usuario.

## S/4HANA y sistemas de desarrollo

El mismo rol sirve para ECC, S/4HANA y DEV. En S/4HANA (y cualquier SAP_BASIS ≥ 7.40) además se leen
**USOBHASH** (nombre real de los servicios Fiori/OData detrás del hash de `S_SERVICE`) y la SU24 de esos
servicios en **USOBX_C/USOBT_C** (registros `TYPE = 'HT'`). **CVERS** identifica el producto (S/4HANA, ECC,
front-end Fiori). Si alguna de estas tablas no está autorizada, la extracción sigue y el diagnóstico lo informa.
