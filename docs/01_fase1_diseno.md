# Fase 1 — Investigación y diseño

**Proyecto:** SAP Security Intelligence & Access Risk Analyzer
**Alcance de la versión 1:** solo lectura, ejecución fuera de SAP, Windows, multi-sistema / multi-mandante.
**Fecha de la investigación:** noviembre de 2026.

> Convención de este documento: lo marcado **[verificar]** es conocimiento técnico que debe
> confirmarse en su release (SE37, SE11, SU24, documentación del objeto) antes de usarlo como
> criterio formal. No se presentan datos no verificados como hechos.

---

## 0. Decisiones principales (resumen)

| Tema | Decisión | Motivo |
|---|---|---|
| Conectividad RFC | **SAP NW RFC SDK 7.50** con binding propio (`ctypes`) + abstracción de conectores. PyRFC solo como backend heredado. | SAP archivó PyRFC (anuncio dic-2024; repositorio de solo lectura). El NW RFC SDK sigue siendo el componente con soporte (SAP Note 2573790). |
| Lectura de datos | RFC estándar (`RFC_READ_TABLE` acotado + BAPIs liberadas). Extractor Z **opcional**. | Cumple "sin desarrollos Z"; el extractor Z se justifica solo si la política no acepta `S_TABU_NAM` sobre ciertas tablas. |
| Motor | Python, independiente de la UI, sobre **snapshots inmutables**. | Reproducibilidad, auditoría y nunca analizar "en vivo" contra producción. |
| Persistencia | SQLite (dev/pruebas) y PostgreSQL (empresa) vía SQLAlchemy 2. | Mismo código, despliegue gradual. |
| Interfaz | FastAPI + plantillas server-side (Jinja2) + API JSON. React+TS en fase 3 sobre la misma API. | Sin Node/npm en servidores Windows en la v1; la API ya existe para un front React. |
| Reglas | YAML versionado + hash SHA-256 registrado en cada análisis. | Configurable, auditable, revisable en Git. |
| IA | Opcional y desactivada por defecto. Nunca detecta: solo explica. | Requisito de evidencia verificable y confidencialidad. |

---

## 1. Análisis de viabilidad

| Capacidad | Viabilidad con RFC estándar | Comentario |
|---|---|---|
| Inventario de usuarios (tipo, grupo, validez, bloqueo) | **Completa** | `BAPI_USER_GETLIST` + `USR02` (campos restringidos) o `BAPI_USER_GET_DETAIL`. |
| Último acceso | **Requiere adaptación** | Solo en `USR02-TRDAT/LTIME`; la BAPI no lo devuelve. Exige `S_TABU_NAM` sobre USR02 (tabla con hashes) o un extractor Z. |
| Roles, compuestos, derivados, textos, menú, org. levels | **Completa** | Tablas AGR_* (lectura dirigida por lotes). |
| Valores de autorización de roles (PFCG) | **Completa** | `AGR_1251`. No hay BAPI liberada para valores de roles. |
| Autorizaciones efectivas del usuario (maestro) | **Completa** | `UST04 → UST10C → UST10S → UST12` (versión activa A). |
| Detección de desajuste PFCG ↔ perfil | **Completa** | Comparación `AGR_1251` vs `UST12` del perfil generado (`AGR_1016`). |
| Capacidad de ejecutar una transacción | **Requiere adaptación** | `S_TCODE` + chequeo de inicio `TSTCA`. Los AUTHORITY-CHECK internos del programa NO son visibles por tablas. |
| Confirmar que una acción se ejecuta | **No garantizable solo con RFC** | Requiere traza (STAUTHTRACE/ST01), SU53 o prueba controlada. La herramienta lo marca como "capacidad potencial". |
| SAP_ALL / SAP_NEW y equivalencias | **Completa** | Perfil literal + cobertura de comodines sobre objetos críticos y sobre el perfil SAP_ALL del sistema. |
| SoD por objetos y valores | **Completa** (dependiente de la calidad de la matriz) | El motor es exacto respecto de las reglas; las reglas deben validarse. |
| Restricciones organizativas | **Requiere adaptación** | Se analizan valores (BUKRS, WERKS, EKORG…) dentro de cada instancia; no se infieren restricciones de negocio no modeladas. |
| Fiori: catálogos/espacios/páginas | **Requiere adaptación** | Menú de rol (`AGR_TCODES`, `AGR_HIER`/`AGR_BUFFI` **[verificar]**) y repositorio del launchpad (tablas `/UI2/*` **[verificar]**). Fase 3. |
| Fiori: `S_SERVICE` → servicio real | **Completa** | `USOBHASH` traduce el hash de `SRV_NAME`. |
| Historial de cambios | **Parcial** | `USH04/USH10/USH12` y documentos de modificación (`CDHDR/CDPOS`) **[verificar clases de objeto]**. Si no alcanza: diferencia de snapshots (implementado). |
| Security Audit Log | **No garantizable con RFC estándar** | Sin API RFC liberada genérica; usar exportación SIEM/archivos o extractor Z. |
| Lectura incremental garantizada | **Requiere adaptación** | Las tablas de autorización no tienen marca de tiempo por fila. Se usan claves de cambio (`AGR_DEFINE-CHANGE_DAT`, `USH*`) como pista, y extracción completa como verdad. |

---

## 2. Funcionalidades adicionales propuestas

1. **Validación cruzada automática por muestreo** contra `BAPI_USER_GET_DETAIL` (implementado) — detecta lecturas incompletas.
2. **Verificación de identidad del sistema** (SID devuelto por `RFC_SYSTEM_INFO` vs. registrado) antes de guardar datos (implementado).
3. **Diagnóstico de permisos del usuario RFC** en la pantalla de conexión (implementado).
4. **Perfil residual / comparación pendiente (PFUD)** como hallazgo propio (implementado).
5. **Detección de restricciones organizativas aparentes**: el motor descubre cuando un rol "limitado a la sociedad 2000" se combina con otro rol y permite operar en la 1000 (implementado, ver prueba `test_apparent_org_restriction_is_not_trusted`).
6. **Acceso de emergencia (firefighter)**: registro de uso temporal y revisión posterior (fase 4).
7. **Campañas de recertificación de accesos** (UAR) con responsables por rol/usuario (fase 4).
8. **Integración con ITSM/IdM**: el simulador como API previa a aprobar una solicitud (API `/api/v1/simular` ya disponible).
9. **Lista de verificación de usuarios estándar** (SAP*, DDIC, TMSADM, EARLYWATCH, SAPCPIC) y parámetros de logon (`login/no_automatic_user_sapstar`, etc. vía `RSPARAM` **[verificar mecanismo RFC]**).
10. **Uso real de transacciones** (estadísticas ST03N / SUIM "uso de transacciones") para mínimo privilegio basado en uso (fase 3, requiere fuente adicional **[verificar]**).
11. **Simulación de transporte de roles**: comparar el rol en DEV/QA con PRD antes de transportarlo (comparador de sistemas, implementado básico).
12. **Exportación a SIEM** de hallazgos y eventos de la propia aplicación (fase 4).

---

## 3. Desafíos técnicos reales

1. **Conectividad**: PyRFC archivado. El SDK C es soportado pero exige mantener un binding. Se mitiga con un binding mínimo (≈20 funciones C documentadas) y una abstracción de conectores intercambiable (JCo vía sidecar como plan B).
2. **`RFC_READ_TABLE`**: no liberado para clientes (SAP Note 382318), fila limitada a 512 caracteres, sin paginación eficiente (ROWSKIPS relee), autorización vía `S_TABU_DIS`/`S_TABU_NAM`. Mitigación: listas permitidas de campos, ancho validado con `NO_DATA`, lotes por clave, detección de truncamiento.
3. **Volumen**: `UST12`/`AGR_1251` pueden tener millones de filas. Lectura dirigida (solo perfiles/roles relevantes) y particionada por objeto/rol.
4. **Semántica de autorizaciones**: la unidad de verificación es la *instancia*. Mezclar campos de instancias distintas produce falsos positivos. El modelo lo impide por diseño.
5. **Lo que las tablas no dicen**: chequeos internos de programas, `AUTHORITY-CHECK` con `DUMMY`, switches (`SU24` "no verificar"), lógica de BAdIs y de Fiori backend. Se reporta con niveles de certeza.
6. **Comparación de usuarios**: lo asignado en `AGR_USERS` y lo presente en `UST04` pueden diferir hasta ejecutar PFUD.
7. **Reglas SoD**: la calidad depende de la matriz; las reglas iniciales son ejemplos y así se etiquetan.
8. **Datos sensibles**: `USR02` contiene hashes. Nunca se leen esos campos (bloqueo en el lector) y la alternativa BAPI evita `S_TABU_NAM` sobre USR02.
9. **Producción**: carga, horarios, bloqueos de cuenta del usuario técnico y trazabilidad de cada lectura.

---

## 4. Evaluación de conectividad RFC

### 4.1 Estado verificado (noviembre de 2026)

* **PyRFC**: SAP publicó una convocatoria de mantenedores (issue SAP/PyRFC #372, julio de 2024) y anunció en diciembre de 2024 el archivado por falta de mantenedores; el repositorio figura como *"no longer maintained"* y archivado (solo lectura). Su última versión (3.3.1, enero de 2024) se compiló contra el NW RFC SDK PL12, que SAP ya no soporta. Fuentes: <https://github.com/SAP/PyRFC>, <https://github.com/SAP/PyRFC/issues/372>.
* **SAP NW RFC SDK 7.50**: componente vigente; descarga y plataformas en SAP Note 2573790 (<https://support.sap.com/en/product/connectors/nwrfcsdk.html>). La documentación pública más reciente encontrada corresponde a PL17 (junio de 2025). Se publicó en enero de 2026 una vulnerabilidad (CVE-2026-0507) que afecta a versiones hasta 7.50 **[verificar el parche requerido en la nota de seguridad SAP]**: usar siempre el último PL.
* **SAP JCo 3.1**: soportado; última versión observada 3.1.14 (<https://support.sap.com/jco>); ciclo de vida en SAP Note 2786882.
* **SOAP sobre HTTP** (`/sap/bc/soap/rfc`): posible sin SDK, pero el servicio ICF suele estar desactivado (y en RISE no está disponible por defecto); amplía superficie HTTP.

### 4.2 Comparación

| Opción | Soporte SAP | Python nativo | Windows | Riesgo de mantenimiento | Valoración |
|---|---|---|---|---|---|
| PyRFC 3.3.1 | No (archivado) | Sí | Sí (wheels ≤ Py 3.12 aprox.) | Alto: sin parches, SDK antiguo | Solo heredado |
| **Binding ctypes sobre NW RFC SDK** | SDK sí | Sí | Sí | Medio-bajo: API C estable, superficie mínima | **Elegido** |
| Fork comunitario de PyRFC | No | Sí | Depende | Medio: compilar con Cython, sin garantías | Alternativa si aparece un fork mantenido |
| JCo en sidecar (Java) + HTTP/gRPC local | Sí | No (proceso aparte) | Sí | Bajo en conectividad, más piezas | **Plan B empresarial** |
| SAP .NET Connector (NCo) + pythonnet | Sí | Parcial | Sí (solo Windows) | Medio (.NET runtime) | Posible solo en Windows |
| SOAP RFC sobre HTTPS | Sí (ICF) | Sí | Sí | Medio; activa servicio ICF | No recomendado para PRD |
| OData/APIs S/4HANA | Sí | Sí | Sí | — | No existen APIs liberadas que cubran valores de autorización PFCG |

### 4.3 Decisión

`connectors/base.py` define `RfcConnector` (solo lectura, lista permitida de funciones, bloqueo de
patrones de escritura, limitación de llamadas por minuto, descarte de campos sensibles). Backends:

* `nwrfc` — `connectors/nwrfc_connector.py`: binding ctypes sobre `sapnwrfc.dll`. Usa únicamente
  funciones documentadas en `sapnwrfc.h` (`RfcOpenConnection`, `RfcGetFunctionDesc`,
  `RfcInvoke`, `RfcSetString`, `RfcGetString`, `RfcGetTable`, …). **Estado: implementado contra
  la API documentada, no ejecutado contra un SAP real en este entorno.** Validar con
  `sapsec rfc-selftest`.
* `pyrfc` — heredado.
* `fixture` — datos ficticios (pruebas automatizadas).
* (Fase 4) `jco-sidecar` si la organización prefiere un componente 100 % soportado por SAP.

---

## 5. Arquitectura

```
                    ┌──────────────── Navegador (español) ────────────────┐
                    │  UI server-side (Jinja2)  ·  futura SPA React (TS)  │
                    └───────────────▲──────────────────────▲──────────────┘
                                    │ HTTPS (proxy inverso) │ API JSON /api/v1
┌───────────────────────────────────┴──────────────────────┴───────────────────────────┐
│ FastAPI  (sesión, roles de la app, CSRF, CSP, auditoría de consultas)                 │
├───────────────────────────────────────────────────────────────────────────────────────┤
│ Servicios: conexiones · extracción · análisis · hallazgos · mitigaciones · reportes   │
├───────────────┬───────────────────────────┬───────────────────────────┬───────────────┤
│ Conectores RFC│ Extractor (snapshots)     │ Motores (puros, sin I/O)  │ Reportes      │
│ nwrfc / pyrfc │ catálogo de fuentes,      │ valores · efectivas ·     │ XLSX/PDF/CSV/ │
│ / fixture     │ lotes, validación BAPI    │ críticas · SoD · riesgo · │ HTML          │
│ (solo lectura)│                           │ simulador · calidad rol   │               │
├───────────────┴───────────────────────────┴───────────────────────────┴───────────────┤
│ Persistencia: SQLAlchemy · SQLite (dev) / PostgreSQL (prod) · snapshots inmutables    │
├───────────────────────────────────────────────────────────────────────────────────────┤
│ Configuración: settings.yaml + SAPSEC_* · reglas YAML versionadas · credenciales en   │
│ Windows Credential Manager (keyring) o archivo cifrado (Fernet)                       │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

**Por qué**: el análisis nunca se hace "en vivo" contra SAP sino sobre snapshots: (1) una
sola lectura controlada por ventana horaria; (2) resultados reproducibles (snapshot + hash de
reglas); (3) comparaciones históricas y entre sistemas; (4) el simulador responde en segundos sin
cargar producción. Los motores son funciones puras sobre `SnapshotData`, lo que permite probarlos
sin SAP y reutilizarlos desde la UI, la API, la CLI o tareas programadas.

Estructura de carpetas:

```
sap-security-analyzer/
├─ config/rules/          critical_auth.yaml · sod_rules.yaml · risk_scoring.yaml
├─ config/settings.example.yaml
├─ docs/                  diseño, conectividad, usuario técnico, extractor Z, validación
├─ scripts/               install.ps1 · run.ps1 · build_demo_fixture.py
├─ src/sapsec/
│  ├─ connectors/         base · nwrfc_connector · pyrfc_connector · fixture_connector · table_reader
│  ├─ extraction/         sources (catálogo) · extractor
│  ├─ storage/            orm · db · snapshot_data
│  ├─ engine/             values · effective · rules · critical · sod · risk · analysis · simulator
│  ├─ reports/            exporters · builders
│  ├─ security/           auth · secrets · audit
│  ├─ api/                app · deps
│  ├─ web/                templates · static
│  ├─ services.py · config.py · cli.py
└─ tests/                 72 pruebas automatizadas + fixture ficticio
```

---

## 6. Inventario de fuentes SAP

Autorización de lectura de tablas: **`S_TABU_NAM` ACTVT=03 con la lista exacta de tablas** (no
`S_TABU_DIS` amplio). `RFC_READ_TABLE` verifica primero `S_TABU_DIS` y, si falla, `S_TABU_NAM`.
Todas las lecturas: campos explícitos, lotes por clave, versión activa (`AKTPS='A'`).

| Fuente | Información | Mandante | Método | Cómo evitar lecturas masivas | Limitaciones | Validación contra SAP |
|---|---|---|---|---|---|---|
| `BAPI_USER_GETLIST` | Lista de usuarios (+ nombre) | Dep. | BAPI liberada | `MAX_ROWS`, `SELECTION_RANGE` | Nombre completo = dato personal (configurable) | SU01 / SUIM |
| `BAPI_USER_GET_DETAIL` | Logon data, bloqueo, roles con validez, perfiles | Dep. | BAPI liberada (S_USER_GRP 03) | Solo muestreo o modo BAPI | Puede devolver hashes en LOGONDATA según release: **se descartan** sin persistir | SU01 |
| `USR02` | Tipo, grupo, validez, UFLAG, último acceso | Dep. | RFC_READ_TABLE, **campos restringidos** | Lotes de BNAME | Tabla con hashes: requiere aceptación de riesgo (o BAPI / Z) | SUIM RSUSR200 |
| `AGR_DEFINE` | Roles, rol padre, creador/modificador | Dep. | RFC_READ_TABLE | Lectura completa (pequeña) | — | PFCG |
| `AGR_TEXTS` | Descripción (LINE 00000) | Dep. | RFC_READ_TABLE | Filtro LINE e idioma | — | PFCG |
| `AGR_FLAGS` | Rol compuesto (`COLL_AGR`) **[verificar]** | Dep. | RFC_READ_TABLE | Filtro FLAG_TYPE | Opcional; fallback AGR_AGRS | PFCG |
| `AGR_AGRS` | Compuesto → simples | Dep. | RFC_READ_TABLE | — | — | PFCG |
| `AGR_USERS` | Asignación rol-usuario, validez, `COL_FLAG` | Dep. | RFC_READ_TABLE | Lotes por UNAME | Puede diferir de UST04 hasta PFUD | SUIM RSUSR070 / SU01 |
| `AGR_1016` | Perfiles generados por rol | Dep. | RFC_READ_TABLE | — | — | PFCG pestaña autorizaciones |
| `AGR_1251` | Valores definidos en PFCG | Dep. | RFC_READ_TABLE | Lotes por AGR_NAME | Definición ≠ efectivo | PFCG modo experto |
| `AGR_1252` | Niveles organizativos | Dep. | RFC_READ_TABLE | Lotes por rol | — | PFCG |
| `AGR_TCODES` | Menú del rol | Dep. | RFC_READ_TABLE | Lotes por rol | Menú no autoriza | PFCG menú |
| `AGR_PROF` | Nombre/texto de perfil | Dep. | (no imprescindible) | — | Redundante con AGR_1016 | — |
| `UST04` | Perfiles en el maestro de usuario | Dep. | RFC_READ_TABLE | Lotes por BNAME | — | SU01 pestaña perfiles |
| `UST10C` | Perfil compuesto → subperfiles | Dep. | RFC_READ_TABLE | Expansión iterativa solo de perfiles relevantes | — | SU02 |
| `UST10S` | Perfil → (objeto, autorización) | Dep. | RFC_READ_TABLE | Lotes por PROFN relevante | — | SU02 |
| `UST12` | Valores de campos por autorización | Dep. | RFC_READ_TABLE | Lotes por OBJCT de perfiles relevantes | Gran volumen | SU03 / SUIM RSUSR002 |
| `USR04` | Perfiles (formato antiguo empaquetado) | Dep. | No se usa | — | Campo empaquetado; UST04 es preferible | — |
| `USR21` | Vínculo a persona/dirección | Dep. | No se usa (minimización) | — | Dato personal | — |
| `TOBJ` / `TOBJT` | Objetos y campos / textos | Indep. | RFC_READ_TABLE | Lotes por objeto | — | SU21 |
| `TACT` / `TACTT` | Actividades / textos | Indep. | RFC_READ_TABLE (TACTT) | Filtro idioma | Validez por objeto en `TACTZ` **[verificar]** | SU21 |
| `TSTC` / `TSTCT` | Transacción → programa / textos | Indep. | RFC_READ_TABLE | Solo tcodes relevantes | — | SE93 |
| `TSTCA` | Chequeo de autorización de inicio | Indep. | RFC_READ_TABLE | Solo tcodes relevantes | Solo el chequeo de inicio | SE93 |
| `USOBT_C` / `USOBX_C` | Propuestas y chequeos SU24 | Indep. | Fase 3 | Por tcode | Mantención del cliente | SU24 |
| `USOBHASH` | Hash S_SERVICE → servicio | Indep. | RFC_READ_TABLE | Solo hashes presentes | — | SU24 / PFCG |
| `USH04/USH10/USH12/USH02` | Historial de cambios de usuarios/perfiles | Dep. | Fase 4 | Por fecha | USH02 contiene hashes: **no** se lee | SUIM RSUSR100N |
| `CDHDR/CDPOS` | Documentos de modificación (roles: clase **[verificar]**) | Dep. | Fase 4 | Por OBJECTCLAS y fecha | Ancho de CDPOS; volumen | SUIM "documentos de modificación" |
| `E070/E071` | Transportes que contienen roles (R3TR ACGR) | Indep. | Fase 4 | Por objeto ACGR | — | SE09/SE10 |

---

## 7. Matriz de viabilidad por dato

| Dato | Fuente | Método | Autorizaciones | Factibilidad | Limitaciones | Alternativa | Prioridad |
|---|---|---|---|---|---|---|---|
| Lista de usuarios | BAPI_USER_GETLIST | BAPI | S_RFC (SU_USER), S_USER_GRP 03 | Alta | — | USR02 | P1 |
| Tipo/grupo/validez/bloqueo | USR02 | RFC_READ_TABLE campos permitidos | S_TABU_NAM USR02 | Alta | Tabla sensible | BAPI_USER_GET_DETAIL (lento: 1 llamada/usuario) | P1 |
| Último acceso | USR02 TRDAT | RFC_READ_TABLE | S_TABU_NAM USR02 | Media | Riesgo de acceso a hashes si el usuario técnico se usa indebidamente | Extractor Z / `SUSR_GET_ADMIN_USER_LOGIN_INFO` **[verificar RFC]** | P1 |
| Roles asignados y validez | AGR_USERS | RFC_READ_TABLE | S_TABU_NAM | Alta | — | BAPI_USER_GET_DETAIL | P1 |
| Perfiles del usuario | UST04 | RFC_READ_TABLE | S_TABU_NAM | Alta | — | BAPI_USER_GET_DETAIL | P1 |
| Autorizaciones efectivas | UST10C/UST10S/UST12 | RFC_READ_TABLE | S_TABU_NAM | Alta | Volumen | Extractor Z | P1 |
| Definición de roles | AGR_1251/1252/AGR_DEFINE/… | RFC_READ_TABLE | S_TABU_NAM | Alta | — | Extractor Z | P1 |
| Objetos/campos/actividades | TOBJ/TACTT | RFC_READ_TABLE | S_TABU_NAM | Alta | — | — | P1 |
| Transacciones y chequeo de inicio | TSTC/TSTCT/TSTCA | RFC_READ_TABLE | S_TABU_NAM | Alta | — | — | P1 |
| Servicios Fiori/OData | USOBHASH | RFC_READ_TABLE | S_TABU_NAM | Alta | — | — | P2 |
| Catálogos/espacios/páginas | AGR_TCODES/AGR_HIER/AGR_BUFFI, /UI2/* | RFC_READ_TABLE | S_TABU_NAM | Media | Modelo de datos del launchpad **[verificar]** | Extractor Z / API launchpad | P3 |
| SU24 | USOBT_C/USOBX_C | RFC_READ_TABLE | S_TABU_NAM | Alta | — | — | P3 |
| Cambios de usuarios/perfiles | USH04/USH10/USH12 | RFC_READ_TABLE | S_TABU_NAM | Media | Cobertura parcial | Diferencia de snapshots | P4 |
| Cambios de roles | CDHDR/CDPOS | RFC_READ_TABLE | S_TABU_NAM | Media | Clase de objeto a confirmar; CDPOS ancho | Diferencia de snapshots | P4 |
| Ejecución real de transacciones | ST03N / STAD | — | — | Baja | No hay API RFC estándar sencilla **[verificar]** | Exportes / SAL | P4 |
| Security Audit Log | SM20 / archivos | — | — | Baja | No vía RFC estándar | SIEM / extractor Z | P4 |

---

## 8. Diseño de la extracción RFC (respuestas a los 15 puntos)

1. **Funciones RFC estándar**: `RFC_PING`, `RFC_SYSTEM_INFO`, `RFC_GET_FUNCTION_INTERFACE`, `RFC_READ_TABLE`, `BAPI_USER_GETLIST`, `BAPI_USER_GET_DETAIL`, `DDIF_FIELDINFO_GET`.
2. **BAPIs apropiadas**: las de usuario (`BAPI_USER_*` de lectura). No existen BAPIs liberadas para valores de autorización de roles.
3. **Mecanismos alternativos**: valores PFCG, perfiles y valores efectivos solo por tablas; Fiori y auditoría por tablas específicas o extractor Z.
4. **Tablas necesarias**: ver §6 (catálogo ejecutable en `extraction/sources.py`).
5. **Autorizaciones de lectura**: rol `Z_SECX_RFC_READ` (ver `docs/03_usuario_tecnico_rfc.md`).
6. **Evitar SAP_ALL**: el rol técnico tiene solo S_RFC por función, S_TABU_NAM por tabla, S_USER_GRP 03; usuario de tipo *Sistema*.
7. **Limitar S_RFC**: `RFC_TYPE=FUNC` con nombres exactos (y `FUGR` solo si la traza lo exige); complementar con UCON (lista blanca de RFC) en PRD.
8. **Limitar S_TABU_DIS/S_TABU_NAM**: no asignar S_TABU_DIS; S_TABU_NAM ACTVT=03 con la lista exacta; nada de `*`.
9. **Consultas costosas**: lectura dirigida (claves primero), lotes `IN` acotados, límite de filas por llamada, pausa entre llamadas, límite de llamadas/minuto, ventana horaria (operativa), sin `ROWSKIPS` salvo último recurso.
10. **Cientos de miles de registros**: particionado por clave (UNAME, AGR_NAME, PROFN, OBJCT); inserción en bloques de 5000; snapshot en base relacional.
11. **Tablas de gran volumen**: `UST12`/`AGR_1251` solo para perfiles/roles relevantes; extractor Z con paginación por clave si se requiere.
12. **Paginación**: por rango/lista de claves; `ROWSKIPS` solo si una clave supera el máximo (registrado como evento).
13. **Limitaciones de RFC funciones antiguas**: ancho 512 (validado con `NO_DATA='X'`), parsing por `OFFSET/LENGTH` (sin delimitadores), escape de comillas en WHERE, líneas de OPTIONS ≤ 72 caracteres, sin campos P/F.
14. **Errores de conexión y permisos**: excepciones tipadas (`RfcLogonError`, `RfcAuthorizationError`, …); un dataset sin permiso marca el snapshot como *incompleto* sin abortar; el diagnóstico de conexión lista funciones y tablas permitidas.
15. **Completitud**: estado por dataset, contador de truncamientos, validación por muestreo contra BAPI, verificación del SID, y bloqueo de "APROBACIÓN RECOMENDADA" si el snapshot está incompleto o desactualizado.

---

## 9. Modelo de datos

* **Aplicación**: `sap_system`, `sap_connection` (sin contraseña, solo `credential_ref`), `snapshot` (estado, estadísticas por dataset, incidencias, hash de reglas, marca de datos de prueba), `finding` (identificador visible `H-SID-MANDANTE-xxxx`, *fingerprint* estable entre snapshots, regla y versión, gravedad, evidencia JSON, puntajes inherente/residual, estado, responsable, excepción, vencimiento, mitigación), `mitigation`, `simulation`, `app_user`, `audit_log`.
* **Datos SAP**: una tabla `sap_<dataset>` por fuente, generada desde el catálogo (`storage/orm.py`), con `snapshot_id`. Los snapshots son inmutables; su retención es configurable.

---

## 10. Modelo de autorizaciones efectivas

```
AGR_USERS (vigencia) ──► rol ──► AGR_1016 ──► perfil generado ─┐
                                                               ├─► ¿está en UST04? ─► UST10C* ─► UST10S ─► UST12
perfiles directos (SAP_ALL, S_A.SYSTEM, …) ────────────────────┘
```

Niveles de certeza (enum `Certainty`):

| Nivel | Significa | Fuente |
|---|---|---|
| Definido en rol | Valor en PFCG, quizá no generado | AGR_1251 |
| En perfil | Valor en el perfil generado | UST10S/UST12 |
| Asignado | Perfil presente en el maestro del usuario | UST04 |
| Capacidad potencial | Además la transacción puede iniciarse (S_TCODE + TSTCA) | Motor |
| Confirmado en SAP | Verificado por traza/SU53/prueba | Fuera del alcance de RFC (manual) |

Reglas del motor (`engine/effective.py`, `engine/values.py`):
* Un requisito se cumple con **una** instancia; nunca se combinan campos de instancias distintas.
* `*`, prefijos `ABC*`, rangos `VON–BIS`, `' '` y variables `$XXX` sin resolver con su semántica.
* Roles vigentes cuyo perfil no está en UST04 → *comparación pendiente*; perfiles en UST04 sin rol vigente → *perfil residual* (siguen otorgando acceso).
* Roles sin perfil o con perfil desactualizado → hallazgo de calidad; en simulación se usa la definición PFCG con certeza reducida.
* Usuarios bloqueados: los permisos se conservan; se distingue riesgo actual y potencial.
* Nunca se afirma ejecución: la UI y los reportes recuerdan que los AUTHORITY-CHECK internos y la lógica Fiori/OData backend pueden restringir o ampliar.

---

## 11. Motor SoD

* **Función** = acciones alternativas; **acción** = transacciones (opcional) + requisitos por objeto/campo/valor. Acciones sin transacción modelan Fiori/API/RFC.
* **Riesgo** = combinación de ≥2 funciones; gravedad, proceso, recomendación, control mitigante sugerido, campos organizativos a comparar.
* Evaluación sobre el conjunto efectivo del usuario (incluye perfiles directos), sobre un rol aislado (SoD intra-rol) y sobre escenarios simulados.
* Para cada conflicto: roles que aportan cada función, evidencia técnica, alcance (*intra-rol*, *entre roles*, *incluye perfil directo*) y análisis organizativo.
* Restricciones organizativas: se informa solapamiento o no solapamiento; **nunca se oculta** el conflicto.
* Gobierno: estados `ejemplo → validada → aprobada`, versión por archivo, hash del conjunto en cada análisis; excepciones y mitigaciones con responsable, justificación y vencimiento.

---

## 12. Catálogo inicial de riesgos

`config/rules/critical_auth.yaml` (31 reglas) y `config/rules/sod_rules.yaml` (30 funciones, 26 riesgos (ECC: compras, ventas, contabilidad, logística, seguridad y cambios)), todas en estado **ejemplo**. Cubren superusuarios (SAP_ALL, SAP_NEW, S_A.SYSTEM, equivalencias), administración de usuarios y roles (S_USER_*), desarrollo (S_DEVELOP incl. DEBUG), tablas (S_TABU_DIS/NAM/CLI), RFC (S_RFC, S_RFCACL), SO (S_LOG_COM, S_DATASET), programas (S_PROGRAM), jobs (S_BTCH_NAM/ADM), transportes (S_CTS_ADMI, S_TRANSPRT), administración (S_ADMI_FCD, AUDA), Fiori (S_SERVICE, S_START), S_TCODE `*`, usuarios estándar e inactividad; y SoD de Finanzas, Compras, Materiales, Seguridad SAP y Gestión de cambios.

Los valores marcados en las reglas como "validar con SU24" (p. ej. `F_REGU_BUK-FBTCH`, `M_ISEG_WDB`) deben confirmarse en el sistema antes de pasar la regla a *validada*.

---

## 13. Simulador

1. Análisis actual (efectivas, críticas, SoD, riesgo).
2. Escenario: agregar/quitar/sustituir roles (simples o compuestos) y cambios hipotéticos de valores.
3. Construcción del estado simulado: se retiran perfiles de roles quitados, se agregan instancias del perfil generado (o de PFCG si no está generado/consistente, con certeza reducida).
4. Diferencias: permisos nuevos (marcando los ya cubiertos por subsunción), críticas nuevas/resueltas, SoD nuevos/preexistentes/resueltos, variación del riesgo.
5. Recomendación orientativa con motivos exactos y evidencia:
   * **NO RECOMENDADO**: algún riesgo nuevo de gravedad crítica.
   * **REQUIERE REVISIÓN**: riesgos nuevos medio/alto, aumento de nivel, rol inexistente/no generado, snapshot incompleto o desactualizado.
   * **APROBACIÓN RECOMENDADA**: nada de lo anterior, indicando cuántas reglas se evaluaron y su estado.
6. Alternativas: roles existentes con ≥50 % de cobertura de transacciones del rol pedido, re-simulados; confianza *baja/media* y advertencia de validar funcionalmente.
7. Persistencia de la simulación (auditoría) y reportes técnico/ejecutivo.

---

## 14. Motor de riesgos

`puntos = gravedad × factor_sistema × factor_tipo_usuario × factor_certeza`; inherente = Σ;
actual = inherente × factor de bloqueo/validez; residual aplica eficacia de controles aprobados y
vigentes (máx. 0,9). Niveles por umbrales configurables (`risk_scoring.yaml`). Desglose visible por hallazgo.

---

## 15. Seguridad Fiori (diseño; implementación completa en fase 3)

* **Acceso visual ≠ autorización**: catálogos/espacios/páginas determinan qué tiles se ven; `S_SERVICE` (inicio del servicio OData/ICF), `S_START`/`S_TCODE` y los objetos de negocio del backend determinan qué se puede ejecutar.
* Implementado: detección de `S_SERVICE` con comodín, traducción de hashes vía `USOBHASH`, menú del rol.
* Fase 3: catálogos y espacios por rol, relación app ↔ servicio ↔ objetos SU24, detección de apps críticas asignadas.

---

## 16. Monitoreo continuo y cambios

* Hoy: snapshots repetibles (CLI programable con el Programador de tareas de Windows), conservación del estado de hallazgos entre snapshots (fingerprint), detección de hallazgos nuevos y **corregidos**, comparador de snapshots (roles nuevos/eliminados/modificados, asignaciones nuevas/eliminadas, objetos críticos que difieren).
* Fase 4: documentos de modificación (USH04/USH10/USH12, CDHDR/CDPOS **[verificar clases]**) como evidencia complementaria; cuando no existan, la diferencia de snapshots se presenta indicando la limitación ("cambio inferido, sin autor ni hora exacta").

---

## 17. Riesgos de consultar producción y mitigaciones

| Riesgo | Mitigación |
|---|---|
| Carga sobre la base de datos | Lotes por clave, límites de filas y llamadas, ventana horaria, extracción dirigida |
| Usuario técnico con permisos excesivos | Rol mínimo documentado; nada de SAP_ALL / S_TABU_DIS `*` |
| Exposición de hashes de contraseña | Campos prohibidos en el lector; modo BAPI; extractor Z con lista blanca |
| Robo de credenciales del usuario técnico | Credential Manager / archivo cifrado; SNC; usuario tipo Sistema; rotación |
| Lecturas no autorizadas desde la herramienta | Autenticación, roles de la app, auditoría de cada consulta |
| Datos de producción en equipos de trabajo | Servidor dedicado, cifrado de disco, retención configurable, reportes protegidos |
| Datos productivos hacia IA externa | Deshabilitado por defecto (`ai_external_allowed: false`) |
| Bloqueo de la cuenta por intentos fallidos | Prueba de conexión explícita antes de extraer; sin reintentos automáticos de logon |
| Llamadas de escritura accidentales | Lista permitida de funciones + bloqueo por patrón |

---

## 18. Mínimo desarrollo en SAP

Versión 1: **cero objetos Z**. Se requiere solo un usuario técnico y un rol PFCG de lectura.
El extractor Z (`docs/04_extractor_z_opcional.md`) se propone únicamente si: (a) la política
prohíbe `S_TABU_NAM` sobre USR02/UST12, (b) el volumen hace inviable `RFC_READ_TABLE`, o (c) se
necesitan fuentes sin acceso tabular razonable (Security Audit Log, launchpad).

---

## 19. IA

Opcional, desactivada por defecto. Solo recibe hallazgos ya calculados (no datos crudos) y
únicamente puede: explicar, resumir y redactar. Toda afirmación debe citar regla, objeto, campo,
valor y rol de la evidencia; las detecciones nunca dependen del modelo. La aplicación funciona
íntegramente sin IA (las explicaciones actuales son plantillas deterministas).

---

## 20. Pruebas y validación contra herramientas SAP

Ver `docs/05_validacion.md`. 72 pruebas automatizadas con un sistema ficticio cubren: SAP_ALL,
SAP_NEW, compuestos, derivados, perfiles directos, vencidos/futuros, perfiles residuales,
restricciones organizativas, comodines, bloqueados, SoD entre roles/intra-rol/perfil directo,
conflictos preexistentes vs nuevos, simulaciones sin riesgo, roles redundantes, perfiles no
generados/desactualizados, datos incompletos y falta de permisos del usuario RFC.

---

## 21. Plan de implementación

| Fase | Contenido | Estado |
|---|---|---|
| 1 | Investigación y diseño (este documento) | **Entregado** |
| 2 | MVP: conexiones, prueba RFC, extracción, usuarios, roles, valores, SAP_ALL/SAP_NEW, críticas, consultas, simulador, evidencia, reportes | **Entregado** (validado con datos ficticios; pendiente validación contra SAP real) |
| 3 | SoD avanzado (aprobación de reglas en UI), simulaciones complejas, comparadores con exportación, recomendador ampliado, Fiori completo, SU24, frontend React | Base implementada (SoD, comparadores, recomendaciones básicas) |
| 4 | Programación interna, alertas, documentos de modificación, flujo de excepciones/mitigaciones, SSO (Entra ID/SAML), PostgreSQL, rendimiento, firefighter, recertificación, SIEM | Planificado |

### Qué funciona hoy y con qué datos

| Componente | Datos de prueba | SAP real |
|---|---|---|
| Motores (efectivas, críticas, SoD, riesgo, simulador, calidad de roles) | Probado (72 pruebas) | Mismo código; depende de la extracción |
| Extractor + lector de tablas | Probado con conector ficticio que emula RFC_READ_TABLE | **Pendiente de validar** en su sistema |
| Backend `nwrfc` (ctypes) | No aplica | **Implementado, no ejecutado contra SAP en este entorno** → `sapsec rfc-selftest` |
| Backend `pyrfc` | No aplica | Implementado (heredado), no probado aquí |
| UI, reportes, seguridad de la app | Probado | Igual |
