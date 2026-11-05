# S/4HANA con Fiori y sistemas de desarrollo

## Agregar un S/4HANA

Se registra igual que un ECC (Conexiones SAP): SID, mandante, ambiente, servidor, usuario RFC (mismo rol de
lectura, ver docs/03, que ya incluye las tablas que suman en S/4: USOBHASH, USOBX_C, USOBT_C y CVERS).
La aplicación detecta sola el producto por los componentes (tabla CVERS) y lo muestra: «SAP S/4HANA (S4CORE …)
· con Fiori».

* **Fiori embebido** (lo habitual desde S/4HANA 1909): el launchpad y los servicios están en el mismo sistema;
  no hace falta nada más.
* **Fiori en un servidor aparte (hub / front-end server)**: registrarlo también como sistema (es otro SID). Ahí están los
  catálogos y el permiso de inicio del launchpad; los permisos de negocio y los conflictos se analizan en el S/4.

## Qué cambia en el análisis

| Tema | ECC | S/4HANA con Fiori |
|---|---|---|
| Punto de entrada | Transacciones (`S_TCODE`) | Transacciones **o apps Fiori** (`S_SERVICE` del servicio OData) |
| Nombre del servicio | — | Se traduce el hash de `S_SERVICE` con USOBHASH (fichas de usuario y rol, pestaña «Fiori / OData») |
| Conflictos SoD | Por transacción + objetos | Si la persona no tiene la transacción, la acción igual se cumple cuando tiene un servicio OData que, **según la SU24 del propio sistema** (USOBX_C/USOBT_C, `TYPE = 'HT'`), verifica el objeto principal con la actividad pedida. La evidencia nombra el servicio. |
| Proveedores y clientes | XK02 / FK02 / XD02 | Interlocutor comercial (BP) con `B_BUPA_RLT` y los roles FLVN00/FLVN01 (proveedor) o FLCU00/FLCU01 (cliente) |

Ejemplo (datos ficticios): una compradora crea pedidos con una app Fiori y los libera con ME29N. No tiene ME21N, pero el
servicio de la app verifica `M_BEST_BSA` con actividad 01/02 según la SU24: el conflicto «Crear pedidos de compra y
liberarlos» se detecta e indica el servicio. Un servicio de solo visualizar (SU24 con actividad 03) no cuenta.

**Límites (a validar en su sistema):** la vía Fiori depende de que la SU24 de los servicios esté mantenida (SU25 / SU24
en el sistema). Si falta, se informan los permisos por transacción y por objeto, pero un conflicto hecho solo por Fiori
puede no detectarse. Verifique con una traza (STAUTHTRACE) las apps críticas de su organización. Algunas funciones de ECC
cambian en S/4HANA (p. ej. la gestión de crédito pasa a SAP Credit Management): la página «Reglas › Verificación contra
el sistema» marca las transacciones de las reglas que no existen en ese sistema.

## Controles distintos para DEV y QA

Cada regla tiene su gravedad en PRD y, opcionalmente, otra en QA y DEV (`by_environment` en los YAML; la página
«Reglas» muestra las tres columnas). Perfil incluido (ejemplo, ajustable):

| Qué | PRD | QA | DEV |
|---|---|---|---|
| SAP_ALL, equivalentes, S_A.SYSTEM | crítico | crítico | alto |
| Administración de usuarios y asignación de roles | alto / crítico | igual | alto (mantener roles: bajo) |
| Desarrollar (S_DEVELOP crear/modificar) | crítico | alto | no aplica (dato informativo) |
| Depurar con modificación (debug & replace) | crítico | alto | bajo |
| Modificar todas las tablas | crítico | alto | medio |
| Crear y liberar órdenes de transporte | medio | medio | no aplica |
| Importar transportes | alto | alto | medio |
| Comandos de sistema operativo, usuarios estándar desbloqueados | alto | alto | alto |
| Conflictos de procesos de negocio (pagos, compras, ventas…) | según regla | no aplica | no aplica |
| Conflictos técnicos (mantener + asignar roles, desarrollar + importar) | crítico | alto / crítico | medio / bajo |

## Control entre sistemas: desarrollo vs. producción

El riesgo más importante de un DEV no está en el DEV: es que **quien desarrolla tenga permisos críticos en
producción** (podría llevar su propio código o saltear controles). La página **Comparar › Desarrollo vs. producción**
cruza los últimos snapshots: desarrolladores de un DEV (regla informativa INFO-DEV-001) que en el PRD del mismo
**landscape** tienen SAP_ALL, desarrollo, depuración con modificación, importación de transportes, mantenimiento de
tablas, administración de usuarios, etc. (lista en `critical_auth.yaml › landscape`). El inicio del PRD avisa si hay casos.

El **landscape** agrupa los DEV, QA y PRD que comparten transportes («ECC Uruguay», «S/4 corporativo»…). Se define al
registrar el sistema o después, en Conexiones SAP (Ambiente / Landscape / Guardar). Si no se define, se comparan todos
los DEV con todos los PRD y se marca para verificar.

Después de cambiar el ambiente de un sistema ya extraído, vuelva a extraerlo para que se apliquen sus controles.
