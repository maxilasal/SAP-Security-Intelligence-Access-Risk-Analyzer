# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado
[semántico](https://semver.org/lang/es/): `MAYOR.MENOR.PARCHE` (MAYOR = cambios incompatibles, por ejemplo en
la base o en las reglas; MENOR = funciones nuevas; PARCHE = correcciones).

## [Sin publicar]

## [0.2.0] - 2026-11-05

### Cambiado
- **Una sola alerta por SAP_ALL.** Con SAP_ALL (o SAP_NEW, S_A.SYSTEM) casi todas las reglas se cumplen: ahora
  se genera una alerta por el perfil y los riesgos que existen solo por él van dentro de ella («desaparecen al
  quitarlo»). Lo que la persona igual tendría sin el perfil, por sus roles, sigue como alerta propia. En los datos
  de prueba, un usuario con SAP_ALL pasa de 40 alertas a 1, y su puntaje de riesgo de la suma de todas a 100.
- Al volver a analizar, las alertas que pasan a estar dentro de SAP_ALL no se informan como «corregidas».
- La tarea de SAP_ALL lista los riesgos que desaparecen al quitarlo, avisa cuántos usuarios están bloqueados y
  muestra primero a quienes hoy pueden ingresar.

### Agregado
- **Búsquedas con comodines como en SAP:** `Z*` empieza con Z, `*PAGO*` contiene, `+` un carácter, varios
  criterios separados por coma. En usuarios, roles, tareas, búsqueda por autorización (objeto `S_TABU*`,
  transacción `SE*`, rol, perfil), hallazgos y en el filtro de cada tabla.
- Usuarios: filtros por rol, perfil, riesgo mínimo y «sin actividad», marca SAP_ALL en la lista y atajos.
- Plan de acción descargable (Excel, PDF, CSV, HTML) con la recomendación, los pasos y columnas para
  responsable y fecha compromiso.
- Inicio: el indicador de SAP_ALL informa cuántos de esos usuarios están bloqueados.

## [0.1.0] - 2026-11-05

Primera versión publicada en el repositorio. Reúne todo lo construido hasta la fecha.

### Conectividad y extracción (solo lectura)
- Conexión RFC con el SAP NW RFC SDK 7.50 (binding propio; PyRFC opcional) y backend de datos ficticios.
- Lectura con RFC_READ_TABLE acotada a una lista de tablas y campos permitidos; nunca contraseñas ni hashes.
- Validación cruzada con BAPI_USER_GET_DETAIL, huella del sistema real y tolerancia a errores por tabla.
- Probado contra un ECC 7.31 real (QAS): usuarios, roles, perfiles y autorizaciones completos.

### Análisis
- Autorizaciones efectivas por instancia, con certeza (definido en rol, en perfil, asignado, capacidad potencial).
- Reglas críticas y matriz SoD configurables en YAML (estado «ejemplo», no son la matriz oficial de SAP GRC),
  con verificación contra la SU24 del propio sistema.
- Riesgo inherente, actual y residual; usuarios bloqueados; controles mitigantes y excepciones con vencimiento.
- Simulador de asignaciones (agregar, quitar, sustituir roles y cambios hipotéticos de valores) con alternativas.

### Interfaz
- «Qué corregir primero»: tareas agrupadas por causa (rol, combinación de roles, perfil, usuarios, calidad)
  con un recuadro «Recomendación» (una frase, por qué, pasos numerados y dónde en SAP) en cada pantalla.
- Varios sistemas (PRD, QA, DEV) con nombre propio, historial de snapshots y comparación entre sistemas y fechas.
- Reportes en Excel, PDF, CSV y HTML; registro de auditoría de la propia aplicación.

### Operación
- Extracciones programadas (también nocturnas con el Programador de tareas de Windows).
- Acceso desde otras PC: modo red con HTTPS (CA local restringida o certificado de la empresa), redes permitidas,
  scripts de firewall e inicio con Windows; bloqueo temporal tras intentos fallidos y gestión de usuarios.

### S/4HANA y sistemas de desarrollo
- Detección del producto (CVERS), servicios Fiori/OData con su nombre (USOBHASH) y conflictos SoD hechos desde
  apps Fiori según la SU24 de los servicios.
- Controles distintos por ambiente (`by_environment`): en DEV y QA no aplican los conflictos de negocio y
  desarrollar o liberar transportes no se marca.
- «Desarrollo vs. producción»: desarrolladores de DEV con permisos críticos en el PRD del mismo landscape.

### Repositorio y versiones
- Pruebas automáticas (GitHub Actions) en Windows y Linux en cada cambio.
- Publicación automática: al subir a `main` una versión nueva con las pruebas en verde, se crean el tag y la
  Release con estas notas. La versión instalada se ve en la interfaz y en `scripts\actualizar.ps1`.
- `scripts\actualizar.ps1` para actualizar cada instalación desde Git sin tocar sus datos.

[Sin publicar]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/releases/tag/v0.1.0
