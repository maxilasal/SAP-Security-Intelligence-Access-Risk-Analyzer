# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado
[semántico](https://semver.org/lang/es/): `MAYOR.MENOR.PARCHE` (MAYOR = cambios incompatibles, por ejemplo en
la base o en las reglas; MENOR = funciones nuevas; PARCHE = correcciones).

## [Sin publicar]

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

[Sin publicar]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/releases/tag/v0.1.0
