# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado
[semántico](https://semver.org/lang/es/): `MAYOR.MENOR.PARCHE` (MAYOR = cambios incompatibles, por ejemplo en
la base o en las reglas; MENOR = funciones nuevas; PARCHE = correcciones).

## [Sin publicar]

## [0.5.0] - 2026-11-06

### Agregado
- **Logo propio** (un escudo con cerradura): en la pestaña del navegador, en el menú lateral y en la pantalla de
  ingreso. El ícono de la pestaña toma el color del tema elegido y se ve en pestañas claras y oscuras.
- **Temas de colores**: Azul (el de siempre), Petróleo, Verde, Bordó, Violeta, Grafito y Cobre. Cada persona elige el
  suyo en *Mi cuenta* (o con el círculo de color junto a su usuario, arriba a la derecha); se guarda en su usuario y,
  en ese navegador, también se usa en la pantalla de ingreso. Todos cumplen el contraste mínimo de accesibilidad
  (WCAG AA, verificado por una prueba automática); los colores de las alertas no cambian.

## [0.4.0] - 2026-11-06

### Agregado
- **Funcionamiento continuo** (`scripts\iniciar_con_windows.ps1`, como administrador): la aplicación queda siempre
  activa en modo red. Arranca sola al encender o reiniciar el servidor aunque nadie inicie sesión; si se cae, se
  vuelve a abrir en segundos; si deja de responder (unos 2 minutos), se cierra y se vuelve a abrir; y cada 5 minutos
  Windows comprueba que el vigilante siga activo. Opciones `-Estado`, `-Detener`, `-Iniciar` y `-Quitar`.
- `sapsec servicio`: el vigilante (una sola copia por instalación; en Windows la aplicación se cierra con él y no
  quedan procesos huérfanos). Registro en `data\logs\servicio.log` y estado en Configuración y acceso.
- `sapsec estado-servicio` y `sapsec verificar-credenciales` (qué conexiones SAP tienen la contraseña guardada para
  el usuario de Windows que ejecutará el servicio; el instalador lo revisa antes de instalar).

### Cambiado
- `scripts\actualizar.ps1` detiene el servicio sin que se reabra a mitad de la actualización, no actualiza si hay
  una extracción en curso o una ventana de la aplicación abierta, y lo vuelve a iniciar también si algo falló.
- Pruebas automáticas: además, una prueba real en Windows que instala la tarea programada con usuario y contraseña,
  tira la aplicación y verifica que vuelve sola.

## [0.3.0] - 2026-11-05

### Agregado
- **Usuarios de emergencia declarados** (Seguimiento › Usuarios de emergencia): se declara el usuario con su
  responsable, procedimiento de uso y fecha de revisión (máximo un año), para un sistema o para todos. Mientras
  esté **bloqueado** (o fuera de su validez) y la declaración vigente, sus alertas quedan controladas y **no
  aparecen como pendientes en cada extracción**. Si se **desbloquea**, aparece la tarea «Mantener bloqueados los
  usuarios de emergencia» con la recomendación «Bloquear … si no hay una emergencia en curso»; si la declaración
  **vence**, vuelve a ser pendiente hasta renovarla. Las decisiones tomadas por una persona (excepción, falso
  positivo, control mitigante) nunca se modifican, y cada alta, renovación o baja queda en la auditoría.
  Se declara desde la tarea de SAP_ALL («Es de emergencia»), desde la ficha del usuario o desde la página, que
  además lista los usuarios con SAP_ALL todavía sin declarar.
- **Qué cambió entre dos fechas** (Seguimiento › Qué cambió): elige dos extracciones del mismo sistema y muestra
  las alertas nuevas y resueltas y los cambios en SAP que las explican (roles asignados o quitados, perfiles
  asignados a mano —SAP_ALL resaltado—, usuarios nuevos, borrados, bloqueados o desbloqueados, roles nuevos,
  borrados o modificados), más las decisiones registradas en la aplicación en ese período. Con recomendación
  («Revisar por qué se asignó SAP_ALL a …») y descarga en Excel o PDF.
- Inicio: «Desde la extracción anterior: N alertas nuevas (M críticas) · K resueltas › Ver qué cambió», y el
  indicador de SAP_ALL informa cuántos son usuarios de emergencia. El historial de cada sistema enlaza a
  «Qué cambió hasta el último».

### Cambiado
- La recomendación de la tarea de SAP_ALL sugiere declarar como usuario de emergencia a quien lo tiene a propósito,
  en lugar de registrar una excepción.
- En Windows, la consola de la aplicación ya no muestra códigos de color («←[32mINFO←[0m»).

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

[Sin publicar]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer/releases/tag/v0.1.0
