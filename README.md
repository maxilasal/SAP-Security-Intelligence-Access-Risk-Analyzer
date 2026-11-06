# SAP Security Intelligence & Access Risk Analyzer

Plataforma de análisis de seguridad y autorizaciones SAP **de solo lectura**: reconstruye las
autorizaciones efectivas de cada usuario, detecta autorizaciones críticas y conflictos SoD con
evidencia técnica, y **simula asignaciones de roles antes de realizarlas en SAP**.

* Python 3.11+ · FastAPI · SQLAlchemy (SQLite / PostgreSQL) · interfaz web en español.
* Conectividad: SAP NW RFC SDK 7.50 (binding propio, ya que PyRFC fue archivado por SAP), PyRFC heredado o datos ficticios.
* Sin desarrollos Z (extractor Z opcional documentado).
* Nunca modifica usuarios, roles, perfiles ni autorizaciones.

Documentación: [diseño de la Fase 1](docs/01_fase1_diseno.md) · [conectividad RFC](docs/02_conectividad_rfc.md) ·
[usuario técnico](docs/03_usuario_tecnico_rfc.md) · [extractor Z opcional](docs/04_extractor_z_opcional.md) ·
[pruebas y validación](docs/05_validacion.md) · [acceso desde otras PC](docs/06_acceso_desde_otras_pc.md) · [S/4HANA, Fiori y DEV](docs/07_s4hana_fiori_y_desarrollo.md) · [versionado y actualización](docs/08_versionado_y_actualizacion.md) · [usuarios de emergencia y qué cambió](docs/09_emergencia_y_cambios.md) · [funcionamiento continuo](docs/10_funcionamiento_continuo.md) · [cambios](CHANGELOG.md)

## Uso diario (en 3 pasos)

1. **«Qué corregir primero»** (inicio): arriba, un recuadro **Recomendación de hoy** con UNA frase que dice
   qué hacer (por ejemplo *«Quitar el perfil SAP_ALL a ADMIN_BASIS y asignarle solo los roles que necesita»*),
   por qué y a cuántos usuarios afecta. Debajo, las siguientes tareas en orden.
2. **Abrir la tarea**: el recuadro **Recomendación** repite la frase y agrega los pasos numerados, dónde hacerlo
   en SAP (PFCG, SU01, SU10, PFUD) y los avisos (rol derivado o compuesto, transporte en PRD). Debajo, los puntos
   concretos (objeto, campo, valor) y los usuarios afectados, con «Simular quitar…».
3. **Corregir en SAP y volver a extraer**: lo corregido pasa a «resuelto» solo. Si un riesgo se acepta, se
   registra la decisión (excepción con vencimiento, control mitigante o falso positivo) para toda la tarea.

**Búsquedas como en SAP:** en todos los campos de búsqueda, `Z*` = empieza con Z, `*PAGO*` = contiene, `+` = un
carácter, y varios criterios separados por coma (`Z_FI*, Z_MM*`).

**SAP_ALL:** una sola alerta por persona; los riesgos que existen solo por ese perfil se ven dentro de ella.

**Usuarios de emergencia** (Seguimiento › Usuarios de emergencia): los que tienen SAP_ALL a propósito se declaran
con responsable, procedimiento y fecha de revisión. Mientras estén bloqueados no aparecen como pendientes en cada
extracción; si alguno se desbloquea o la declaración vence, vuelve a aparecer como tarea.

**Qué cambió** (Seguimiento › Qué cambió, o el enlace del inicio): entre dos extracciones del mismo sistema, las
alertas nuevas y resueltas y qué cambió en SAP (roles asignados o quitados, perfiles a mano, usuarios, roles
modificados). Se descarga en Excel o PDF.

**Tema de colores y modo oscuro:** cada persona elige el suyo en *Mi cuenta* (Azul, Petróleo, Verde, Bordó, Violeta,
Grafito o Cobre; modo Claro, Oscuro o Automático como Windows). El botón ☾ / ☀ de arriba a la derecha cambia entre
claro y oscuro.

Las fichas de **usuario** y de **rol** y el **simulador** tienen el mismo recuadro: qué hacer con ese usuario,
con ese rol, o si se puede asignar el rol pedido («No asignar Z_FI_PAGOS a USUARIO_TEST» / «Se puede asignar…»),
con una alternativa cuando existe.

## Acceso desde otras PC

Por defecto la aplicación solo atiende a la propia PC (`http://localhost:8000`). Para que entren otras personas:

1. **Una vez**, en PowerShell **como administrador** (abre el puerto 8443 solo para redes privadas de la empresa):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\habilitar_acceso_red.ps1
```

2. Abrir la aplicación en **modo red** (HTTPS; la ventana muestra las direcciones para las otras PC):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run.ps1 -Red
```

3. En cada PC: abrir `https://NOMBRE-DEL-SERVIDOR:8443` (la primera vez el navegador avisa: *Configuración
   avanzada › Continuar*) e **instalar el certificado** desde el enlace de la pantalla de ingreso (o que TI lo
   distribuya por GPO); desde entonces no vuelve a avisar. Cada persona entra con su propio usuario
   (Configuración y acceso › Usuarios de la aplicación).
4. **Para que funcione siempre** (recomendado en un servidor): ver *Funcionamiento continuo*, más abajo.

* **Desde fuera de la oficina: por la VPN de la empresa.** No abra el puerto en el router: la aplicación
  rechaza las direcciones de internet (`network.allowed_networks` en `settings.yaml`) aunque alguien lo abriera.
* **Certificado**: si la empresa tiene su propia CA, configure `network.tls_cert_file` / `tls_key_file`. Si no,
  la aplicación crea una CA local (`data\tls\ca.crt`) **restringida** a este servidor y a direcciones privadas
  (no sirve para suplantar otros sitios). Si cambia la IP, se renueva sola sin reinstalar nada en las PC.
* Tras 5 intentos fallidos, el usuario se bloquea 15 minutos; un administrador puede desbloquearlo o
  restablecer la contraseña. Recuperación por consola: `sapsec reset-password USUARIO`.
* Conviene instalarla en un servidor o VM siempre encendido, no en una notebook.

## Funcionamiento continuo

Para que la aplicación funcione **siempre en modo red**, arranque sola al encender o reiniciar el servidor (aunque
nadie inicie sesión) y se vuelva a abrir sola si se cae o deja de responder: en el servidor, en PowerShell **como
administrador** y con el usuario de Windows que guardó las contraseñas de SAP (cerrar antes la ventana de `run.ps1`):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\iniciar_con_windows.ps1
```

Pide la contraseña de Windows de ese usuario (la guarda el Programador de tareas). Después: `-Estado` para ver si
funciona y sus reinicios automáticos, `-Detener` / `-Iniciar`, `-Quitar`. El estado también está en
Configuración y acceso. Detalle: [docs/10](docs/10_funcionamiento_continuo.md).

## S/4HANA con Fiori y sistemas de desarrollo

* **S/4HANA**: se registra igual que un ECC, **una sola vez** (un S/4 con Fiori embebido es un único sistema: no hace
  falta registrarlo como «S/4» y como «Fiori»). La aplicación detecta el producto (CVERS), traduce los servicios
  Fiori/OData de `S_SERVICE` a su nombre real (USOBHASH) y detecta conflictos hechos **desde apps Fiori** aunque la
  persona no tenga la transacción, usando la SU24 de los servicios del propio sistema. Solo si el Fiori está en un
  servidor front-end aparte (hub, con otro SID) se registra ese servidor como un sistema más.
* **DEV y QA tienen otros controles**: desarrollar o liberar transportes es normal en DEV y no se marca; los conflictos de
  negocio (pagos, compras, ventas) solo aplican en PRD; SAP_ALL, usuarios estándar, RFC y sistema operativo se siguen
  revisando. Cada regla muestra su gravedad en PRD / QA / DEV (página Reglas, `by_environment` en los YAML).
* **Desarrollo vs. producción** (menú Comparar): quién desarrolla en DEV y además tiene permisos críticos en el PRD del
  mismo landscape. Definir el **landscape** de cada sistema en Conexiones SAP.

Detalle: [docs/07](docs/07_s4hana_fiori_y_desarrollo.md).

## Varios sistemas (p. ej. 4 PRD + 4 DEV)

* Cada sistema se registra con un **nombre propio** ("PRD Uruguay", "DEV Argentina"…), su SID, mandante y
  ambiente. El SID puede repetirse entre landscapes distintos: lo que los distingue es el nombre y la
  **huella** (SID + host de base de datos) que se registra en la primera extracción. Si una conexión apunta
  por error a otro sistema, la extracción se cancela.
* **Todos los sistemas** muestra un renglón por sistema con su último snapshot, usuarios con riesgo crítico/alto,
  conflictos SoD, SAP_ALL y la antigüedad de los datos. "Extraer todos los PRD" los procesa de a uno.
* El selector superior elige el **sistema**; siempre se trabaja con su último snapshot. Los anteriores están en
  el historial de cada sistema (y se conservan los últimos 5; `snapshots_to_keep` en `settings.yaml`).

### Extracción nocturna programada

Las horas se configuran en la aplicación (**Administración › Extracciones programadas**). Con el *funcionamiento
continuo* las ejecuta la propia aplicación, también después de reiniciar el servidor. Sin él, para que corran aunque
la aplicación esté cerrada: `scripts\instalar_tarea_programada.ps1` (una vez, con el mismo usuario de Windows que
guardó las contraseñas de SAP, ya que el Administrador de credenciales es por usuario).

## Instalación en Windows

Requisitos: Git para Windows, Python 3.11–3.13 de 64 bits y, para conectarse a SAP, el SAP NW RFC SDK 7.50 (ver docs/02).

```powershell
git clone https://github.com/maxilasal/sap-security-intelligence-access-risk-analyzer.git C:\sapsec\sap-security-analyzer
```

```powershell
cd C:\sapsec\sap-security-analyzer
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

```powershell
.\.venv\Scripts\python.exe -m pytest
```

```powershell
.\.venv\Scripts\sapsec.exe demo
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run.ps1
```

Abrir <http://127.0.0.1:8000> e ingresar con el usuario `admin` creado por `demo`.
El sistema `DMO` es **ficticio** y la interfaz lo marca como "DATOS DE PRUEBA".

### Actualizar

```powershell
powershell -ExecutionPolicy Bypass -File scripts\actualizar.ps1
```

Trae la última versión, aplica las migraciones de la base y conserva `data\` y `config\settings.yaml`. Para pasar a Git
una instalación que se descargó como zip, ver [docs/08](docs/08_versionado_y_actualizacion.md).

### Conectar un sistema SAP real

1. Crear el usuario técnico y el rol de lectura (docs/03).
2. `sapsec rfc-selftest` (docs/02).
3. En **Conexiones SAP**: registrar SID, mandante, ambiente (DEV/QA/PRD), backend `nwrfc`, servidor y usuario; la contraseña se guarda en Windows Credential Manager. Para PRD se recomienda SNC.
4. **Probar conectividad y permisos** → revisar el diagnóstico de funciones y tablas.
5. **Extraer snapshot** → el análisis se ejecuta automáticamente.


### PostgreSQL

```powershell
pip install "sapsec[postgres]"
```

```powershell
$env:SAPSEC_DATABASE_URL = "postgresql+psycopg://sapsec@dbserver/sapsec"
```

## Estado de esta versión

| Probado con un SAP real (ECC 7.31, QAS) | Probado solo con datos ficticios (pruebas automatizadas) |
|---|---|
| Conexión con el SAP NW RFC SDK 7.50, extracción completa (usuarios, roles, perfiles, autorizaciones), análisis y tareas de corrección | Funcionamiento continuo: probado en un Windows real de GitHub Actions (tarea con usuario y contraseña, caída y recuperación, detener e iniciar), salvo el reinicio del servidor (se verifica el disparador); modo red con HTTPS (verificado con un servidor real y OpenSSL, no en la red de su empresa), script de firewall (no ejecutado en Windows aquí), recomendaciones por pantalla, simulador, reportes; S/4HANA: detección de producto, servicios Fiori/OData y conflictos vía Fiori (SU24 TYPE HT), controles por ambiente y Desarrollo vs. producción; usuarios de emergencia declarados y «Qué cambió» entre dos extracciones |

Las reglas incluidas están en estado **ejemplo**: no son la matriz oficial de SAP GRC y deben
validarse y aprobarse antes de usarse como criterio de auditoría.

## Comandos

| Comando | Descripción |
|---|---|
| `sapsec init-db` | Crea las tablas |
| `sapsec create-user USUARIO ROL` | Usuario de la aplicación (administrador / auditor / consultor) |
| `sapsec demo` | Sistema ficticio + snapshot de prueba |
| `sapsec list-connections` | Conexiones registradas |
| `sapsec test-connection ID` | Diagnóstico de conectividad y permisos |
| `sapsec extract ID` | Extracción (solo lectura) + análisis |
| `sapsec analyze SNAPSHOT` | Recalcula hallazgos |
| `sapsec rfc-selftest` | Prueba del backend RFC con variables `SAPSEC_RFC_*` |
| `sapsec generate-key` | Clave para `SAPSEC_MASTER_KEY` (almacén cifrado) |
| `sapsec serve` | Interfaz web solo para esta PC (`http://localhost:8000`) |
| `sapsec serve --red` | Interfaz web para otras PC de la empresa / VPN (HTTPS, puerto 8443) |
| `sapsec servicio --red` | La interfaz web vigilada: la reabre si se cae o deja de responder (lo usa `iniciar_con_windows.ps1`) |
| `sapsec estado-servicio` | Si el servicio está funcionando, desde cuándo y sus reinicios automáticos |
| `sapsec verificar-credenciales` | Qué conexiones SAP tienen la contraseña guardada para este usuario de Windows |
| `sapsec reset-password USUARIO` | Contraseña nueva para un usuario de la aplicación (y lo desbloquea) |
| `sapsec extract-all [--ambiente PRD]` | Extrae todos los sistemas activos, uno por vez |
| `sapsec run-due` | Ejecuta las extracciones programadas vencidas |

## Variables de entorno

| Variable | Uso |
|---|---|
| `SAPSEC_SESSION_SECRET` | Clave de sesiones web (obligatoria en servidor) |
| `SAPSEC_DATABASE_URL` | Base de datos |
| `SAPSEC_CONFIG` | Ruta de `settings.yaml` |
| `SAPSEC_MASTER_KEY` | Clave Fernet si `credential_store: encrypted_file` |
| `SAPNWRFC_HOME` | Carpeta del SAP NW RFC SDK |
