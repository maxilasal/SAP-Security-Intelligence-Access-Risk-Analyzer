# Funcionamiento continuo (la aplicación siempre activa)

Con esto la aplicación queda **siempre disponible en modo red** en el servidor:

* **arranca sola al encender o reiniciar el servidor**, aunque nadie inicie sesión;
* **si se cae** (el proceso termina), se vuelve a abrir en segundos;
* **si deja de responder** (cuatro comprobaciones seguidas sin respuesta, unos 2 minutos), se cierra y se vuelve a abrir;
* **cada 5 minutos Windows comprueba** que el vigilante siga activo y, si no, lo vuelve a iniciar.

## Instalar (una vez)

En el servidor, en PowerShell **como administrador** (clic derecho › Ejecutar como administrador), en la carpeta de
la aplicación, con el **mismo usuario de Windows que guardó las contraseñas de SAP**:

1. Cerrar la ventana de la aplicación si está abierta con `run.ps1` (Ctrl+C).
2. Ejecutar:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\iniciar_con_windows.ps1
```

3. Ingresar la **contraseña de Windows** de ese usuario cuando la pida. La guarda el Programador de tareas de Windows
   (no esta aplicación): es lo que permite abrirla sin que nadie haya iniciado sesión.

El script verifica antes que ese usuario tenga guardadas las contraseñas de SAP (el almacén de credenciales de
Windows es por usuario), instala la tarea, la inicia y espera a que la aplicación responda.

| Comando (agregar al anterior) | Qué hace |
|---|---|
| `-Estado` | Si está funcionando, desde cuándo, reinicios automáticos y su motivo |
| `-Detener` | La cierra y no vuelve a abrirse (ni al reiniciar el servidor) hasta `-Iniciar` |
| `-Iniciar` | La vuelve a habilitar y la abre |
| `-Quitar` | Deja de funcionar como servicio (se puede abrir a mano con `run.ps1 -Red`) |
| `-Usuario DOMINIO\usuario` | Ejecutarla con otro usuario de Windows (debe tener las contraseñas de SAP) |
| `-SoloAlIniciarSesion` | PC personal: se abre al iniciar sesión, sin pedir contraseña |

El estado también se ve en la aplicación: **Configuración y acceso › Funcionamiento continuo**.

## Cómo funciona

| Pieza | Qué hace |
|---|---|
| Tarea de Windows «SAP Security Analyzer - servidor web» | Se inicia al encender el servidor (con 1 minuto de espera para que la red esté lista) y cada 5 minutos; si el vigilante ya está corriendo, Windows no abre otro. Sin límite de tiempo de ejecución. |
| `sapsec servicio --red` (el vigilante) | Abre la aplicación en modo red y la comprueba cada 30 segundos (`/api/v1/salud`). Si se cae, la reabre (espera 5 s, 15 s, 30 s, 1 min, 2 min y 5 min si falla seguido; vuelve al mínimo cuando funcionó 10 minutos). Si no responde, la cierra y la reabre. |
| Una sola copia | Un bloqueo de archivo impide dos vigilantes en la misma instalación. Si la aplicación ya está abierta en una ventana (`run.ps1 -Red`), el vigilante no abre otra: la vigila y, si se cierra, abre la suya. |
| Sin procesos huérfanos | En Windows la aplicación queda asociada al vigilante (*Job Object*): si el vigilante se detiene (por ejemplo, al actualizar), la aplicación se cierra con él y libera el puerto. |
| Registro | `data\logs\servicio.log` (arranques, caídas, reinicios y su motivo) y `data\servicio.json` (estado actual). |

El vigilante no toca SAP ni la base de datos: solo vigila el proceso local de la aplicación.

**Extracciones programadas:** con la aplicación siempre activa, las ejecuta la propia aplicación a la hora
configurada (Administración › Extracciones programadas), también después de un reinicio del servidor. La tarea de
`instalar_tarea_programada.ps1` ya no hace falta; si está instalada, puede quedar: las extracciones no se duplican.

## Actualizar

`scripts\actualizar.ps1` detecta el servicio: verifica que no haya una extracción en curso, lo detiene (sin que la
comprobación de 5 minutos lo vuelva a abrir a mitad de camino), actualiza y lo vuelve a iniciar, también si algo
falló. Ejecutarlo en PowerShell **como administrador**.

## Si algo no anda

| Síntoma | Causa probable y solución |
|---|---|
| «Windows rechazó la contraseña» | Contraseña de Windows mal ingresada: volver a ejecutar el script. |
| Dejó de abrir después de cambiar la contraseña de Windows | El Programador de tareas guarda la anterior: volver a ejecutar el script con la nueva. Conviene una cuenta de servicio con contraseña que no venza. |
| Resultado de la tarea `0x80070569` | La cuenta no tiene el permiso «Iniciar sesión como proceso por lotes»: lo asigna TI (directiva local o de dominio). |
| La aplicación abre pero las extracciones fallan por contraseña | Las contraseñas de SAP están guardadas con otro usuario de Windows: guardarlas con el usuario del servicio (Conexiones SAP) o instalar con `-Usuario`. |
| Se reinicia seguido | Ver el motivo en `data\logs\servicio.log` y el error de la aplicación en `data\logs\sapsec.log`. |

## Qué está probado

* En Windows real (GitHub Actions, `windows-latest`, en cada cambio): instalación de la tarea con usuario y
  contraseña, respuesta en modo red (HTTPS), caída forzada y recuperación automática, `-Estado`, `-Detener` (sin
  procesos huérfanos), `-Iniciar` y `-Quitar`.
* Con pruebas automáticas en Windows y Linux: reapertura tras una caída, reinicio cuando deja de responder, una sola
  copia y cierre limpio.
* **El reinicio del servidor no se puede probar en GitHub Actions**: se verifica que la tarea tenga el disparador
  «al iniciar el sistema» y el inicio sin sesión. Conviene comprobarlo una vez en el servidor real: reiniciarlo y,
  sin iniciar sesión, entrar desde otra PC.
