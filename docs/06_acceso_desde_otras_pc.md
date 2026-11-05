# Acceso desde otras PC (red de la empresa y VPN)

Por defecto la aplicación escucha solo en `127.0.0.1:8000`: nadie más puede entrar. El **modo red** la publica
para la red interna con HTTPS. Desde fuera de la oficina se entra **por la VPN corporativa**.

## Puesta en marcha (una vez)

| Paso | Dónde | Comando / acción |
|---|---|---|
| 1. Abrir el puerto 8443 solo a redes privadas | Servidor, PowerShell **como administrador** | `powershell -ExecutionPolicy Bypass -File scripts\habilitar_acceso_red.ps1` |
| 2. Iniciar en modo red | Servidor | `powershell -ExecutionPolicy Bypass -File scripts\run.ps1 -Red` |
| 3. Que quede siempre disponible (opcional) | Servidor, mismo usuario que guardó las contraseñas SAP | `powershell -ExecutionPolicy Bypass -File scripts\iniciar_con_windows.ps1` |
| 4. Instalar el certificado (una vez por PC) | Cada PC, o por GPO | Pantalla de ingreso › «Instalar el certificado» |
| 5. Crear un usuario por persona | Aplicación › Configuración y acceso | consultor (solo consulta), auditor, administrador |

La ventana del servidor muestra las direcciones a usar (`https://NOMBRE:8443`, `https://IP:8443`).

## Qué protege

* **Redes permitidas** (`network.allowed_networks`, por defecto 10/8, 172.16/12, 192.168/16 y privadas IPv6):
  cualquier otra dirección recibe «Acceso no permitido» aunque el puerto quedara abierto por error.
  El propio servidor siempre puede entrar. Para restringir más, liste solo las subredes de la oficina y de la VPN.
* **HTTPS siempre en modo red.** Sin certificado de la empresa, la aplicación crea una CA local
  (`data\tls\ca.crt`) con *restricciones de nombre* (solo este servidor, su dominio y direcciones privadas): si
  alguien robara su clave, no serviría para suplantar otros sitios. Si cambia la IP del servidor, el certificado
  se renueva solo y las PC no tienen que reinstalar nada. Con certificado corporativo: `network.tls_cert_file` y
  `network.tls_key_file` (PEM).
* **Cookie de sesión** `Secure`, `HttpOnly`, `SameSite=Strict`; formularios con token CSRF.
* **Bloqueo** de 15 minutos tras 5 intentos fallidos (`security.lockout_minutes`, `max_failed_logins`).
  El administrador puede desbloquear, restablecer contraseñas y desactivar usuarios; recuperación por consola:
  `sapsec reset-password USUARIO`.
* **Auditoría**: ingresos (con IP de origen), consultas, exportaciones y cambios de usuarios.

## Desde fuera de la oficina

* **Recomendado: VPN corporativa.** La PC remota recibe una IP privada y entra igual que en la oficina.
* **No** reenviar el puerto en el router ni publicarlo en internet.
* Si TI necesitara publicarla sin VPN: detrás de un proxy inverso o servicio de publicación con inicio de sesión
  corporativo y doble factor; el conector interno entra desde una IP privada (ya permitida).

## Si otra PC no llega

1. ¿El servidor está en modo red? La ventana debe decir «Desde otras PC: https://…» (o la tarea «SAP Security
   Analyzer - servidor web» en el Programador de tareas, si se inicia con Windows).
2. ¿Se ejecutó `habilitar_acceso_red.ps1`? El script avisa si la red de Windows está marcada como **Pública**
   (bloquea conexiones entrantes) o si hay reglas que bloquean a Python.
3. Desde la otra PC: `Test-NetConnection NOMBRE-DEL-SERVIDOR -Port 8443` debe dar `TcpTestSucceeded : True`.
4. «Acceso no permitido desde esta red»: la IP de esa PC no está en `network.allowed_networks`.
5. Advertencia de certificado: instalar el certificado (pantalla de ingreso › «Instalar el certificado»), o
   usar el nombre que figura en el certificado (no un alias distinto; los alias van en `network.extra_names`).
