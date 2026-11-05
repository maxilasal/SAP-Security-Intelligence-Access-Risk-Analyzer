# Usuarios de emergencia y «Qué cambió»

## Usuarios de emergencia declarados

Un **usuario de emergencia** tiene permisos amplios **a propósito** (normalmente SAP_ALL): se mantiene bloqueado y se
habilita solo ante una emergencia, con aprobación; después se revisa lo que se hizo con él. Si no se declara, la
aplicación lo trata como a cualquier usuario con SAP_ALL y lo muestra como pendiente en cada extracción.

**Cómo se declara** (rol administrador o auditor): *Seguimiento › Usuarios de emergencia*, o el botón «Es de
emergencia» en la tarea «Quitar el perfil SAP_ALL», o «Declarar como usuario de emergencia» en la ficha del usuario.
Se indica:

| Dato | Para qué |
|---|---|
| Sistema | Uno en particular o «todos los sistemas» (si el usuario existe con el mismo nombre en todos). La declaración de un sistema tiene prioridad sobre la general. |
| Usuario SAP | Nombre exacto (sin comodines). |
| Responsable | Quién aprueba que se use. |
| Procedimiento | Cuándo se desbloquea, quién lo aprueba, por cuánto tiempo y cómo se revisa lo que se hizo. |
| Revisar antes de | Fecha en que vence la declaración (como máximo un año): obliga a confirmar periódicamente que sigue haciendo falta. |

**Qué cambia en el análisis** (se aplica en cada extracción, sin intervención):

| Estado en SAP según la extracción | Declaración | Resultado |
|---|---|---|
| Bloqueado (USR02-UFLAG ≠ 0) o fuera de su validez (GLTGV/GLTGB) | vigente | Sus alertas quedan **controladas** (estado «mitigado», fijado automáticamente): no son pendientes. |
| Desbloqueado y dentro de su validez | vigente | Tarea pendiente: **«Bloquear … si no hay una emergencia en curso»**, con el responsable a consultar. |
| Cualquiera | vencida | Tarea pendiente: **renovar o quitar la declaración**. |
| El usuario no existe en ese sistema | — | Se informa en la página; no afecta nada. |

* Todas las alertas del usuario (SAP_ALL y lo que tenga por roles) van a una sola tarea, «Mantener bloqueados los
  usuarios de emergencia», en lugar de «Quitar el perfil SAP_ALL».
* **Las decisiones de una persona prevalecen**: si una alerta ya tenía una excepción, un falso positivo o un control
  mitigante registrado, no se toca. Solo se ajustan las alertas pendientes (abiertas o en revisión).
* Al **quitar** la declaración, sus alertas vuelven a la tarea que corresponda (por ejemplo, «Quitar el perfil SAP_ALL»).
* La aplicación **no bloquea ni desbloquea nada en SAP**: solo lee el estado del usuario en cada extracción.
* Cada declaración, renovación o baja queda en la auditoría de la aplicación.
* Si se usó el usuario, la recomendación sugiere revisar lo hecho en el registro de auditoría de seguridad de SAP
  (SM20 o RSAU_READ_LOG, si está activo en el sistema).

## Qué cambió entre dos fechas

*Seguimiento › Qué cambió* (o el enlace «Ver qué cambió» del inicio, o «Qué cambió hasta el último» en el historial
del sistema). Se eligen dos extracciones del **mismo sistema y mandante**; por defecto, la última y la anterior.

| Sección | Cómo se calcula |
|---|---|
| Alertas nuevas | Estaban en la extracción posterior y no en la anterior (por su huella: regla + usuario o rol). Si antes iban dentro de la alerta de SAP_ALL, se aclara. |
| Alertas resueltas | Estaban en la anterior y ya no están en SAP. Las que pasaron a ir dentro de una alerta de SAP_ALL no se cuentan como resueltas. |
| Roles asignados / quitados | Diferencia de AGR_USERS (usuario + rol). Las asignaciones heredadas de roles compuestos se cuentan aparte; los roles de usuarios borrados no se repiten. |
| Perfiles asignados a mano | Diferencia de UST04 sin los perfiles generados de roles (AGR_1016). SAP_ALL y SAP_NEW se resaltan. |
| Usuarios | Nuevos (con fecha y creador de USR02), borrados, bloqueados, desbloqueados y con la validez cambiada. |
| Roles | Nuevos, borrados y modificados: cambió la fecha o el usuario de última modificación (AGR_DEFINE) o la cantidad de valores de autorización (AGR_1251). «Ver diferencias» abre la comparación detallada del rol. |
| Decisiones en la aplicación | Excepciones, controles mitigantes y declaraciones de emergencia registradas entre las dos fechas (auditoría propia). |

**Límites:** se reconstruye comparando dos extracciones; un cambio hecho y deshecho entre ambas no se ve, y no se
sabe **quién** asignó un rol. Para eso están los documentos de modificación de SAP: SUIM › Documentos de
modificación (usuarios: RSUSR100N; roles: RSSCD100_PFCG). Solo se pueden comparar las extracciones que se conservan
(las últimas 5 de cada sistema por defecto; `snapshots_to_keep` en `settings.yaml`).

La página se descarga en **Excel o PDF** (evidencia de la revisión periódica de cambios).
