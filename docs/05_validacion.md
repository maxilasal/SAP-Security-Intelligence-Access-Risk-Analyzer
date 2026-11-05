# Pruebas y validación de resultados

## Pruebas automatizadas (sin SAP)

`python -m pytest` ejecuta 72 pruebas sobre un sistema **ficticio** (`scripts/build_demo_fixture.py`):

| Archivo | Cubre |
|---|---|
| `test_values.py` | `*`, prefijos, rangos, `' '`, `$VAR`, subsunción, **no mezclar instancias**, DUMMY |
| `test_connectivity.py` | Campos de contraseña y tablas fuera de lista rechazados, funciones de escritura bloqueadas, descarte de hashes de BAPI, OPTIONS ≤72, truncamiento y división de lotes, parsing de ancho fijo |
| `test_extraction.py` | Snapshot completo, hashes nunca almacenados, tabla sin autorización ⇒ incompleto, fallback de USR02, modo BAPI, SID incorrecto ⇒ abortado, validación cruzada con BAPI detecta diferencias |
| `test_effective.py` | Compuestos, perfiles directos (SAP_ALL), vencidos/futuros, perfil residual, bloqueados, perfil no generado/desactualizado, org. sin mantener, derivados/padre, chequeo de inicio TSTCA |
| `test_rules_engines.py` | SAP_ALL, SAP_NEW, equivalencia a SAP_ALL, reglas por ambiente, RFC técnico, inactividad, SoD entre roles/intra-rol/perfil directo, restricción organizativa aparente, solapamiento org., compuestos, riesgo actual vs potencial, mitigación, calidad de rol |
| `test_simulator.py` | Conflicto nuevo (NO RECOMENDADO) con roles y evidencia, preexistente no reportado como nuevo, sin riesgos, quitar, sustituir, múltiples roles, compuesto, valores hipotéticos, rol no generado, rol inexistente, snapshot incompleto/antiguo, alternativas, inmutabilidad del snapshot |
| `test_web.py` | Login, CSRF, todas las pantallas, simulador y reportes (PDF/XLSX/HTML/CSV), API, consultor de solo lectura, excepciones con justificación y auditoría, cabeceras de seguridad |

## Validación contra SAP (procedimiento para el primer sistema real)

Realizar en QA con un conjunto de 10–20 usuarios y roles representativos:

| Resultado de la herramienta | Comparar con | Criterio |
|---|---|---|
| Usuarios, tipo, bloqueo, validez | SU01 / SUIM `RSUSR200` | Igualdad exacta |
| Roles y validez por usuario | SU01 pestaña Roles / SUIM `RSUSR070` | Igualdad exacta (incl. heredados de compuestos) |
| Perfiles por usuario | SU01 pestaña Perfiles | Igualdad exacta |
| Autorizaciones efectivas | SU01 → "Autorizaciones" / SUIM `RSUSR002` por objeto/valor | Mismo conjunto de usuarios para 10 consultas de objeto/campo/valor |
| Búsqueda inversa (p. ej. S_USER_AGR 02) | SUIM `RSUSR002` con los mismos valores | Mismos usuarios |
| Transacciones ejecutables | SUIM "usuarios por transacción" (`RSUSR010` **[verificar variante]**) | Mismos usuarios; diferencias explicadas por TSTCA |
| Perfil desactualizado | PFCG (semáforo de la pestaña Autorizaciones) | Coincidencia |
| Comparación pendiente | PFUD / SU01 | Coincidencia |
| Combinaciones críticas | SUIM `RSUSR008_009_NEW` con las mismas reglas cargadas | Mismos usuarios por regla |
| Usuarios estándar | `RSUSR003` | Coincidencia de estado |
| Capacidad potencial de una acción concreta | STAUTHTRACE / SU53 en una prueba controlada en QA | Documentar resultado; elevar a "Confirmado en SAP" manualmente |

Registrar cada comparación (fecha, sistema/mandante, snapshot, regla, resultado) como evidencia
de calidad. Mientras no se complete, los resultados deben tratarse como **estimados**.

## Resultados confirmados vs estimados

* **Confirmado** (por datos): asignaciones, perfiles, valores de autorización, desajustes de perfil.
* **Estimado/potencial**: ejecución real de transacciones y operaciones, efectividad de restricciones organizativas, alternativas de rol.
* **Incompleto**: cualquier análisis sobre un snapshot con estado `incompleto` (se indica en UI y reportes).
