# Conectividad RFC: instalación y verificación en Windows

## 1. SAP NW RFC SDK 7.50

1. Descargar el **último patch level** del SAP NW RFC SDK 7.50 para *Windows on x64 64bit* desde el SAP Software Download Center (requiere S-user). Ver SAP Note 2573790.
2. Descomprimir en `C:\nwrfcsdk` (debe existir `C:\nwrfcsdk\lib\sapnwrfc.dll`).
3. Instalar los *Microsoft Visual C++ Redistributables* indicados en la nota.
4. Variables de entorno (usuario o sistema):
   ```powershell
   [Environment]::SetEnvironmentVariable("SAPNWRFC_HOME", "C:\nwrfcsdk", "User")
   [Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\nwrfcsdk\lib", "User")
   ```
5. Revisar periódicamente las notas de seguridad del SDK (p. ej. CVE-2026-0507) y actualizar.

## 2. Prueba mínima (`rfc-selftest`)

```powershell
$env:SAPSEC_RFC_ASHOST="sapqa4.empresa.local"; $env:SAPSEC_RFC_SYSNR="00"
$env:SAPSEC_RFC_CLIENT="100"; $env:SAPSEC_RFC_USER="SECX_READ"
sapsec rfc-selftest
```

Debe mostrar la versión del SDK, `RFC_PING OK`, los datos de `RFC_SYSTEM_INFO` y tres filas de
`TACTT`. Si funciona, registre la conexión en la UI y use **Probar conectividad y permisos**.

## 3. Errores frecuentes

| Síntoma | Causa probable |
|---|---|
| `No se encontró el SAP NW RFC SDK` | `SAPNWRFC_HOME`/PATH incorrectos o DLL de 32 bits |
| `RFC_LOGON_FAILURE` | Credenciales, usuario bloqueado, mandante incorrecto |
| `RFC_COMMUNICATION_FAILURE` | Host/instancia, firewall (puerto 33NN / 32NN), SAProuter |
| `NOT_AUTHORIZED` en una tabla | Falta `S_TABU_NAM` para esa tabla (el diagnóstico la lista) |
| `Function module ... not found` / sin autorización | Falta `S_RFC` o UCON bloquea el módulo |
| SID no coincide | La conexión apunta a otro sistema: se cancela la extracción |

## 4. Backend alternativo

`backend = pyrfc` usa PyRFC 3.3.1 (archivado por SAP). Instalar solo si la organización ya lo
tiene homologado: `pip install "sapsec[pyrfc]"`.
