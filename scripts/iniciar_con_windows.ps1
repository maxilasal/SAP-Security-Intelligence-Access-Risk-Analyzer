# Hace que la aplicación se abra sola (sin ventana) en MODO RED cada vez que se inicia Windows,
# para que las otras PC puedan entrar aunque nadie haya abierto run.ps1.
#
# Ejecutar con el MISMO usuario de Windows que guardó las contraseñas de SAP:
#   powershell -ExecutionPolicy Bypass -File scripts\iniciar_con_windows.ps1
#       -> se abre al iniciar sesión ese usuario
#   powershell -ExecutionPolicy Bypass -File scripts\iniciar_con_windows.ps1 -AunqueNoHayaSesion
#       -> se abre al encender la PC, sin iniciar sesión (como administrador; pide la contraseña de Windows)
#   -SoloEstaPC   sin modo red (solo esta PC)
#   -Detener      cierra la aplicación que está corriendo en segundo plano
#   -Quitar       deja de abrirse sola
param([switch]$AunqueNoHayaSesion, [switch]$SoloEstaPC, [switch]$Detener, [switch]$Quitar)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$nombre = "SAP Security Analyzer - servidor web"

if ($Detener) {
  Stop-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue
  Write-Host "Aplicación detenida (volverá a abrirse sola en el próximo inicio)."
  exit 0
}
Unregister-ScheduledTask -TaskName $nombre -Confirm:$false -ErrorAction SilentlyContinue
if ($Quitar) { Write-Host "Listo: la aplicación ya no se abre sola."; exit 0 }

$pythonw = Join-Path $root ".venv\Scripts\pythonw.exe"
if (-not (Test-Path $pythonw)) { throw "No se encontró $pythonw. Ejecute primero scripts\install.ps1" }
$argumentos = "-m sapsec.cli serve"
if (-not $SoloEstaPC) { $argumentos += " --red" }
$accion = New-ScheduledTaskAction -Execute $pythonw -Argument $argumentos -WorkingDirectory $root
$config = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 `
  -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$user = "$env:USERDOMAIN\$env:USERNAME"
if ($AunqueNoHayaSesion) {
  $cred = Get-Credential -UserName $user -Message "Contraseña de Windows de $user (la guarda Windows para iniciar la aplicación)"
  Register-ScheduledTask -TaskName $nombre -Action $accion -Trigger (New-ScheduledTaskTrigger -AtStartup) `
    -Settings $config -User $user -Password $cred.GetNetworkCredential().Password -RunLevel Limited | Out-Null
} else {
  $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName $nombre -Action $accion -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $user) `
    -Settings $config -Principal $principal | Out-Null
}
Start-ScheduledTask -TaskName $nombre
Write-Host "Listo: la aplicación quedó abierta en segundo plano y se abrirá sola en cada inicio." -ForegroundColor Green
if ($SoloEstaPC) { Write-Host "  Dirección: http://localhost:8000" } else {
  Write-Host "  En esta PC: https://localhost:8443   ·   Otras PC: https://$($env:COMPUTERNAME.ToLower()):8443"
}
Write-Host "  Registro: data\logs\sapsec.log   ·   Detener: scripts\iniciar_con_windows.ps1 -Detener"
