# Instala (o quita) la tarea del Programador de tareas de Windows que ejecuta las
# extracciones programadas aunque la aplicación esté cerrada.
#
# Las HORAS se configuran en la aplicación (Administración > Extracciones programadas).
# Esta tarea solo "despierta" cada 30 minutos y ejecuta lo que esté vencido.
#
# Uso (en PowerShell, en la carpeta de la aplicación, con el MISMO usuario de Windows
# que guardó las contraseñas de SAP):
#   powershell -ExecutionPolicy Bypass -File scripts\instalar_tarea_programada.ps1
#       -> funciona mientras la sesión de Windows esté iniciada (aunque esté bloqueada)
#   powershell -ExecutionPolicy Bypass -File scripts\instalar_tarea_programada.ps1 -AunqueNoHayaSesion
#       -> funciona aunque se cierre la sesión (pide la contraseña de Windows; la guarda Windows)
#   powershell -ExecutionPolicy Bypass -File scripts\instalar_tarea_programada.ps1 -Quitar
param([switch]$AunqueNoHayaSesion, [switch]$Quitar)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$name = "SAP Security Analyzer - extracciones programadas"

if ($Quitar) {
  Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "Tarea eliminada."
  return
}

# pythonw = sin ventana de consola cada 30 minutos; el registro queda en data\logs\sapsec.log
$pythonw = Join-Path $root ".venv\Scripts\pythonw.exe"
if (-not (Test-Path $pythonw)) { throw "No se encontró $pythonw. Ejecute primero scripts\install.ps1" }

$action = New-ScheduledTaskAction -Execute $pythonw -Argument "-m sapsec.cli run-due" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -Daily -At "00:05"
$repeat = New-ScheduledTaskTrigger -Once -At "00:05" -RepetitionInterval (New-TimeSpan -Minutes 30) `
          -RepetitionDuration (New-TimeSpan -Hours 23 -Minutes 55)
$trigger.Repetition = $repeat.Repetition
$settings = New-ScheduledTaskSettingsSet -WakeToRun -StartWhenAvailable -MultipleInstances IgnoreNew `
            -ExecutionTimeLimit (New-TimeSpan -Hours 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$user = "$env:USERDOMAIN\$env:USERNAME"

if ($AunqueNoHayaSesion) {
  $cred = Get-Credential -UserName $user -Message "Contraseña de Windows de $user (la guarda el Programador de tareas)"
  Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings `
    -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Limited -Force | Out-Null
} else {
  $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null
}
Write-Host "Tarea instalada para ${user}: cada 30 minutos revisa si hay extracciones programadas pendientes."
Write-Host "Configure las horas en la aplicación: Administración > Extracciones programadas."
