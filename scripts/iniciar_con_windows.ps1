# Deja la aplicación FUNCIONANDO SIEMPRE en modo red, como un servicio:
#   * arranca sola al encender o reiniciar el servidor, aunque nadie inicie sesión;
#   * si se cae o deja de responder, se vuelve a abrir sola (la vigila "sapsec servicio");
#   * además, cada 5 minutos Windows comprueba que el vigilante siga activo y, si no, lo vuelve a iniciar.
#
# Ejecutar en PowerShell COMO ADMINISTRADOR (clic derecho > Ejecutar como administrador), en la carpeta de la
# aplicación y con el MISMO usuario de Windows que guardó las contraseñas de SAP. Pide la contraseña de Windows
# de ese usuario: la guarda el Programador de tareas de Windows (no esta aplicación) para poder abrirla sin que
# nadie inicie sesión. Si esa contraseña cambia, volver a ejecutar este script.
#
#   powershell -ExecutionPolicy Bypass -File scripts\iniciar_con_windows.ps1            -> instalar o actualizar
#   powershell -ExecutionPolicy Bypass -File scripts\iniciar_con_windows.ps1 -Estado    -> ¿está funcionando?
#   ... -Detener               la cierra y no vuelve a abrirse (ni al reiniciar) hasta usar -Iniciar
#   ... -Iniciar               la vuelve a habilitar y la abre
#   ... -Quitar                deja de funcionar como servicio (se puede abrir a mano con run.ps1)
#   ... -SoloAlIniciarSesion   en una PC personal: se abre al iniciar sesión, sin pedir contraseña
#   ... -SoloEstaPC            sin modo red (solo esta PC, http://localhost:8000)
#   ... -Usuario DOMINIO\usuario   ejecutarla con otro usuario de Windows (debe tener las contraseñas de SAP)
param(
  [switch]$Estado, [switch]$Detener, [switch]$Iniciar, [switch]$Quitar,
  [switch]$SoloAlIniciarSesion, [switch]$SoloEstaPC,
  [switch]$AunqueNoHayaSesion,   # versiones anteriores: ahora es el comportamiento normal
  [string]$Usuario = "",
  [System.Management.Automation.PSCredential]$Credencial = $null   # para instalar sin preguntar (pruebas)
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$nombre = "SAP Security Analyzer - servidor web"
$pythonw = Join-Path $root ".venv\Scripts\pythonw.exe"
$python = Join-Path $root ".venv\Scripts\python.exe"

function Invoke-Sapsec {
  # Programas externos: lo que escriban en stderr (avisos, registro) no debe cortar el script en PowerShell 5.1.
  $anterior = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try { & $python -m sapsec.cli @args | Out-Host } finally { $ErrorActionPreference = $anterior }
  return $LASTEXITCODE
}

function Es-Administrador {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Puerto-Abierto([int]$puerto) {
  $c = New-Object Net.Sockets.TcpClient
  try { $c.Connect("127.0.0.1", $puerto); return $true } catch { return $false } finally { $c.Close() }
}

function Esperar-Puerto([int]$puerto, [int]$segundos, [bool]$abierto = $true) {
  $fin = (Get-Date).AddSeconds($segundos)
  while ((Get-Date) -lt $fin) {
    if ((Puerto-Abierto $puerto) -eq $abierto) { return $true }
    Start-Sleep -Seconds 2
  }
  return $false
}

function Puerto-Aplicacion {
  if ($SoloEstaPC) { return 8000 }
  $anterior = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try { $p = & $python -c "from sapsec.config import get_settings; print(get_settings().network.port)" 2>$null }
  finally { $ErrorActionPreference = $anterior }
  if ("$p".Trim() -match '^\d+$') { return [int]"$p".Trim() }
  return 8443
}

function Mostrar-Estado {
  $t = Get-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue
  if (-not $t) {
    Write-Host "No está instalada como servicio. Para instalarla: scripts\iniciar_con_windows.ps1 (como administrador)." -ForegroundColor Yellow
    return
  }
  $i = $t | Get-ScheduledTaskInfo
  $estadoTarea = @{ "Running" = "en ejecución"; "Ready" = "lista (se inicia en la próxima comprobación)";
                    "Disabled" = "DETENIDA (-Detener): no se inicia hasta usar -Iniciar" }[[string]$t.State]
  if (-not $estadoTarea) { $estadoTarea = [string]$t.State }
  $disparadores = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ", "
  Write-Host "Tarea de Windows «$nombre»: $estadoTarea"
  Write-Host ("  Usuario: {0} · inicio sin sesión: {1} · último inicio: {2} · resultado: 0x{3:X}" -f `
    $t.Principal.UserId, ($(if ($t.Principal.LogonType -eq "Password") { "sí" } else { "no" })), $i.LastRunTime, $i.LastTaskResult)
  if ($disparadores -match "Boot") { Write-Host "  Se inicia al encender el servidor y se comprueba cada 5 minutos." }
  $null = Invoke-Sapsec estado-servicio
}

if ($Estado) { Mostrar-Estado; exit 0 }

if ($Detener -or $Iniciar -or $Quitar) {
  $t = Get-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue
  if (-not $t) { Write-Host "No está instalada como servicio: no hay nada que $(if ($Quitar) {'quitar'} elseif ($Iniciar) {'iniciar'} else {'detener'})."; exit 0 }
  if ($Detener -or $Quitar) {
    if ($Detener) { Disable-ScheduledTask -TaskName $nombre | Out-Null }   # que la comprobación de 5 minutos no la reabra
    Stop-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue
    if ($Quitar) {
      Unregister-ScheduledTask -TaskName $nombre -Confirm:$false
      Write-Host "Listo: ya no funciona como servicio. Para abrirla a mano: scripts\run.ps1 -Red" -ForegroundColor Green
    } else {
      Write-Host "Detenida. No vuelve a abrirse (ni al reiniciar el servidor) hasta: scripts\iniciar_con_windows.ps1 -Iniciar" -ForegroundColor Green
    }
    exit 0
  }
  Enable-ScheduledTask -TaskName $nombre | Out-Null
  Start-ScheduledTask -TaskName $nombre
  $puerto = Puerto-Aplicacion
  if (Esperar-Puerto $puerto 90) { Write-Host "Listo: la aplicación está abierta (puerto $puerto)." -ForegroundColor Green }
  else { Write-Warning "La tarea se inició pero la aplicación no abrió el puerto $puerto en 90 s. Ver: scripts\iniciar_con_windows.ps1 -Estado y data\logs\servicio.log" }
  exit 0
}

# ------------------------------------------------------------------------------------------- instalación
if (-not (Test-Path $pythonw)) { throw "No se encontró $pythonw. Ejecute primero scripts\install.ps1" }
if (-not $SoloAlIniciarSesion -and -not (Es-Administrador)) {
  throw "Ejecute PowerShell como administrador (clic derecho > Ejecutar como administrador): Windows lo exige para que la aplicación se inicie al encender el servidor."
}
$actual = "$env:USERDOMAIN\$env:USERNAME"
$user = if ($Credencial) { $Credencial.UserName } elseif ($Usuario) { $Usuario } else { $actual }
$puerto = Puerto-Aplicacion

# 1) Las contraseñas de SAP están en el almacén de credenciales de Windows, que es POR USUARIO.
if ($user -ieq $actual) {
  Write-Host "Contraseñas de SAP guardadas para ${user}:"
  $faltan = (Invoke-Sapsec verificar-credenciales) -eq 5
  if ($faltan -and -not $Credencial) {
    Write-Warning "La aplicación va a abrir, pero las extracciones de las conexiones marcadas con X van a fallar: guarde su contraseña con este mismo usuario (Conexiones SAP) o instale con -Usuario el usuario que las guardó."
    $r = Read-Host "¿Instalar igual? (S/N)"
    if ($r -notmatch '^[sS]') { exit 1 }
  }
} else {
  Write-Warning "La aplicación se ejecutará como ${user}: las contraseñas de SAP tienen que estar guardadas con ESE usuario de Windows."
}
if (Puerto-Abierto $puerto) {
  Write-Warning "La aplicación ya está abierta en esta PC (puerto $puerto), por ejemplo en una ventana de run.ps1. Ciérrela (Ctrl+C) para que quede a cargo del servicio; mientras siga abierta, el servicio la vigila sin abrir otra."
}

# 2) La tarea: el vigilante ("sapsec servicio") abre la aplicación y la reabre si se cae o deja de responder.
$argumentos = "-m sapsec.cli servicio"
if (-not $SoloEstaPC) { $argumentos += " --red" }
$accion = New-ScheduledTaskAction -Execute $pythonw -Argument $argumentos -WorkingDirectory $root
$config = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
  -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd
# Comprobación cada 5 minutos, todo el día: si el vigilante ya está corriendo, Windows no abre otro.
$vigilancia = New-ScheduledTaskTrigger -Daily -At "00:00"
$vigilancia.Repetition = (New-ScheduledTaskTrigger -Once -At "00:00" -RepetitionInterval (New-TimeSpan -Minutes 5) `
  -RepetitionDuration (New-TimeSpan -Hours 23 -Minutes 59)).Repetition

Stop-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue   # si ya estaba instalada (versión anterior)
if ($SoloAlIniciarSesion) {
  $inicio = New-ScheduledTaskTrigger -AtLogOn -User $user
  $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName $nombre -Action $accion -Trigger @($inicio, $vigilancia) -Settings $config `
    -Principal $principal -Force | Out-Null
} else {
  $inicio = New-ScheduledTaskTrigger -AtStartup
  $inicio.Delay = "PT1M"   # da tiempo a que la red esté lista después de encender
  if (-not $Credencial) {
    $Credencial = Get-Credential -UserName $user -Message ("Contraseña de Windows de $user. La guarda el Programador de " +
      "tareas de Windows (no esta aplicación) para abrirla al encender el servidor aunque nadie inicie sesión.")
  }
  if (-not $Credencial) { throw "Se canceló: sin la contraseña de Windows no puede iniciarse sin sesión (o use -SoloAlIniciarSesion)." }
  try {
    Register-ScheduledTask -TaskName $nombre -Action $accion -Trigger @($inicio, $vigilancia) -Settings $config `
      -User $Credencial.UserName -Password $Credencial.GetNetworkCredential().Password -RunLevel Limited -Force | Out-Null
  } catch {
    if ("$($_.Exception.Message)" -match "password|contrase|0x8007052E|1326") {
      throw "Windows rechazó la contraseña de $($Credencial.UserName). Vuelva a ejecutar el script e ingrésela de nuevo."
    }
    throw
  }
}

# 3) Iniciarla ahora y comprobar que responde.
Start-ScheduledTask -TaskName $nombre
Write-Host "Iniciando la aplicación como servicio..."
if (Esperar-Puerto $puerto 120) {
  Write-Host "Listo: la aplicación funciona siempre en segundo plano." -ForegroundColor Green
  if ($SoloEstaPC) { Write-Host "  Dirección: http://localhost:$puerto" } else {
    Write-Host "  En esta PC: https://localhost:$puerto   ·   Otras PC: https://$($env:COMPUTERNAME.ToLower()):$puerto"
  }
  if ($SoloAlIniciarSesion) { Write-Host "  Se abre al iniciar sesión $user; si se cae o deja de responder, se vuelve a abrir sola." }
  else { Write-Host "  Arranca sola al encender el servidor (aunque nadie inicie sesión); si se cae o deja de responder, se vuelve a abrir sola." }
  Write-Host "  Estado: scripts\iniciar_con_windows.ps1 -Estado   ·   Registro: data\logs\servicio.log"
  Write-Host "  Si cambia la contraseña de Windows de $user, vuelva a ejecutar este script." -ForegroundColor Yellow
} else {
  $i = Get-ScheduledTaskInfo -TaskName $nombre
  Write-Warning ("La tarea quedó instalada, pero la aplicación no abrió el puerto $puerto en 2 minutos (resultado de la tarea: 0x{0:X})." -f $i.LastTaskResult)
  if ($i.LastTaskResult -eq 2147943785) {   # 0x80070569: falta el permiso de inicio de sesión por lotes
    Write-Warning "La cuenta $user no tiene el permiso «Iniciar sesión como proceso por lotes»: lo asigna TI (directiva de seguridad local o de dominio)."
  }
  Write-Warning "Revise data\logs\servicio.log y data\logs\sapsec.log, o ejecute: scripts\iniciar_con_windows.ps1 -Estado"
  exit 1
}
