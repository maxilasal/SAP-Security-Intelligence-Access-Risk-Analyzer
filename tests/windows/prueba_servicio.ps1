# Prueba REAL en Windows (GitHub Actions, windows-latest) del funcionamiento continuo:
# instala la tarea con scripts\iniciar_con_windows.ps1 (inicio al encender + comprobación cada 5 minutos, con un
# usuario de Windows y su contraseña), comprueba que la aplicación responde en modo red, la tira a la fuerza y
# verifica que vuelve sola, la detiene, la vuelve a iniciar y la quita. El reinicio del servidor no se puede probar
# en GitHub Actions: se verifica que la tarea tenga el disparador «al iniciar el sistema».
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root
$nombre = "SAP Security Analyzer - servidor web"
$puerto = 8443

function Fallar([string]$msg) { Write-Host "FALLÓ: $msg" -ForegroundColor Red; exit 1 }
function Ok([string]$msg) { Write-Host "OK: $msg" -ForegroundColor Green }
function Puerto-Abierto {
  $c = New-Object Net.Sockets.TcpClient
  try { $c.Connect("127.0.0.1", $puerto); return $true } catch { return $false } finally { $c.Close() }
}
function Esperar([scriptblock]$cond, [int]$segundos, [string]$que) {
  $fin = (Get-Date).AddSeconds($segundos)
  while ((Get-Date) -lt $fin) { if (& $cond) { return }; Start-Sleep -Milliseconds 500 }
  Fallar "$que (esperé $segundos s)"
}
function Estado {
  try { Get-Content (Join-Path $root "data\servicio.json") -Raw -Encoding UTF8 | ConvertFrom-Json }
  catch { [pscustomobject]@{ estado = ""; reinicios = 0; pid_app = 0 } }   # se está reescribiendo: se reintenta
}
function Procesos-App { Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'sapsec\.cli"?\s+(serve|servicio)(\s|$)' } }
function Instalador {
  $global:LASTEXITCODE = 0
  & (Join-Path $root "scripts\iniciar_con_windows.ps1") @args
  if ($LASTEXITCODE -ne 0) { Fallar "iniciar_con_windows.ps1 $($args -join ' ') terminó con código $LASTEXITCODE" }
}

# Usuario de Windows de prueba: en un servidor real es el que guardó las contraseñas de SAP.
$pw = "Sp-" + [guid]::NewGuid().ToString("N").Substring(0, 20) + "!9a"
Write-Host "::add-mask::$pw"
$secreto = ConvertTo-SecureString $pw -AsPlainText -Force
New-LocalUser -Name "sapsecci" -Password $secreto -PasswordNeverExpires -AccountNeverExpires `
  -Description "Prueba del servicio de SAP Security Analyzer" | Out-Null
Add-LocalGroupMember -SID "S-1-5-32-544" -Member "sapsecci"   # Administradores: tiene «iniciar sesión por lotes»
& icacls $root /grant "sapsecci:(OI)(CI)M" /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { Fallar "no se pudieron dar permisos sobre la carpeta a sapsecci" }
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\sapsecci", $secreto)
try {
  # 1) Instalación
  Instalador -Credencial $cred
  $t = Get-ScheduledTask -TaskName $nombre
  if ([string]$t.Principal.LogonType -ne "Password") { Fallar "la tarea no se inicia sin sesión: $($t.Principal.LogonType)" }
  $clases = @($t.Triggers | ForEach-Object { $_.CimClass.CimClassName })
  if ($clases -notcontains "MSFT_TaskBootTrigger") { Fallar "falta el inicio al encender el servidor: $($clases -join ', ')" }
  if (-not ($t.Triggers | Where-Object { $_.Repetition.Interval -eq "PT5M" })) { Fallar "falta la comprobación cada 5 minutos" }
  if ([string]$t.Settings.MultipleInstances -ne "IgnoreNew") { Fallar "podría abrir dos copias: $($t.Settings.MultipleInstances)" }
  if ($t.Actions[0].Arguments -notmatch "servicio --red") { Fallar "la tarea no usa el servicio en modo red: $($t.Actions[0].Arguments)" }
  Ok "tarea instalada: al encender el servidor (sin sesión, usuario $($t.Principal.UserId)) y comprobación cada 5 minutos"
  $salud = & curl.exe -sk "https://localhost:$puerto/api/v1/salud"
  if ("$salud" -notmatch '"estado":"ok"') { Fallar "la aplicación no responde por HTTPS: $salud" }
  Ok "responde en modo red: https://localhost:$puerto ($salud)"
  Esperar { (Estado).estado -eq "funcionando" } 90 "el servicio no informó «funcionando»"
  Ok "el servicio informa: funcionando"

  # 2) Caída: se tira la aplicación a la fuerza y tiene que volver sola
  $antes = Estado
  Stop-Process -Id $antes.pid_app -Force
  Esperar { -not (Puerto-Abierto) } 30 "la aplicación no se cerró al tirarla"
  Ok "aplicación tirada a la fuerza (proceso $($antes.pid_app))"
  Esperar { (Puerto-Abierto) -and ((Estado).reinicios -ge 1) } 90 "la aplicación no volvió sola"
  $despues = Estado
  Ok "volvió sola: reinicios=$($despues.reinicios), motivo «$($despues.ultimo_reinicio.motivo)», proceso nuevo $($despues.pid_app)"

  # 3) Estado, detener (no se reabre), iniciar y quitar
  Instalador -Estado
  Instalador -Detener
  Esperar { -not (Puerto-Abierto) } 60 "la aplicación siguió abierta después de -Detener"
  Esperar { -not (Procesos-App) } 30 "quedaron procesos de la aplicación después de -Detener"
  if ([string](Get-ScheduledTask -TaskName $nombre).State -ne "Disabled") { Fallar "-Detener no deshabilitó la tarea" }
  Ok "-Detener la cierra (sin procesos huérfanos) y la tarea queda deshabilitada"
  Instalador -Iniciar
  Esperar { Puerto-Abierto } 90 "-Iniciar no la volvió a abrir"
  Ok "-Iniciar la vuelve a abrir"
  Instalador -Quitar
  if (Get-ScheduledTask -TaskName $nombre -ErrorAction SilentlyContinue) { Fallar "-Quitar no eliminó la tarea" }
  Esperar { -not (Puerto-Abierto) } 60 "la aplicación siguió abierta después de -Quitar"
  Ok "-Quitar elimina la tarea y cierra la aplicación"
} finally {
  Unregister-ScheduledTask -TaskName $nombre -Confirm:$false -ErrorAction SilentlyContinue
  Remove-LocalUser -Name "sapsecci" -ErrorAction SilentlyContinue
}
Write-Host "Prueba del servicio en Windows: todo correcto." -ForegroundColor Green
