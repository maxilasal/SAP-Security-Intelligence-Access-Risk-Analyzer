# Actualiza la aplicación desde el repositorio Git. No toca data\ (base, snapshots, certificados, logs)
# ni config\settings.yaml: Git los ignora.
#
#   powershell -ExecutionPolicy Bypass -File scripts\actualizar.ps1                   -> última versión (main)
#   powershell -ExecutionPolicy Bypass -File scripts\actualizar.ps1 -Version v0.1.0   -> una versión puntual (tag)
#
# Antes: cerrar la ventana de la aplicación si se abrió con run.ps1. Si funciona como servicio
# (scripts\iniciar_con_windows.ps1), este script la detiene y la vuelve a iniciar: en ese caso, ejecutarlo en
# PowerShell como administrador.
param([string]$Version = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Invoke-Git {
  # git informa el avance por stderr: se ejecuta sin que PowerShell lo trate como error y se revisa el código de salida.
  $anterior = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  & git @args
  $codigo = $LASTEXITCODE
  $ErrorActionPreference = $anterior
  if ($codigo -ne 0) { throw "Falló: git $($args -join ' ')" }
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw "No se encontró Git. Instálelo con: winget install --id Git.Git -e (y abra una nueva ventana de PowerShell)."
}
if (-not (Test-Path (Join-Path $root ".git"))) {
  throw "Esta carpeta no es un clon del repositorio. Ver docs\08_versionado_y_actualizacion.md."
}
$modificados = git status --porcelain --untracked-files=no
if ($modificados) {
  Write-Host "Hay archivos de la aplicación modificados en esta PC:" -ForegroundColor Yellow
  $modificados | ForEach-Object { Write-Host "  $_" }
  throw "Para no perder esos cambios se detuvo la actualización. Descártelos con 'git checkout -- .' o guárdelos con 'git stash'."
}

function Procesos-Sapsec([string]$patron) {
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match $patron }
}
if (Procesos-Sapsec 'sapsec\.exe"?\s+serve(\s|$)') {
  throw "La aplicación está abierta en una ventana (run.ps1): ciérrela con Ctrl+C y vuelva a ejecutar la actualización."
}
$tarea = Get-ScheduledTask -TaskName "SAP Security Analyzer - servidor web" -ErrorAction SilentlyContinue
$reiniciar = $tarea -and $tarea.State -ne "Disabled"
if ($reiniciar) {
  if (Procesos-Sapsec 'sapsec(\.cli|\.exe)?"?\s+(extract|extract-all|run-schedule|run-due)(\s|$)') {
    throw "Hay una extracción en curso: espere a que termine (ver «Todos los sistemas») y vuelva a ejecutar la actualización."
  }
  Write-Host "Deteniendo la aplicación (funciona como servicio)..."
  try {
    Disable-ScheduledTask -TaskName $tarea.TaskName | Out-Null   # que la comprobación de cada 5 minutos no la reabra
    Stop-ScheduledTask -TaskName $tarea.TaskName
  } catch {
    throw "No se pudo detener el servicio: ejecute la actualización en PowerShell como administrador. ($($_.Exception.Message))"
  }
  $patron = 'sapsec\.cli"?\s+(serve|servicio)(\s|$)'
  $fin = (Get-Date).AddSeconds(30)
  while ((Procesos-Sapsec $patron) -and (Get-Date) -lt $fin) { Start-Sleep -Seconds 1 }
  Procesos-Sapsec $patron | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

try {
$antes = (git rev-parse --short HEAD).Trim()
Invoke-Git fetch --tags --prune origin
if ($Version) {
  Invoke-Git checkout --quiet $Version
} else {
  Invoke-Git checkout --quiet main
  Invoke-Git merge --ff-only --quiet origin/main
}
$despues = (git rev-parse --short HEAD).Trim()

if ($antes -eq $despues) {
  Write-Host "La aplicación ya estaba en esa versión ($despues)." -ForegroundColor Green
} else {
  Write-Host "Cambios incorporados ($antes -> $despues):" -ForegroundColor Green
  git log --oneline --no-decorate "$antes..$despues"
  git diff --quiet $antes $despues -- pyproject.toml
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Cambiaron las dependencias: reinstalando..."
    & .\.venv\Scripts\python.exe -m pip install -e . --quiet
    if ($LASTEXITCODE -ne 0) { throw "No se pudieron instalar las dependencias." }
  }
}

# Migraciones de la base (idempotentes): agrega columnas o tablas nuevas sin borrar datos.
$anterior = $ErrorActionPreference
$ErrorActionPreference = "Continue"   # el registro va a stderr: no es un error
& .\.venv\Scripts\sapsec.exe init-db
$codigo = $LASTEXITCODE
$ErrorActionPreference = $anterior
if ($codigo -ne 0) { throw "No se pudo actualizar la base de datos (ver data\logs\sapsec.log)." }
} finally {
  if ($reiniciar) {   # también si algo falló: que el servicio no quede apagado
    Enable-ScheduledTask -TaskName $tarea.TaskName | Out-Null
    Start-ScheduledTask -TaskName $tarea.TaskName
  }
}

if ($reiniciar) {
  Write-Host "Listo: la aplicación se reinició como servicio (funciona siempre en segundo plano)." -ForegroundColor Green
} else {
  Write-Host "Listo. Abra la aplicación: powershell -ExecutionPolicy Bypass -File scripts\run.ps1  (agregue -Red para otras PC)" -ForegroundColor Green
}
Write-Host "Versión instalada: $(git describe --tags --always)"
