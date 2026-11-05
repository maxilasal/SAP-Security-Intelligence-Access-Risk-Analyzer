# Actualiza la aplicación desde el repositorio Git. No toca data\ (base, snapshots, certificados, logs)
# ni config\settings.yaml: Git los ignora.
#
#   powershell -ExecutionPolicy Bypass -File scripts\actualizar.ps1                   -> última versión (main)
#   powershell -ExecutionPolicy Bypass -File scripts\actualizar.ps1 -Version v0.1.0   -> una versión puntual (tag)
#
# Antes: cerrar la ventana de la aplicación si se abrió con run.ps1. Si se inicia con Windows
# (scripts\iniciar_con_windows.ps1), este script la detiene y la vuelve a iniciar.
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

$tarea = Get-ScheduledTask -TaskName "SAP Security Analyzer - servidor web" -ErrorAction SilentlyContinue
$reiniciar = $tarea -and $tarea.State -eq "Running"
if ($reiniciar) {
  Write-Host "Deteniendo la aplicación que corre en segundo plano..."
  Stop-ScheduledTask -TaskName $tarea.TaskName
  Start-Sleep -Seconds 2
}

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
& .\.venv\Scripts\sapsec.exe init-db
if ($LASTEXITCODE -ne 0) { throw "No se pudo actualizar la base de datos (ver data\logs\sapsec.log)." }

if ($reiniciar) {
  Start-ScheduledTask -TaskName $tarea.TaskName
  Write-Host "Listo: la aplicación se reinició en segundo plano." -ForegroundColor Green
} else {
  Write-Host "Listo. Abra la aplicación: powershell -ExecutionPolicy Bypass -File scripts\run.ps1  (agregue -Red para otras PC)" -ForegroundColor Green
}
Write-Host "Versión instalada: $(git describe --tags --always)"
