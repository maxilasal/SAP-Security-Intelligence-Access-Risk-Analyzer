# Instalación en Windows (PowerShell). Ejecutar desde la carpeta del proyecto:
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) { & py -3 -m venv .venv } else { & python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[dev]"

if (-not (Test-Path "config\settings.yaml")) { Copy-Item "config\settings.example.yaml" "config\settings.yaml" }
New-Item -ItemType Directory -Force -Path data | Out-Null

& .\.venv\Scripts\python.exe scripts\build_demo_fixture.py
& .\.venv\Scripts\sapsec.exe init-db

if (-not $env:SAPNWRFC_HOME) {
  Write-Warning "SAPNWRFC_HOME no está definido. Necesario para conectarse a SAP (ver docs\02_conectividad_rfc.md)."
}
Write-Host ""
Write-Host "Instalación completa."
Write-Host "  Pruebas:          .\.venv\Scripts\python.exe -m pytest"
Write-Host "  Demo (ficticio):  .\.venv\Scripts\sapsec.exe demo"
Write-Host "  Crear admin:      .\.venv\Scripts\sapsec.exe create-user admin administrador"
Write-Host "  Iniciar:          powershell -ExecutionPolicy Bypass -File scripts\run.ps1"
Write-Host "  Para otras PC:    scripts\habilitar_acceso_red.ps1 (una vez, como administrador) y luego scripts\run.ps1 -Red"
Write-Host "  Actualizar:       powershell -ExecutionPolicy Bypass -File scripts\actualizar.ps1"
