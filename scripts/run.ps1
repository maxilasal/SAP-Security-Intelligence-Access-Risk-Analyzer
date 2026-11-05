# Inicia la aplicación.
#   Solo esta PC (http://localhost:8000):
#       powershell -ExecutionPolicy Bypass -File scripts\run.ps1
#   Para que entren otras PC de la empresa o por VPN (https://NOMBRE-DE-ESTA-PC:8443):
#       powershell -ExecutionPolicy Bypass -File scripts\run.ps1 -Red
#   (la primera vez, como administrador: scripts\habilitar_acceso_red.ps1)
param(
  [switch]$Red,        # accesible desde otras PC de la red de la empresa / VPN (HTTPS)
  [switch]$SinHttps,   # solo para pruebas: modo red sin cifrar
  [int]$Puerto = 0     # 0 = el predeterminado (8000 solo esta PC, 8443 en red)
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$cli = @("serve")
if ($Red) { $cli += "--red" }
if ($SinHttps) { $cli += "--sin-https" }
if ($Puerto -gt 0) { $cli += @("--port", "$Puerto") }
& .\.venv\Scripts\sapsec.exe @cli
