# Permite que otras PC de la empresa (o conectadas por VPN) entren a la aplicación.
# Abre el puerto en el Firewall de Windows SOLO para direcciones privadas de la empresa.
#
# Ejecutar UNA VEZ, en PowerShell como ADMINISTRADOR, en la carpeta de la aplicación:
#   powershell -ExecutionPolicy Bypass -File scripts\habilitar_acceso_red.ps1
# Después, abrir la aplicación en modo red:  scripts\run.ps1 -Red
#
# Opciones:
#   -Puerto 8443            el mismo de network.port en config\settings.yaml (por defecto 8443)
#   -SoloSubredLocal        solo PC de la misma subred (más restrictivo; puede dejar afuera a la VPN)
#   -IncluirRedPublica      también si Windows marcó la red como «Pública» (no recomendado en notebooks)
#   -QuitarBloqueosPython   elimina reglas que bloquean a Python (se crean al elegir «Cancelar» en el aviso)
#   -Quitar                 cierra el acceso desde otras PC
#
# Desde fuera de la oficina: usar la VPN de la empresa. NO abrir este puerto en el router.
param([int]$Puerto = 8443, [switch]$SoloSubredLocal, [switch]$IncluirRedPublica,
      [switch]$QuitarBloqueosPython, [switch]$Quitar)
$ErrorActionPreference = "Stop"

$yo = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $yo.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Hay que ejecutarlo como administrador: clic derecho en PowerShell > Ejecutar como administrador." -ForegroundColor Yellow
  exit 1
}

$prefijo = "SAP Security Analyzer (acceso"
Get-NetFirewallRule -DisplayName "$prefijo*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Quitar) {
  Write-Host "Listo: se cerró el acceso desde otras PC (la aplicación sigue funcionando en esta PC)."
  exit 0
}

if ($SoloSubredLocal) { $remotas = @("LocalSubnet") } else { $remotas = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") }
if ($IncluirRedPublica) { $perfiles = "Any" } else { $perfiles = "Domain, Private" }
New-NetFirewallRule -DisplayName "$prefijo desde la red, HTTPS $Puerto)" -Direction Inbound -Action Allow `
  -Protocol TCP -LocalPort $Puerto -RemoteAddress $remotas -Profile $perfiles `
  -Description "Interfaz web de SAP Security Analyzer (solo lectura). Solo redes privadas de la empresa y VPN." | Out-Null
Write-Host "Regla del firewall creada: puerto $Puerto, solo desde $($remotas -join ', ')." -ForegroundColor Green

# Redes marcadas como «Pública»: Windows no deja entrar conexiones
$publicas = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | Where-Object { $_.NetworkCategory -eq "Public" })
if ($publicas.Count -gt 0 -and -not $IncluirRedPublica) {
  foreach ($p in $publicas) {
    Write-Host ""
    Write-Host "ATENCIÓN: la red '$($p.Name)' ($($p.InterfaceAlias)) está marcada como PÚBLICA y Windows bloquea las conexiones entrantes en ella." -ForegroundColor Yellow
    Write-Host "  Si es la red de la oficina, márquela como Privada (o pídalo a TI):"
    Write-Host "    Set-NetConnectionProfile -InterfaceIndex $($p.InterfaceIndex) -NetworkCategory Private"
  }
}

# Reglas que bloquean a Python (ganan sobre cualquier permiso)
$bloqueos = @(Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
  Where-Object { $_.Program -match 'pythonw?\.exe$' } | Get-NetFirewallRule -ErrorAction SilentlyContinue |
  Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Block" -and $_.Enabled -eq "True" })
if ($bloqueos.Count -gt 0) {
  if ($QuitarBloqueosPython) {
    $bloqueos | Remove-NetFirewallRule
    Write-Host "Se quitaron $($bloqueos.Count) regla(s) que bloqueaban a Python."
  } else {
    Write-Host ""
    Write-Host "ATENCIÓN: hay reglas que BLOQUEAN a Python (aparecen si alguien eligió «Cancelar» en el aviso del firewall):" -ForegroundColor Yellow
    $bloqueos | ForEach-Object { Write-Host "  - $($_.DisplayName)" }
    Write-Host "  Para quitarlas: vuelva a ejecutar este script agregando  -QuitarBloqueosPython"
  }
}

try { $nombre = [System.Net.Dns]::GetHostEntry("").HostName } catch { $nombre = $env:COMPUTERNAME }
$ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
  Select-Object -ExpandProperty IPAddress)
Write-Host ""
Write-Host "Listo. Siguiente paso: abrir la aplicación en modo red" -ForegroundColor Green
Write-Host "    powershell -ExecutionPolicy Bypass -File scripts\run.ps1 -Red"
Write-Host "Las otras PC entran con:"
Write-Host "    https://$($nombre.ToLower()):$Puerto"
foreach ($ip in $ips) { Write-Host "    https://$($ip):$Puerto" }
Write-Host "Desde fuera de la oficina: primero conectarse a la VPN de la empresa."
