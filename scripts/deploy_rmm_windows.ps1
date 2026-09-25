[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$EnrollmentCode,
    [string]$ServerUrl = "https://aegis.msp-control.com"
)

$ErrorActionPreference = "Stop"
$InstallDir = "C:\ProgramData\Aegis"
$BinaryUrl = "$ServerUrl/downloads/aegis-agent-win-x64.exe"
$ExePath = Join-Path $InstallDir "aegis-agent.exe"

Write-Host "[*] Bereite Aegis MSP Deployment vor..."
if (!(Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }

Write-Host "[*] Lade Agent herunter..."
Invoke-WebRequest -Uri $BinaryUrl -OutFile $ExePath -UseBasicParsing

Write-Host "[*] Registriere Endpoint (Silent API Call)..."
$OSInfo = (Get-CimInstance Win32_OperatingSystem).Caption
$Payload = @{
    enrollment_code = $EnrollmentCode
    hostname = $env:COMPUTERNAME
    os_info = $OSInfo
} | ConvertTo-Json

$Response = Invoke-RestMethod -Uri "$ServerUrl/api/v1/agents/register" -Method Post -Body $Payload -ContentType "application/json"

if ($Response.status -eq "success" -and $Response.host_token) {
    Write-Host "[+] Registrierung erfolgreich. Setze Systemvariablen..."
    [Environment]::SetEnvironmentVariable("AEGIS_HOST_TOKEN", $Response.host_token, [EnvironmentVariableTarget]::Machine)
    [Environment]::SetEnvironmentVariable("AEGIS_SERVER_URL", $ServerUrl, [EnvironmentVariableTarget]::Machine)

    Write-Host "[*] Registriere und starte Windows Dienst..."
    # SC.exe zur Dienstregistrierung des Go-Binaries (vorausgesetzt das Go-Binary unterstützt Windows Services)
    sc.exe create "AegisAgent" binPath= "$ExePath" start= auto
    sc.exe start "AegisAgent"
    Write-Host "[+] Deployment abgeschlossen."
} else {
    Write-Error "[-] Registrierung fehlgeschlagen!"
}
