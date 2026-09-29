<#
.SYNOPSIS
    Aegis MSP Agent Deployment Skript für Windows
.DESCRIPTION
    Lädt den Aegis Compliance Agenten herunter, registriert den Endpoint 
    über die Control Plane API, konfiguriert den persistente Windows-Dienst 
    und richtet automatische Wiederherstellungsoptionen ein.
.PARAMETER EnrollmentCode
    Der mandantenspezifische Registrierungscode aus dem Aegis Portal.
.PARAMETER ServerUrl
    Die Basis-URL der Control Plane (Standard: https://aegis.msp-control.com).
.PARAMETER TestMode
    Ignoriert SSL-Zertifikatsfehler (nur für lokale VM-Testumgebungen nutzen!).
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$EnrollmentCode,
    
    [string]$ServerUrl = "https://aegis.msp-control.com",
    
    [switch]$TestMode
)

$ErrorActionPreference = "Stop"
$InstallDir = "C:\ProgramData\Aegis"
$LogFile = Join-Path$InstallDir "deployment.log"

# Stelle sicher, dass das Installationsverzeichnis existiert
if (!(Test-Path $InstallDir)) { 
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null 
}

# Zentrales Logging für RMM-Audits einrichten
function Write-Log {
    param ([string]$Message, [string]$Level="INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level]$Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value$LogEntry
}

try {
    Write-Log "=== Starte Aegis Agent Deployment ==="

    # NIS2 / Lab-Handling: TLS-Sicherheit erzwingen, Zertifikate im Testmodus optional bypassen
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    if ($TestMode) {
        Write-Log "WARNUNG: TestMode aktiv - SSL-Zertifikatsvalidierung wird übersprungen." "WARN"
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    }

    $BinaryUrl = "$ServerUrl/downloads/aegis-agent-win-x64.exe"
    $ExePath = Join-Path$InstallDir "aegis-agent.exe"

    # 1. Vorherigen Dienst bereinigen (ermöglicht reibungslose Updates/Re-Tests)
    try {
        $Service = Get-Service -Name "AegisAgent" -ErrorAction SilentlyContinue
        if ($Service) {
            Write-Log "Existierender AegisAgent-Dienst wird gestoppt und entfernt..."
            Stop-Service -Name "AegisAgent" -Force -ErrorAction SilentlyContinue
            sc.exe delete "AegisAgent" | Out-Null
            Start-Sleep -Seconds 3
        }
    } catch {
        Write-Log "Hinweis bei Dienst-Bereinigung: $_" "WARN"
    }

    # 2. Agent-Binärdatei herunterladen
    Write-Log "Lade Agent herunter von: $BinaryUrl"
    Invoke-WebRequest -Uri $BinaryUrl -OutFile$ExePath -UseBasicParsing

    # 3. Endpoint bei der Control Plane registrieren
    Write-Log "Registriere Endpoint bei Control Plane..."
    $OSInfo = (Get-CimInstance Win32_OperatingSystem).Caption
    $Payload = @{
        enrollment_code = $EnrollmentCode
        hostname        = $env:COMPUTERNAME
        os_info         = $OSInfo
    } | ConvertTo-Json -Depth 2

    $Response = Invoke-RestMethod -Uri "$ServerUrl/api/v1/agents/register" -Method Post -Body $Payload -ContentType "application/json"

    if ($Response.status -eq "success" -and $Response.host_token) {
        Write-Log "Registrierung erfolgreich. Schreibe Systemvariablen (Machine Scope)..."
        [Environment]::SetEnvironmentVariable("AEGIS_HOST_TOKEN", $Response.host_token, [EnvironmentVariableTarget]::Machine)
        [Environment]::SetEnvironmentVariable("AEGIS_SERVER_URL", $ServerUrl, [EnvironmentVariableTarget]::Machine)

        # 4. Windows Dienst einrichten
        Write-Log "Registriere Windows Dienst..."
        # Wichtig: Ingame-Anführungszeichen im Pfad wegen möglicher Leerzeichen im Installationspfad
        sc.exe create "AegisAgent" binPath= "`"$ExePath`"" start= auto displayname= "Aegis Compliance Agent" | Out-Null
        
        # Enterprise Best Practice: Automatischer Neustart bei Dienstabsturz (nach 60 Sekunden)
        sc.exe failure "AegisAgent" reset= 86400 actions= restart/60000 | Out-Null

        Write-Log "Starte Windows Dienst..."
        Start-Service -Name "AegisAgent"
        
        Write-Log "=== Deployment erfolgreich abgeschlossen ===" "SUCCESS"
        exit 0
    } else {
        throw "API meldete Fehler oder ungültige Antwort: $($Response | ConvertTo-Json -Compress)"
    }

} catch {
    Write-Log "FEHLER beim Deployment: $_" "ERROR"
    exit 1
}
