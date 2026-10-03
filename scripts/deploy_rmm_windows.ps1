<#
.SYNOPSIS
    Aegis MSP Agent Deployment Skript für Windows (RMM & Intune Ready)
.DESCRIPTION
    Lädt den Aegis Compliance Agenten herunter, registriert den Endpoint 
    über die Control Plane API, konfiguriert den persistenten Windows-Dienst 
    und richtet automatische Wiederherstellungsoptionen ein.
.PARAMETER EnrollmentCode
    Der mandantenspezifische Registrierungscode aus dem Aegis Portal.
.PARAMETER ServerUrl
    Die Basis-URL der Control Plane (Standard: https://aegis.msp-control.com).
.PARAMETER TestMode
    Ignoriert SSL-Zertifikatsfehler (nur für lokale VM-Testumgebungen nutzen!).
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$EnrollmentCode,

    [string]$ServerUrl = "https://aegis.msp-control.com",

    [Parameter(Mandatory=$true)]
    [string]$RootCACertificate,

    [Parameter(Mandatory=$true)]
    [string]$ClientCertificate,

    [Parameter(Mandatory=$true)]
    [string]$ClientPrivateKey,

    [Parameter(Mandatory=$true)]
    [string]$ClientPfx,

    [Parameter(Mandatory=$true)]
    [securestring]$ClientPfxPassword
)

$ErrorActionPreference = "Stop"
$InstallDir = "C:\ProgramData\Aegis"
$PkiDir = Join-Path $InstallDir "pki"
$LogFile = Join-Path $InstallDir "deployment.log"

# Stelle sicher, dass das Installationsverzeichnis existiert
if (!(Test-Path $InstallDir)) { 
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null 
}
if (!(Test-Path $PkiDir)) {
    New-Item -ItemType Directory -Path $PkiDir -Force | Out-Null
}

foreach ($CertificateFile in @($RootCACertificate, $ClientCertificate, $ClientPrivateKey, $ClientPfx)) {
    if (!(Test-Path -LiteralPath $CertificateFile -PathType Leaf)) {
        throw "Certificate input file does not exist: $CertificateFile"
    }
}

icacls.exe $PkiDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not restrict the agent certificate directory ACL." }
Copy-Item -LiteralPath $RootCACertificate -Destination (Join-Path $PkiDir "ca.crt") -Force
Copy-Item -LiteralPath $ClientCertificate -Destination (Join-Path $PkiDir "client.crt") -Force
Copy-Item -LiteralPath $ClientPrivateKey -Destination (Join-Path $PkiDir "client.key") -Force

Import-Certificate -FilePath (Join-Path $PkiDir "ca.crt") -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
$PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientPfxPassword)
try {
    $PfxPasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($PasswordPointer)
    $ClientCertificateObject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $ClientPfx,
        $PfxPasswordPlainText,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    )
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
    $PfxPasswordPlainText = $null
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

    # Keep platform TLS defaults and certificate validation enabled.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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

    # 2. Agent-Binärdatei herunterladen (mit RMM Retry-Logik)
    Write-Log "Lade Agent herunter von: $BinaryUrl"
    $MaxRetries = 3$RetryCount = 0
    $Downloaded =$false

    while (!$Downloaded -and $RetryCount -lt$MaxRetries) {
        try {
            Invoke-WebRequest -Uri $BinaryUrl -OutFile $ExePath -Certificate $ClientCertificateObject -UseBasicParsing -ErrorAction Stop
            $Downloaded =$true
            Write-Log "Download erfolgreich."
        } catch {
            $RetryCount++
            Write-Log "Download fehlgeschlagen (Versuch $RetryCount von $MaxRetries):$_" "WARN"
            if ($RetryCount -ge$MaxRetries) { throw "Konnte Aegis Agent nach $MaxRetries Versuchen nicht herunterladen." }
            Start-Sleep -Seconds 5
        }
    }

    # 3. Endpoint bei der Control Plane registrieren
    Write-Log "Registriere Endpoint bei Control Plane..."
    $OSInfo = (Get-CimInstance Win32_OperatingSystem).Caption
    $Payload = @{
        enrollment_code = $EnrollmentCode
        hostname        = $env:COMPUTERNAME
        os_info         = $OSInfo
    } | ConvertTo-Json -Depth 2

    $Response = Invoke-RestMethod -Uri "$ServerUrl/api/v1/agents/register" -Method Post -Body $Payload -ContentType "application/json" -Certificate $ClientCertificateObject

    if ($Response.status -eq "success" -and $Response.host_token) {
        Write-Log "Registrierung erfolgreich. Schreibe Systemvariablen..."
        
        # Systemweite Variablen setzen (für Shell-Zugriff und zukünftige Reboots)
        [Environment]::SetEnvironmentVariable("AEGIS_HOST_TOKEN", $Response.host_token, [EnvironmentVariableTarget]::Machine)
        [Environment]::SetEnvironmentVariable("AEGIS_SERVER_URL", $ServerUrl, [EnvironmentVariableTarget]::Machine)

        # 4. Windows Dienst einrichten
        Write-Log "Registriere Windows Dienst..."
        sc.exe create "AegisAgent" binPath= "`"$ExePath`"" start= auto displayname= "Aegis Compliance Agent" | Out-Null
        
        # CRITICAL FIX: Windows Dienste lesen neue Machine-Umgebungsvariablen nicht ohne Neustart ein.
        # Wir injizieren die Variablen direkt in die Registry des Dienstes, damit er sofort starten kann.
        $ServiceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AegisAgent"
        $ServiceEnv = @(
            "AEGIS_HOST_TOKEN=$($Response.host_token)",
            "AEGIS_SERVER_URL=$ServerUrl"
        )
        Set-ItemProperty -Path $ServiceRegPath -Name "Environment" -Value $ServiceEnv -Type MultiString

        # Enterprise Best Practice: Automatischer Neustart bei Dienstabsturz (nach 60s, unendlich oft)
        sc.exe failure "AegisAgent" reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

        Write-Log "Starte Windows Dienst..."
        Start-Service -Name "AegisAgent"
        $ClientCertificateObject.Dispose()
        
        # Überprüfe, ob der Dienst wirklich läuft
        Start-Sleep -Seconds 2
        $ServiceStatus = (Get-Service -Name "AegisAgent").Status
        if ($ServiceStatus -eq "Running") {
            Write-Log "=== Deployment erfolgreich abgeschlossen (Service Running) ===" "SUCCESS"
            exit 0
        } else {
            throw "Dienst wurde installiert, aber startete unerwartet nicht. Status: $ServiceStatus"
        }
    } else {
        throw "API meldete Fehler oder ungültige Antwort: $($Response | ConvertTo-Json -Compress)"
    }

} catch {
    Write-Log "FEHLER beim Deployment: $_" "ERROR"
    exit 1
}
