[CmdletBinding()]
param(
    [string]$BundlePath,
    [string]$ControlPlaneSSHHost,
    [string]$ControlPlaneSSHUser,
    [string]$RemoteBundlePath
)

$ErrorActionPreference = "Stop"
$TransferDirectory = $null

trap {
    if ($TransferDirectory -and (Test-Path -LiteralPath $TransferDirectory)) {
        Remove-Item -LiteralPath $TransferDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw $_
}

$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$PrincipalIdentity = [Security.Principal.WindowsPrincipal]::new($CurrentIdentity)
if (-not $PrincipalIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from PowerShell as Administrator."
}

if (-not $BundlePath) {
    if (-not $ControlPlaneSSHHost) {
        $ControlPlaneSSHHost = Read-Host "Control-plane IPv4 address (SSH must be enabled)"
    }
    if (-not $ControlPlaneSSHUser) {
        $ControlPlaneSSHUser = Read-Host "Ubuntu SSH username [vboxuser]"
        if (-not $ControlPlaneSSHUser) {
            $ControlPlaneSSHUser = "vboxuser"
        }
    }
    if (-not $RemoteBundlePath) {
        $RemoteBundlePath = Read-Host "Bundle directory on Ubuntu [/media/sf_aegis/aegis-vbox]"
        if (-not $RemoteBundlePath) {
            $RemoteBundlePath = "/media/sf_aegis/aegis-vbox"
        }
    }

    $ParsedSSHAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($ControlPlaneSSHHost, [ref]$ParsedSSHAddress) -or
        $ParsedSSHAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Enter the control-plane VM's IPv4 address for SSH."
    }
    if ($ControlPlaneSSHUser -notmatch '^[A-Za-z_][A-Za-z0-9_.-]*$') {
        throw "Invalid Ubuntu SSH username."
    }
    if ($RemoteBundlePath -notmatch '^/[A-Za-z0-9_./-]+$' -or
        $RemoteBundlePath -match '(^|/)\.\.?(/|$)') {
        throw "Remote bundle path must be an absolute path without spaces or shell metacharacters."
    }

    $SshCommand = (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source
    $ScpCommand = (Get-Command scp.exe -ErrorAction SilentlyContinue).Source
    $TarCommand = (Get-Command tar.exe -ErrorAction SilentlyContinue).Source
    if (-not $SshCommand -or -not $ScpCommand -or -not $TarCommand) {
        throw "Windows OpenSSH Client (ssh/scp) and tar.exe are required. Enable the OpenSSH Client optional feature, then retry."
    }

    $RemoteArchiveName = "aegis-windows-bundle-$([guid]::NewGuid().ToString('N')).tar.gz"
    $RemoteArchivePath = "/tmp/$RemoteArchiveName"
    $Target = "$ControlPlaneSSHUser@$ControlPlaneSSHHost"
    $StageCommand = "sudo test -s '$RemoteBundlePath/control-plane-ip.txt' && sudo test -s '$RemoteBundlePath/windows-agent/client.p12' && sudo rm -f '$RemoteArchivePath' && sudo tar -czf '$RemoteArchivePath' -C '$RemoteBundlePath' . && sudo chown '$ControlPlaneSSHUser' '$RemoteArchivePath' && chmod 600 '$RemoteArchivePath'"
    $TransferDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "aegis-agent-$([guid]::NewGuid().ToString('N'))"
    $LocalArchivePath = Join-Path $TransferDirectory $RemoteArchiveName
    $BundlePath = Join-Path $TransferDirectory "bundle"

    New-Item -ItemType Directory -Path $TransferDirectory | Out-Null
    try {
        Write-Host "Preparing a temporary bundle archive on the control-plane VM."
        Write-Host "SSH may ask for your Ubuntu password and sudo password."
        & $SshCommand -t $Target $StageCommand
        if ($LASTEXITCODE -ne 0) {
            throw "Could not prepare the bundle over SSH. Check SSH access, the sudo password, and the remote bundle path."
        }

        & $ScpCommand "${Target}:$RemoteArchivePath" $LocalArchivePath
        if ($LASTEXITCODE -ne 0) {
            throw "Could not download the temporary bundle archive over SCP."
        }

        New-Item -ItemType Directory -Path $BundlePath | Out-Null
        & $TarCommand -xzf $LocalArchivePath -C $BundlePath
        if ($LASTEXITCODE -ne 0) {
            throw "Could not extract the downloaded bundle."
        }
    } finally {
        & $SshCommand $Target "rm -f '$RemoteArchivePath'" 2>$null
    }
}

if (-not (Test-Path -LiteralPath $BundlePath -PathType Container)) {
    throw "Bundle folder does not exist: $BundlePath"
}
$BundlePath = (Resolve-Path -LiteralPath $BundlePath).Path
$AgentBundle = Join-Path $BundlePath "windows-agent"
$AddressFile = Join-Path $BundlePath "control-plane-ip.txt"
if (-not (Test-Path -LiteralPath $AddressFile -PathType Leaf)) {
    throw "Control-plane bundle is missing. Run setup-control-plane.sh first."
}
$ControlPlaneAddress = (Get-Content -Raw $AddressFile).Trim()
if ($ControlPlaneAddress -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') {
    throw "Invalid control-plane IPv4 address in $AddressFile"
}
$ParsedAddress = $null
if (-not [System.Net.IPAddress]::TryParse($ControlPlaneAddress, [ref]$ParsedAddress)) {
    throw "Invalid control-plane IPv4 address in $AddressFile"
}

$RequiredFiles = @("aegis-agent.exe", "ca.crt", "client.crt", "client.key", "client.p12")
foreach ($file in $RequiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $AgentBundle $file) -PathType Leaf)) {
        throw "Missing Windows agent bundle file: $(Join-Path $AgentBundle $file)"
    }
}

$AgentRoot = Join-Path $env:ProgramData "Aegis"
$PkiDirectory = Join-Path $AgentRoot "pki"
$AgentPath = Join-Path $AgentRoot "aegis-agent.exe"
$RunnerPath = Join-Path $AgentRoot "run-agent.ps1"
$LogPath = Join-Path $AgentRoot "agent.log"
$TaskName = "Aegis VirtualBox Test Agent"
$ServerUrl = "https://$ControlPlaneAddress`:8000"

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

New-Item -ItemType Directory -Force -Path $AgentRoot, $PkiDirectory | Out-Null
& icacls.exe $AgentRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not restrict access to $AgentRoot."
}
Copy-Item -LiteralPath (Join-Path $AgentBundle "aegis-agent.exe") -Destination $AgentPath -Force
foreach ($file in @("ca.crt", "client.crt", "client.key")) {
    Copy-Item -LiteralPath (Join-Path $AgentBundle $file) -Destination (Join-Path $PkiDirectory $file) -Force
}

$RootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
$RootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
    $RootCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Join-Path $AgentBundle "ca.crt")
    )
    if (-not $RootStore.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $RootCertificate.Thumbprint,
        $false
    ).Count) {
        [void]$RootStore.Add($RootCertificate)
    }
} finally {
    $RootStore.Close()
}

$ClientCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    (Join-Path $AgentBundle "client.p12"),
    "",
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
)
$PersonalStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    [System.Security.Cryptography.X509Certificates.StoreName]::My,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
$PersonalStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
    if (-not $PersonalStore.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $ClientCertificate.Thumbprint,
        $false
    ).Count) {
        Import-PfxCertificate -FilePath (Join-Path $AgentBundle "client.p12") `
            -CertStoreLocation Cert:\CurrentUser\My -Password $EmptyPassword | Out-Null
    }
} finally {
    $PersonalStore.Close()
    $ClientCertificate.Dispose()
}

$Handler = [System.Net.Http.HttpClientHandler]::new()
$ProbeCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    (Join-Path $AgentBundle "client.p12"),
    "",
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
)
[void]$Handler.ClientCertificates.Add($ProbeCertificate)
$HttpClient = [System.Net.Http.HttpClient]::new($Handler)
$Reachable = $false
$LastConnectionError = "No successful HTTPS response."
try {
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $Response = $HttpClient.GetAsync("$ServerUrl/docs").GetAwaiter().GetResult()
            if ($Response.IsSuccessStatusCode) {
                $Reachable = $true
                $Response.Dispose()
                break
            }
            $LastConnectionError = "HTTP $([int]$Response.StatusCode)"
            $Response.Dispose()
        } catch {
            $LastConnectionError = $_.Exception.Message
        }
        if (-not $Reachable -and $attempt -lt 59) {
            Start-Sleep -Seconds 2
        }
    }
} finally {
    $HttpClient.Dispose()
    $ProbeCertificate.Dispose()
}
if (-not $Reachable) {
    throw "Cannot reach $ServerUrl with the shared test certificate ($LastConnectionError). Check the control plane and port 8000, then retry."
}

& $AgentPath -server $ServerUrl -register enroll_pilot_2026 -once -debug
if ($LASTEXITCODE -ne 0) {
    throw "Agent registration failed with exit code $LASTEXITCODE."
}

@"
`$ErrorActionPreference = "Continue"
& "$AgentPath" -server "$ServerUrl" -debug >> "$LogPath" 2>&1
exit `$LASTEXITCODE
"@ | Set-Content -Path $RunnerPath -Encoding ascii

$Action = New-ScheduledTaskAction -Execute "$PSHOME\powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$RunnerPath`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "Windows agent installed and scheduled to start at boot."
Write-Host "Agent log: $LogPath"
Write-Host "Dashboard: $ServerUrl/api/v1/dashboard/ui"
Write-Host "Sign in as admin; use ADMIN_INITIAL_PASSWORD printed by setup-control-plane.sh."
Write-Host "The Windows client certificate was installed for this Windows user for dashboard access."

if ($TransferDirectory -and (Test-Path -LiteralPath $TransferDirectory)) {
    Remove-Item -LiteralPath $TransferDirectory -Recurse -Force
}
