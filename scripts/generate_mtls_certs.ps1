[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    [Parameter(Mandatory = $true)]
    [string]$ClientName
)

$ErrorActionPreference = "Stop"
if ($ServerName -notmatch '^[A-Za-z0-9.-]+$') { throw "ServerName must be a DNS name or IPv4 address." }
if ($ClientName -notmatch '^[A-Za-z0-9._-]+$') { throw "ClientName contains unsupported characters." }
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { throw "OpenSSL is required." }

function Invoke-OpenSSL {
    param([string[]]$OpenSSLArgs)
    & openssl @OpenSSLArgs
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL failed with exit code $LASTEXITCODE." }
}

$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$CaDirectory = Join-Path $OutputDirectory "ca"
$ServerDirectory = Join-Path $OutputDirectory "server"
$ClientDirectory = Join-Path (Join-Path $OutputDirectory "clients") $ClientName
New-Item -ItemType Directory -Force -Path $CaDirectory, $ServerDirectory, $ClientDirectory | Out-Null
$CurrentAccount = "$env:USERDOMAIN\$env:USERNAME"
& icacls.exe $OutputDirectory /inheritance:r /grant:r "$($CurrentAccount):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not restrict certificate directory ACLs." }
$CaKey = Join-Path $CaDirectory "ca.key"
$CaCertificate = Join-Path $CaDirectory "ca.crt"

if (-not (Test-Path $CaKey) -and -not (Test-Path $CaCertificate)) {
    Invoke-OpenSSL @("genpkey", "-algorithm", "RSA", "-aes-256-cbc", "-pkeyopt", "rsa_keygen_bits:4096", "-out", $CaKey)
    Invoke-OpenSSL @("req", "-x509", "-new", "-key", $CaKey, "-sha256", "-days", "3650", "-subj", "/CN=Aegis Root CA", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", $CaCertificate)
} elseif (-not (Test-Path $CaKey) -or -not (Test-Path $CaCertificate)) {
    throw "The CA certificate and encrypted private key must both exist."
}

$ServerCaCopy = Join-Path $ServerDirectory "ca.crt"
$ClientCaCopy = Join-Path $ClientDirectory "ca.crt"
Copy-Item -Force $CaCertificate $ServerCaCopy
Copy-Item -Force $CaCertificate $ClientCaCopy

$ServerKey = Join-Path $ServerDirectory "server.key"
$ServerRequest = Join-Path $ServerDirectory "server.csr"
$ServerExt = Join-Path $ServerDirectory "server.ext"
$ServerCertificate = Join-Path $ServerDirectory "server.crt"
$ServerSubjectAltName = "DNS:localhost,IP:127.0.0.1"
$ParsedIP = $null
if ([System.Net.IPAddress]::TryParse($ServerName, [ref]$ParsedIP)) {
    $ServerSubjectAltName += ",IP:$ServerName"
} else {
    $ServerSubjectAltName += ",DNS:$ServerName"
}
Invoke-OpenSSL @("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", $ServerKey)
Invoke-OpenSSL @("req", "-new", "-key", $ServerKey, "-subj", "/CN=$ServerName", "-out", $ServerRequest)
@"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$ServerSubjectAltName
"@ | Set-Content -Encoding ascii $ServerExt
Invoke-OpenSSL @("x509", "-req", "-in", $ServerRequest, "-CA", $CaCertificate, "-CAkey", $CaKey, "-CAcreateserial", "-days", "397", "-sha256", "-extfile", $ServerExt, "-out", $ServerCertificate)
Remove-Item -Force $ServerRequest, $ServerExt

$ClientKey = Join-Path $ClientDirectory "client.key"
$ClientRequest = Join-Path $ClientDirectory "client.csr"
$ClientExt = Join-Path $ClientDirectory "client.ext"
$ClientCertificate = Join-Path $ClientDirectory "client.crt"
$ClientPfx = Join-Path $ClientDirectory "client.p12"
Invoke-OpenSSL @("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", $ClientKey)
Invoke-OpenSSL @("req", "-new", "-key", $ClientKey, "-subj", "/CN=$ClientName", "-out", $ClientRequest)
@"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
"@ | Set-Content -Encoding ascii $ClientExt
Invoke-OpenSSL @("x509", "-req", "-in", $ClientRequest, "-CA", $CaCertificate, "-CAkey", $CaKey, "-CAcreateserial", "-days", "397", "-sha256", "-extfile", $ClientExt, "-out", $ClientCertificate)
Invoke-OpenSSL @("pkcs12", "-export", "-in", $ClientCertificate, "-inkey", $ClientKey, "-certfile", $CaCertificate, "-name", $ClientName, "-out", $ClientPfx)
Remove-Item -Force $ClientRequest, $ClientExt

& icacls.exe $OutputDirectory /inheritance:r /grant:r "$($CurrentAccount):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not restrict certificate directory ACLs." }
Write-Host "Server material: $ServerDirectory"
Write-Host "Client identity: $ClientDirectory"
Write-Host "Keep $CaKey offline and never copy it to a VM."
