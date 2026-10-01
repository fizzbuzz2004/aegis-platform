$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$AgentDirectory = Join-Path $RepositoryRoot "agent-go"
$OutputDirectory = Join-Path $RepositoryRoot "dist"
$PreviousGoos = $env:GOOS
$PreviousGoarch = $env:GOARCH
$PreviousCgoEnabled = $env:CGO_ENABLED

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
Push-Location $AgentDirectory
try {
    $env:CGO_ENABLED = "0"
    $env:GOARCH = "amd64"

    $env:GOOS = "windows"
    go build -trimpath -ldflags "-s -w" -o (Join-Path $OutputDirectory "aegis-agent.exe") .
    if ($LASTEXITCODE -ne 0) { throw "Windows-Agent-Build fehlgeschlagen ($LASTEXITCODE)" }

    $env:GOOS = "linux"
    go build -trimpath -ldflags "-s -w" -o (Join-Path $OutputDirectory "aegis-agent-linux") .
    if ($LASTEXITCODE -ne 0) { throw "Linux-Agent-Build fehlgeschlagen ($LASTEXITCODE)" }
} finally {
    Pop-Location
    if ($null -eq $PreviousGoos) { Remove-Item Env:GOOS -ErrorAction SilentlyContinue } else { $env:GOOS = $PreviousGoos }
    if ($null -eq $PreviousGoarch) { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue } else { $env:GOARCH = $PreviousGoarch }
    if ($null -eq $PreviousCgoEnabled) { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue } else { $env:CGO_ENABLED = $PreviousCgoEnabled }
}

Write-Host "Agenten erstellt: $OutputDirectory"