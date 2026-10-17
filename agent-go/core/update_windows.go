//go:build windows

package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

const windowsUpdateScript = `param([string]$ExecutablePath, [string]$StagedPath, [int]$ParentProcessId, [string]$ArgumentsBase64)
$ErrorActionPreference = "Stop"
try {
    # Warten, bis der alte Prozess komplett freigegeben ist
    Wait-Process -Id $ParentProcessId -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $BackupPath = "$ExecutablePath.old"
    if (Test-Path -LiteralPath $BackupPath) {
        Remove-Item -LiteralPath $BackupPath -Force -ErrorAction SilentlyContinue
    }

    # Robuste Retry-Schleife mit Backoff bei File-Locks / Antivirus-Scans
    $maxRetries = 5
    $delaySeconds = 3
    $moved = $false

    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            Move-Item -LiteralPath $ExecutablePath -Destination $BackupPath -Force
            $moved = $true
            break
        } catch {
            Start-Sleep -Seconds ($delaySeconds * $attempt)
        }
    }
    if (-not $moved) { throw "Konnte alte Binärdatei aufgrund von File-Locks nicht verschieben." }

    try {
        Move-Item -LiteralPath $StagedPath -Destination $ExecutablePath -Force
    } catch {
        Move-Item -LiteralPath $BackupPath -Destination $ExecutablePath -Force
        throw
    }

    $ArgumentsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgumentsBase64))
    $Arguments = @($ArgumentsJson | ConvertFrom-Json)
    Start-Process -FilePath $ExecutablePath -ArgumentList $Arguments -WorkingDirectory (Split-Path -Parent $ExecutablePath)
} finally {
    Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
}`

// init führt beim Start des Pakets automatisch die Bereinigung verwaister Update-Skripte durch.
func init() {
	cleanOrphanedUpdateHelpers()
}

func cleanOrphanedUpdateHelpers() {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(execPath)
	matches, err := filepath.Glob(filepath.Join(dir, ".aegis-update-*.ps1"))
	if err != nil {
		return
	}
	for _, match := range matches {
		_ = os.Remove(match)
	}
}

func replaceExecutable(executablePath, stagedPath string) (bool, error) {
	stagedBinary := executablePath + ".new"
	if err := os.Remove(stagedBinary); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("cannot remove stale staged update: %w", err)
	}
	if err := os.Rename(stagedPath, stagedBinary); err != nil {
		return false, fmt.Errorf("cannot prepare staged Windows update: %w", err)
	}

	helper, err := os.CreateTemp(filepath.Dir(executablePath), ".aegis-update-*.ps1")
	if err != nil {
		_ = os.Remove(stagedBinary)
		return false, fmt.Errorf("cannot create Windows update helper: %w", err)
	}
	helperPath := helper.Name()
	if _, err := helper.WriteString(windowsUpdateScript); err != nil {
		_ = helper.Close()
		_ = os.Remove(helperPath)
		_ = os.Remove(stagedBinary)
		return false, fmt.Errorf("cannot write Windows update helper: %w", err)
	}
	if err := helper.Close(); err != nil {
		_ = os.Remove(helperPath)
		_ = os.Remove(stagedBinary)
		return false, fmt.Errorf("cannot close Windows update helper: %w", err)
	}

	arguments, err := json.Marshal(os.Args[1:])
	if err != nil {
		_ = os.Remove(helperPath)
		_ = os.Remove(stagedBinary)
		return false, fmt.Errorf("cannot preserve agent arguments for restart: %w", err)
	}
	encodedArguments := base64.StdEncoding.EncodeToString(arguments)
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", helperPath,
		executablePath, stagedBinary, strconv.Itoa(os.Getpid()), encodedArguments)
	if err := command.Start(); err != nil {
		_ = os.Remove(helperPath)
		_ = os.Remove(stagedBinary)
		return false, fmt.Errorf("cannot start Windows update helper: %w", err)
	}
	if err := command.Process.Release(); err != nil {
		return false, fmt.Errorf("cannot detach Windows update helper: %w", err)
	}
	return true, nil
}
