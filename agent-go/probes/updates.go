package probes

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func RunUpdatesProbe(ctx ProbeContext) []Finding {
	var findings []Finding

	switch ctx.OSName {
	case "windows":
		checkScript := `
		$reboot = $false
		$reasons = @()
		if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reboot = $true; $reasons += 'CBS RebootPending' }
		if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reboot = $true; $reasons += 'WindowsUpdate RebootRequired' }
		if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue)) { $reboot = $true; $reasons += 'PendingFileRenameOperations' }
		if ($reboot) { Write-Output "REBOOT_REQUIRED: $($reasons -join ', ')" } else { Write-Output "NO_REBOOT" }
		`

		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", checkScript)
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()

		if err == nil {
			outStr := strings.TrimSpace(out.String())
			if strings.HasPrefix(outStr, "REBOOT_REQUIRED") {
				findings = append(findings, Finding{
					Status:     "WARN",
					Code:       "PENDING_REBOOT",
					Severity:   "MEDIUM",
					Message:    fmt.Sprintf("System erfordert einen Neustart für ausstehende Updates: %s", outStr),
					Compliance: []string{"NIS2:Art21.2.e", "BSI:SYS.1.1.A12", "ISO27001:A.8.8"},
				})
			} else {
				findings = append(findings, Finding{
					Status:     "PASS",
					Code:       "NO_PENDING_REBOOT",
					Severity:   "INFO",
					Message:    "Kein ausstehender Systemneustart erkannt.",
					Compliance: []string{"NIS2:Art21.2.e", "BSI:SYS.1.1.A12", "ISO27001:A.8.8"},
				})
			}
		} else {
			findings = append(findings, Finding{
				Status:     "WARN",
				Code:       "UPDATE_CHECK_FAILED",
				Severity:   "LOW",
				Message:    fmt.Sprintf("Fehler bei der Abfrage des Reboot-Status: %v", err),
				Compliance: []string{"NIS2:Art21.2.e", "ISO27001:A.8.8"},
			})
		}

	case "linux":
		if _, err := os.Stat("/var/run/reboot-required"); err == nil {
			findings = append(findings, Finding{
				Status:     "WARN",
				Code:       "PENDING_REBOOT",
				Severity:   "MEDIUM",
				Message:    "Datei /var/run/reboot-required vorhanden. Ausstehender Systemneustart nach Kernel-/Paketupdates.",
				Compliance: []string{"NIS2:Art21.2.e", "BSI:SYS.1.1.A12", "ISO27001:A.8.8"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "NO_PENDING_REBOOT",
				Severity:   "INFO",
				Message:    "Kein ausstehender Systemneustart erkannt.",
				Compliance: []string{"NIS2:Art21.2.e", "BSI:SYS.1.1.A12", "ISO27001:A.8.8"},
			})
		}
	}

	return findings
}
