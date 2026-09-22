//go:build !windows

package probes

import (
	"os/exec"
)

func RunBackupProbe(ctx ProbeContext) []Finding {
	var findings []Finding

	cmd := exec.Command("systemctl", "is-active", "backup.service")
	if err := cmd.Run(); err == nil {
		findings = append(findings, Finding{
			Status:     "PASS",
			Code:       "BACKUP_TIMER_OK",
			Severity:   "INFO",
			Message:    "Systemd backup.service ist aktiv.",
			Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
		})
	} else {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "BACKUP_TIMER_FAIL",
			Severity:   "MEDIUM",
			Message:    "Systemd backup.service nicht aktiv oder nicht vorhanden.",
			Compliance: []string{"ISO27001:A.8.13"},
		})
	}

	return findings
}
