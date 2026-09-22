package probes

import (
	"fmt"
	"os"
	"time"
)

func RunBackupProbe(ctx ProbeContext) []Finding {
	var findings []Finding
	var paths []string

	if ctx.OSName == "windows" {
		paths = []string{`C:\BackupLogs\latest.log`, `C:\ProgramData\Veeam\Backup.log`}
	} else {
		paths = []string{"/var/log/backup.log", "/var/log/syslog"}
	}

	maxAge := 48 * time.Hour
	now := time.Now()

	for _, path := range paths {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			findings = append(findings, Finding{
				Status:     "WARN",
				Code:       "BACKUP_NOT_FOUND",
				Severity:   "MEDIUM",
				Message:    fmt.Sprintf("Backup-Protokollpfad '%s' nicht gefunden.", path),
				Compliance: []string{"ISO27001:A.8.13"},
			})
			continue
		}

		if now.Sub(info.ModTime()) > maxAge {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "BACKUP_STALE",
				Severity:   "HIGH",
				Message:    fmt.Sprintf("Backup-Log '%s' ist veraltet (> %d Std. alt).", path, int(now.Sub(info.ModTime()).Hours())),
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "BACKUP_OK",
				Severity:   "INFO",
				Message:    fmt.Sprintf("Backup-Log '%s' ist aktuell.", path),
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		}
	}

	return findings
}
