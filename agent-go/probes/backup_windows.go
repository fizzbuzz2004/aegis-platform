//go:build windows

package probes

import (
	"os"
	"time"

	"golang.org/x/sys/windows/registry"
)

func RunBackupProbe(ctx ProbeContext) []Finding {
	var findings []Finding

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\VeeamBackupSvc`, registry.READ)
	if err != nil {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "BACKUP_SVC_NOT_FOUND",
			Severity:   "MEDIUM",
			Message:    "Veeam Backup Service in der Registry nicht gefunden.",
			Compliance: []string{"ISO27001:A.8.13"},
		})
	} else {
		startType, _, _ := key.GetIntegerValue("Start")
		key.Close()

		if startType == 4 { // 4 = Disabled
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "BACKUP_SVC_DISABLED",
				Severity:   "HIGH",
				Message:    "Veeam Backup Service ist deaktiviert!",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "BACKUP_SVC_OK",
				Severity:   "INFO",
				Message:    "Veeam Backup Service ist ordnungsgemäß registriert.",
				Compliance: []string{"ISO27001:A.8.13"},
			})
		}
	}

	path := `C:\ProgramData\Veeam\Backup.log`
	if info, err := os.Stat(path); err == nil {
		if time.Since(info.ModTime()) > 48*time.Hour {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "BACKUP_STALE",
				Severity:   "HIGH",
				Message:    "Backup-Log ist veraltet (> 48 Std. alt).",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "BACKUP_OK",
				Severity:   "INFO",
				Message:    "Backup-Log ist aktuell.",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		}
	}

	return findings
}
