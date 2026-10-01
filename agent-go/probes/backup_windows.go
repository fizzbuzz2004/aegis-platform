//go:build windows

package probes

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/windows/registry"
)

func init() {
	Register("backup_probe", RunBackupProbe)
}

func RunBackupProbe(_ context.Context, _ ProbeContext) []Finding {
	var findings []Finding

	// --- 1. Veeam Backup Service Check ---
	veeamKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\VeeamBackupSvc`, registry.READ)
	if err != nil {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "BACKUP_VEEAM_NOT_FOUND",
			Severity:   "MEDIUM",
			Message:    "Veeam Backup Service in der Registry nicht gefunden.",
			Compliance: []string{"ISO27001:A.8.13"},
		})
	} else {
		startType, _, _ := veeamKey.GetIntegerValue("Start")
		veeamKey.Close()

		if startType == 4 { // 4 = Disabled
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "BACKUP_VEEAM_DISABLED",
				Severity:   "HIGH",
				Message:    "Veeam Backup Service ist deaktiviert!",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "BACKUP_VEEAM_OK",
				Severity:   "INFO",
				Message:    "Veeam Backup Service ist ordnungsgemäß registriert und aktiv.",
				Compliance: []string{"ISO27001:A.8.13"},
			})
		}
	}

	// Veeam Logfile Staleness Check
	veeamLogPath := `C:\ProgramData\Veeam\Backup.log`
	if info, err := os.Stat(veeamLogPath); err == nil {
		if time.Since(info.ModTime()) > 48*time.Hour {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "BACKUP_VEEAM_STALE",
				Severity:   "HIGH",
				Message:    "Veeam Backup-Log ist veraltet (> 48 Std. alt).",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "BACKUP_VEEAM_LOG_OK",
				Severity:   "INFO",
				Message:    "Veeam Backup-Log ist aktuell.",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		}
	}

	// --- 2. Acronis Cyber Protect / Backup Check ---
	acronisKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\MMS`, registry.READ)
	if err == nil {
		startType, _, _ := acronisKey.GetIntegerValue("Start")
		acronisKey.Close()

		if startType == 4 {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "BACKUP_ACRONIS_DISABLED",
				Severity:   "HIGH",
				Message:    "Acronis Managed Machine Service ist deaktiviert!",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "BACKUP_ACRONIS_OK",
				Severity:   "INFO",
				Message:    "Acronis Managed Machine Service ist aktiv.",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		}
	}

	// --- 3. Datto Endpoint Backup Check ---
	dattoKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\DattoBackupAgent`, registry.READ)
	if err == nil {
		startType, _, _ := dattoKey.GetIntegerValue("Start")
		dattoKey.Close()

		if startType == 4 {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "BACKUP_DATTO_DISABLED",
				Severity:   "HIGH",
				Message:    "Datto Backup Agent ist deaktiviert!",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "BACKUP_DATTO_OK",
				Severity:   "INFO",
				Message:    "Datto Backup Agent registriert und aktiv.",
				Compliance: []string{"ISO27001:A.8.13", "NIS2:Art21.2.c"},
			})
		}
	}

	return findings
}
