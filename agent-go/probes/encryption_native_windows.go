//go:build windows

package probes

import (
	"context"
	"fmt"

	"github.com/yusufpapurcu/wmi"
)

type Win32_EncryptableVolume struct {
	DeviceID         string
	DriveLetter      string
	ProtectionStatus uint32
}

func init() {
	Register("encryption_probe", RunEncryptionProbe)
}

func RunEncryptionProbe(ctx context.Context, pCtx ProbeContext) (findings []Finding) {
	defer func() {
		if r := recover(); r != nil {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "PANIC_RECOVERED",
				Severity:   "CRITICAL",
				Message:    fmt.Sprintf("Kritischer Fehler (Panic) in EncryptionProbe abgefangen: %v", r),
				Compliance: []string{"ISO27001:A.8.24"},
			})
		}
	}()

	done := make(chan []Finding, 1)

	go func() {
		var localFindings []Finding
		var volumes []Win32_EncryptableVolume

		query := "SELECT DeviceID, DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = 'C:'"
		err := wmi.QueryNamespace(query, &volumes, `root\CIMv2\Security\MicrosoftVolumeEncryption`)

		if err != nil {
			localFindings = append(localFindings, Finding{
				Status:     "WARN",
				Code:       "BITLOCKER_WMI_FAILED",
				Severity:   "MEDIUM",
				Message:    fmt.Sprintf("BitLocker WMI-Abfrage fehlgeschlagen (Admin-Rechte prüfen): %v", err),
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1"},
			})
			done <- localFindings
			return
		}

		if len(volumes) == 0 {
			localFindings = append(localFindings, Finding{
				Status:     "FAIL",
				Code:       "BITLOCKER_NO_DRIVE",
				Severity:   "HIGH",
				Message:    "Systemlaufwerk C: konnte via WMI nicht zur Verschlüsselungsprüfung gefunden werden.",
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1", "NIS2:Art21.2.h"},
			})
			done <- localFindings
			return
		}

		vol := volumes[0]
		if vol.ProtectionStatus == 1 {
			localFindings = append(localFindings, Finding{
				Status:     "PASS",
				Code:       "BITLOCKER_ENABLED",
				Severity:   "INFO",
				Message:    "BitLocker Laufwerksverschlüsselung auf Systemlaufwerk C: ist aktiv (Native WMI Check).",
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1", "NIS2:Art21.2.h"},
			})
		} else {
			localFindings = append(localFindings, Finding{
				Status:     "FAIL",
				Code:       "BITLOCKER_DISABLED",
				Severity:   "HIGH",
				Message:    "BitLocker Schutz auf Systemlaufwerk C: IST DEAKTIVIERT!",
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1", "NIS2:Art21.2.h"},
			})
		}
		done <- localFindings
	}()

	select {
	case <-ctx.Done():
		return []Finding{{
			Status:     "FAIL",
			Code:       "PROBE_TIMEOUT",
			Severity:   "HIGH",
			Message:    "Timeout (10s) bei der WMI-Abfrage überschritten.",
			Compliance: []string{"ISO27001:A.8.24"},
		}}
	case res := <-done:
		return res
	}
}
