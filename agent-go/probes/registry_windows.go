//go:build windows

package probes

import (
	"context"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func init() {
	Register("registry_probe", RunRegistryAudit)
}

func RunRegistryAudit(_ context.Context, _ ProbeContext) []Finding {
	var findings []Finding

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.READ)
	if err != nil {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "REGISTRY_OPEN_FAILED",
			Severity:   "MEDIUM",
			Message:    "HKLM Autostart-Schlüssel konnte nicht gelesen werden: " + err.Error(),
			Compliance: []string{"ISO27001:A.8.9"},
		})
		return findings
	}
	defer key.Close()

	names, err := key.ReadValueNames(-1)
	if err != nil {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "REGISTRY_READ_FAILED",
			Severity:   "MEDIUM",
			Message:    "Fehler beim Auslesen der Autostart-Einträge: " + err.Error(),
			Compliance: []string{"ISO27001:A.8.9"},
		})
		return findings
	}

	for _, valName := range names {
		val, _, err := key.GetStringValue(valName)
		if err != nil {
			continue
		}

		if strings.Contains(val, "AppData") || strings.Contains(val, "Temp") {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "SUSPICIOUS_AUTOSTART",
				Severity:   "HIGH",
				Message:    "Verdächtiger Autostart-Pfad in HKLM: " + valName + " -> " + val,
				Compliance: []string{"ISO27001:A.8.9", "NIS2:Art21.2.g"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "AUTOSTART_OK",
				Severity:   "INFO",
				Message:    "Autostart-Eintrag verifiziert: " + valName,
				Compliance: []string{"ISO27001:A.8.9"},
			})
		}
	}

	return findings
}
