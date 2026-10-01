//go:build !windows

package probes

import (
	"context"
	"os"
)

func init() {
	Register("updates_probe", RunUpdatesProbe)
}

func RunUpdatesProbe(_ context.Context, _ ProbeContext) []Finding {
	var findings []Finding

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

	return findings
}
