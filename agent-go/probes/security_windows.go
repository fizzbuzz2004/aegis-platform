//go:build windows

package probes

import (
	"context"

	"golang.org/x/sys/windows/registry"
)

func init() {
	Register("security_probe", RunEndpointSecurityProbe)
}

func RunEndpointSecurityProbe(_ context.Context, ctx ProbeContext) []Finding {
	var findings []Finding

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, registry.READ)
	if err != nil {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "AV_STATUS_UNKNOWN",
			Severity:   "MEDIUM",
			Message:    "Windows Defender Registry-Key konnte nicht gelesen werden.",
			Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7"},
		})
		return findings
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue("DisableRealtimeMonitoring")
	if err != nil || val == 0 {
		findings = append(findings, Finding{
			Status:     "PASS",
			Code:       "AV_REALTIME_ACTIVE",
			Severity:   "INFO",
			Message:    "Windows Defender Echtzeitschutz ist aktiv (Registry-Check).",
			Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7", "DSGVO:Art32"},
		})
	} else {
		findings = append(findings, Finding{
			Status:     "FAIL",
			Code:       "AV_REALTIME_DISABLED",
			Severity:   "HIGH",
			Message:    "Windows Defender Echtzeitschutz IST DEAKTIVIERT (DisableRealtimeMonitoring=1)!",
			Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7", "DSGVO:Art32"},
		})
	}

	return findings
}
