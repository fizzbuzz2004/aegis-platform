//go:build darwin

package probes

import (
	"context"
	"os/exec"
	"strings"
)

func init() {
	Register("security_probe", RunEndpointSecurityProbe)
}

func RunEndpointSecurityProbe(ctx context.Context, pCtx ProbeContext) []Finding {
	var findings []Finding

	// Check 1: EDR Agent / Security Daemon Audit
	edrProcesses := []string{"falcon-sensor", "SentinelAgent", "com.microsoft.wdav", "jamf"}
	out, err := exec.CommandContext(ctx, "ps", "-ax").Output()

	foundEDR := ""
	if err == nil {
		psOutput := string(out)
		for _, proc := range edrProcesses {
			if strings.Contains(psOutput, proc) {
				foundEDR = proc
				break
			}
		}
	}

	if foundEDR != "" {
		findings = append(findings, Finding{
			Status:     "PASS",
			Code:       "MACOS_EDR_ACTIVE",
			Severity:   "INFO",
			Message:    "Aktiver macOS EDR Agent erkannt: " + foundEDR,
			Compliance: []string{"ISO27001:A.8.7", "NIS2:Art21.2.g"},
		})
	} else {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "MACOS_NO_EDR",
			Severity:   "HIGH",
			Message:    "Kein bekannter Endpoint Security Agent auf macOS aktiv",
			Compliance: []string{"ISO27001:A.8.7", "NIS2:Art21.2.g"},
		})
	}

	// Check 2: Gatekeeper System Protection
	spctlCmd := exec.CommandContext(ctx, "spctl", "--status")
	if err := spctlCmd.Run(); err == nil {
		findings = append(findings, Finding{
			Status:     "PASS",
			Code:       "GATEKEEPER_ACTIVE",
			Severity:   "INFO",
			Message:    "macOS Gatekeeper ist aktiv.",
			Compliance: []string{"ISO27001:A.8.9"},
		})
	} else {
		findings = append(findings, Finding{
			Status:     "FAIL",
			Code:       "GATEKEEPER_DISABLED",
			Severity:   "HIGH",
			Message:    "macOS Gatekeeper ist deaktiviert!",
			Compliance: []string{"ISO27001:A.8.9"},
		})
	}

	return findings
}
