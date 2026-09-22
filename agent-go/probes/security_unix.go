//go:build !windows

package probes

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func RunEndpointSecurityProbe(ctx ProbeContext) []Finding {
	var findings []Finding
	agents := []string{"falcon-sensor", "sentineld", "mdatp", "clamd"}
	foundAgent := false

	cmd := exec.Command("ps", "aux")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		psOut := out.String()
		for _, agent := range agents {
			if strings.Contains(psOut, agent) {
				foundAgent = true
				findings = append(findings, Finding{
					Status:     "PASS",
					Code:       "EDR_AGENT_ACTIVE",
					Severity:   "INFO",
					Message:    fmt.Sprintf("Aktiver Endpoint Security Agent erkannt: %s", agent),
					Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7", "DSGVO:Art32"},
				})
				break
			}
		}
	}

	if !foundAgent {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "NO_EDR_AGENT_FOUND",
			Severity:   "HIGH",
			Message:    "Kein bekannter EDR/AV-Prozess im Speicher gefunden.",
			Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7", "DSGVO:Art32"},
		})
	}
	return findings
}
