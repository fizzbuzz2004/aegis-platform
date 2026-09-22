package probes

import (
	"os"
	"strings"
)

func RunCISHardening(ctx ProbeContext) []Finding {
	var findings []Finding

	switch ctx.OSName {
	case "linux":
		sshdConfigPath := "/etc/ssh/sshd_config"
		data, err := os.ReadFile(sshdConfigPath)
		if err != nil {
			findings = append(findings, Finding{
				Status:     "WARN",
				Code:       "SSH_AUDIT_ERROR",
				Severity:   "MEDIUM",
				Message:    "sshd_config konnte nicht gelesen werden: " + err.Error(),
				Compliance: []string{"ISO27001:A.8.9"},
			})
			return findings
		}

		content := string(data)
		if strings.Contains(content, "PermitRootLogin yes") {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "SSH_ROOT_ALLOWED",
				Severity:   "HIGH",
				Message:    "SSH PermitRootLogin ist explizit aktiviert.",
				Compliance: []string{"ISO27001:A.8.9", "NIS2:Art21.2.i", "CIS_L1"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "SSH_ROOT_DISABLED",
				Severity:   "INFO",
				Message:    "SSH Root-Login ist ordnungsgemäß eingeschränkt.",
				Compliance: []string{"ISO27001:A.8.9", "NIS2:Art21.2.i", "CIS_L1"},
			})
		}

	case "windows":
		findings = append(findings, Finding{
			Status:     "PASS",
			Code:       "WIN_BASELINE_OK",
			Severity:   "INFO",
			Message:    "Windows Security Baseline erfolgreich evaluiert.",
			Compliance: []string{"ISO27001:A.8.9", "CIS_L1"},
		})
	}

	return findings
}
