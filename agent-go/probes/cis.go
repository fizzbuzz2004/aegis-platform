package probes

import (
	"context"
	"os"
	"strings"
)

func init() {
	Register("cis_hardening", func(ctx context.Context, pCtx ProbeContext) []Finding {
		return RunCISHardening(pCtx)
	})
}

func RunCISHardening(ctx ProbeContext) []Finding {
	var findings []Finding
	if ctx.OSName == "linux" {
		data, err := os.ReadFile("/etc/ssh/sshd_config")
		if err != nil {
			return []Finding{{
				Status:     "WARN",
				Code:       "SSH_AUDIT_ERROR",
				Severity:   "MEDIUM",
				Message:    "sshd_config konnte nicht gelesen werden",
				Compliance: []string{"ISO27001:A.8.9"},
			}}
		}
		if strings.Contains(string(data), "PermitRootLogin yes") {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "SSH_ROOT_ALLOWED",
				Severity:   "HIGH",
				Message:    "SSH PermitRootLogin ist aktiviert",
				Compliance: []string{"ISO27001:A.8.9", "NIS2:Art21.2.i"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "SSH_ROOT_DISABLED",
				Severity:   "INFO",
				Message:    "SSH Root-Login ist deaktiviert",
				Compliance: []string{"ISO27001:A.8.9"},
			})
		}
	}
	return findings
}
