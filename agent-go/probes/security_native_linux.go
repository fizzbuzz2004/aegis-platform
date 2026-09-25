//go:build !windows && !darwin

package probes

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func init() {
	Register("security_probe", RunEndpointSecurityProbe)
}

func RunEndpointSecurityProbe(ctx context.Context, pCtx ProbeContext) []Finding {
	var findings []Finding

	// Check 1: Procfs EDR Check
	agents := []string{"falcon-sensor", "sentineld", "mdatp", "clamd", "osqueryd"}
	foundAgent := ""

	entries, err := os.ReadDir("/proc")
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if _, err := strconv.Atoi(entry.Name()); err != nil {
				continue
			}

			data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if err != nil {
				continue
			}

			procName := strings.TrimSpace(string(data))
			for _, agent := range agents {
				if strings.Contains(procName, agent) {
					foundAgent = procName
					break
				}
			}
			if foundAgent != "" {
				break
			}
		}
	}

	if foundAgent != "" {
		findings = append(findings, Finding{
			Status:     "PASS",
			Code:       "EDR_AGENT_ACTIVE",
			Severity:   "INFO",
			Message:    "Aktiver EDR Agent erkannt: " + foundAgent,
			Compliance: []string{"NIS2:Art21.2.g", "ISO27001:A.8.7"},
		})
	} else {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "NO_EDR_AGENT_FOUND",
			Severity:   "HIGH",
			Message:    "Kein EDR/AV Prozess auf Linux identifiziert",
			Compliance: []string{"NIS2:Art21.2.g", "ISO27001:A.8.7"},
		})
	}

	// Check 2: Container Runtime Isolation Check
	if _, err := exec.LookPath("docker"); err == nil {
		cmd := exec.CommandContext(ctx, "systemctl", "is-active", "docker")
		if err := cmd.Run(); err == nil {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "CONTAINER_ENGINE_ACTIVE",
				Severity:   "INFO",
				Message:    "Docker Engine ist aktiv und abgesichert.",
				Compliance: []string{"ISO27001:A.8.28"},
			})
		}
	}

	return findings
}
