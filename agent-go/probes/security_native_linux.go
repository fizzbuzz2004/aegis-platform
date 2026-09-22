//go:build !windows

package probes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func RunEndpointSecurityProbe(ctx context.Context, pCtx ProbeContext) (findings []Finding) {
	defer func() {
		if r := recover(); r != nil {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "PANIC_RECOVERED",
				Severity:   "CRITICAL",
				Message:    fmt.Sprintf("Kritischer Fehler (Panic) in Linux SecurityProbe abgefangen: %v", r),
				Compliance: []string{"ISO27001:A.8.7"},
			})
		}
	}()

	done := make(chan []Finding, 1)
	agents := []string{"falcon-sensor", "sentineld", "mdatp", "clamd", "osqueryd"}

	go func() {
		var localFindings []Finding
		foundAgent := false
		foundName := ""

		entries, err := os.ReadDir("/proc")
		if err != nil {
			localFindings = append(localFindings, Finding{
				Status:     "WARN",
				Code:       "PROCFS_READ_FAILED",
				Severity:   "HIGH",
				Message:    fmt.Errorf("Fehler beim Lesen von /proc: %w", err).Error(),
				Compliance: []string{"NIS2:Art21.2.g"},
			})
			done <- localFindings
			return
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if _, err := strconv.Atoi(entry.Name()); err != nil {
				continue
			}

			commPath := filepath.Join("/proc", entry.Name(), "comm")
			data, err := os.ReadFile(commPath)
			if err != nil {
				continue
			}

			procName := strings.TrimSpace(string(data))
			for _, agent := range agents {
				if strings.Contains(procName, agent) {
					foundAgent = true
					foundName = procName
					break
				}
			}
			if foundAgent {
				break
			}
		}

		if foundAgent {
			localFindings = append(localFindings, Finding{
				Status:     "PASS",
				Code:       "EDR_AGENT_ACTIVE",
				Severity:   "INFO",
				Message:    fmt.Sprintf("Aktiver Endpoint Security Agent erkannt (via procfs): %s", foundName),
				Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7", "DSGVO:Art32"},
			})
		} else {
			localFindings = append(localFindings, Finding{
				Status:     "WARN",
				Code:       "NO_EDR_AGENT_FOUND",
				Severity:   "HIGH",
				Message:    "Kein bekannter EDR/AV-Prozess im Speicher (procfs) gefunden.",
				Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7", "DSGVO:Art32"},
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
			Message:    "Timeout (10s) bei der procfs-Abfrage überschritten.",
			Compliance: []string{"ISO27001:A.8.7"},
		}}
	case res := <-done:
		return res
	}
}
