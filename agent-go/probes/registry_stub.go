//go:build !windows

package probes

import "context"

func init() {
	Register("registry_probe", RunRegistryAudit)
}

func RunRegistryAudit(_ context.Context, _ ProbeContext) []Finding {
	return []Finding{
		{
			Status:     "INFO",
			Code:       "REGISTRY_SKIPPED",
			Severity:   "INFO",
			Message:    "Registry-Audit auf Nicht-Windows-System übersprungen.",
			Compliance: []string{},
		},
	}
}
