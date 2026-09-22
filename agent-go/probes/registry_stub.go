//go:build !windows

package probes

func RunRegistryAudit(ctx ProbeContext) []Finding {
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
