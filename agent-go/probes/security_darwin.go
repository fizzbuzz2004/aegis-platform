//go:build darwin

package probes

import "context"

func RunEndpointSecurityProbe(ctx context.Context, pCtx ProbeContext) []Finding {
	return []Finding{
		{
			Status:     "INFO",
			Code:       "EDR_UNSUPPORTED_OS",
			Severity:   "INFO",
			Message:    "Endpoint Security Probe auf macOS (Darwin) nicht aktiv implementiert.",
			Compliance: []string{"ISO27001:A.8.7"},
		},
	}
}
