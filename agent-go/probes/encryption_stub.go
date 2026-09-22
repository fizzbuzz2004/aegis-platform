//go:build !windows

package probes

import "context"

func RunEncryptionProbe(ctx context.Context, pCtx ProbeContext) []Finding {
	return []Finding{
		{
			Status:     "INFO",
			Code:       "ENCRYPTION_UNSUPPORTED_OS",
			Severity:   "INFO",
			Message:    "Verschlüsselungs-Probe für dieses Betriebssystem als Stub (nicht nativ erforderlich/implementiert).",
			Compliance: []string{"ISO27001:A.8.24"},
		},
	}
}
