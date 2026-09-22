package probes

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func RunEncryptionProbe(ctx ProbeContext) []Finding {
	var findings []Finding

	switch ctx.OSName {
	case "windows":
		cmd := exec.Command("manage-bde.exe", "-status", "C:")
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()

		if err != nil {
			findings = append(findings, Finding{
				Status:     "WARN",
				Code:       "BITLOCKER_CHECK_FAILED",
				Severity:   "MEDIUM",
				Message:    fmt.Sprintf("BitLocker Status konnte nicht ermittelt werden (Rechte prüfen): %v", err),
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1"},
			})
			return findings
		}

		output := out.String()
		if strings.Contains(output, "Protection On") || strings.Contains(output, "Der Schutz ist aktiviert") {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "BITLOCKER_ENABLED",
				Severity:   "INFO",
				Message:    "BitLocker Laufwerksverschlüsselung auf Systemlaufwerk C: ist aktiv.",
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1", "NIS2:Art21.2.h"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "BITLOCKER_DISABLED",
				Severity:   "HIGH",
				Message:    "BitLocker Schutz auf Systemlaufwerk C: IST DEAKTIVIERT!",
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1", "NIS2:Art21.2.h"},
			})
		}

	case "linux":
		cmd := exec.Command("lsblk", "-o", "NAME,TYPE,FSTYPE")
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()

		if err != nil {
			findings = append(findings, Finding{
				Status:     "WARN",
				Code:       "LUKS_CHECK_FAILED",
				Severity:   "MEDIUM",
				Message:    fmt.Sprintf("LUKS/dm-crypt Status konnte nicht ermittelt werden: %v", err),
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1"},
			})
			return findings
		}

		output := out.String()
		if strings.Contains(output, "crypto_LUKS") || strings.Contains(output, "crypt") {
			findings = append(findings, Finding{
				Status:     "PASS",
				Code:       "LUKS_ENABLED",
				Severity:   "INFO",
				Message:    "LUKS/dm-crypt Verschlüsselung auf mindestens einer Partition erkannt.",
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1", "NIS2:Art21.2.h"},
			})
		} else {
			findings = append(findings, Finding{
				Status:     "FAIL",
				Code:       "LUKS_DISABLED",
				Severity:   "HIGH",
				Message:    "Keine LUKS-verschlüsselten Blockgeräte im System gefunden.",
				Compliance: []string{"DSGVO:Art32", "ISO27001:A.8.24", "BSI:CON.1", "NIS2:Art21.2.h"},
			})
		}
	}

	return findings
}
