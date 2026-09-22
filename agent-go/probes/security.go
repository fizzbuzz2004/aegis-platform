package probes

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func RunEndpointSecurityProbe(ctx ProbeContext) []Finding {
	var findings []Finding

	switch ctx.OSName {
	case "windows":
		psScript := `
		try {
			$mp = Get-MpComputerStatus -ErrorAction Stop
			$rt = $mp.RealTimeProtectionEnabled
			$age = $mp.AntivirusSignatureAge
			Write-Output "DEFENDER_OK|RealTime:$rt|SigAge:$age"
		} catch {
			Write-Output "DEFENDER_ERROR|$($_.Exception.Message)"
		}
		`
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()

		if err != nil {
			findings = append(findings, Finding{
				Status:     "WARN",
				Code:       "AV_STATUS_UNKNOWN",
				Severity:   "MEDIUM",
				Message:    fmt.Sprintf("Endpoint Security Status konnte nicht abgefragt werden: %v", err),
				Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7"},
			})
			return findings
		}

		res := strings.TrimSpace(out.String())
		if strings.HasPrefix(res, "DEFENDER_OK") {
			if strings.Contains(res, "RealTime:True") {
				findings = append(findings, Finding{
					Status:     "PASS",
					Code:       "AV_REALTIME_ACTIVE",
					Severity:   "INFO",
					Message:    "Windows Defender Echtzeitschutz ist aktiv (" + res + ").",
					Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7", "DSGVO:Art32"},
				})
			} else {
				findings = append(findings, Finding{
					Status:     "FAIL",
					Code:       "AV_REALTIME_DISABLED",
					Severity:   "HIGH",
					Message:    "Windows Defender Echtzeitschutz IST DEAKTIVIERT!",
					Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7", "DSGVO:Art32"},
				})
			}
		} else {
			findings = append(findings, Finding{
				Status:     "WARN",
				Code:       "AV_CHECK_ERROR",
				Severity:   "MEDIUM",
				Message:    "Fehler beim Auslesen des Antivirus-Status: " + res,
				Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7"},
			})
		}

	case "linux":
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
				Message:    "Kein bekannter EDR/AV-Prozess (Falcon, SentinelOne, mdatp, ClamAV) im Speicher gefunden.",
				Compliance: []string{"NIS2:Art21.2.g", "BSI:SYS.1.1.A9", "ISO27001:A.8.7", "DSGVO:Art32"},
			})
		}
	}

	return findings
}
