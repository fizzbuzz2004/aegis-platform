package probes

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
)

func init() {
	Register("firewall_status", runFirewallStatus)
}

func runFirewallStatus(ctx context.Context, _ ProbeContext) []Finding {
	switch runtime.GOOS {
	case "windows":
		command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			"$p = Get-NetFirewallProfile; if ($p.Count -eq 0 -or ($p | Where-Object { -not $_.Enabled }).Count -gt 0) { exit 1 }")
		if err := command.Run(); err == nil {
			return firewallFinding("PASS", "FIREWALL_ACTIVE", "INFO", "Die Host-Firewall ist aktiv.")
		}
		if ctx.Err() != nil {
			return firewallFinding("WARN", "FIREWALL_CHECK_INTERRUPTED", "MEDIUM", "Firewall-Prüfung wurde abgebrochen.")
		}
		return firewallFinding("FAIL", "FIREWALL_NOT_ACTIVE", "HIGH", "Mindestens ein Windows-Firewall-Profil ist deaktiviert oder die Prüfung ist fehlgeschlagen.")
	case "linux":
		return runLinuxFirewallStatus(ctx)
	default:
		return firewallFinding("WARN", "FIREWALL_CHECK_UNSUPPORTED", "LOW", "Firewall-Prüfung auf diesem Betriebssystem nicht unterstützt.")
	}
}

func runLinuxFirewallStatus(ctx context.Context) []Finding {
	checksRun := 0
	checkFailed := false
	inactiveFirewallFound := false

	if ufwPath, err := exec.LookPath("ufw"); err == nil {
		checksRun++
		output, commandErr := exec.CommandContext(ctx, ufwPath, "status").CombinedOutput()
		if ctx.Err() != nil {
			return firewallFinding("WARN", "FIREWALL_CHECK_INTERRUPTED", "MEDIUM", "Firewall-Prüfung wurde abgebrochen.")
		}
		active, known := parseUFWStatus(string(output))
		if commandErr != nil || !known {
			checkFailed = true
		} else if active {
			return firewallFinding("PASS", "FIREWALL_ACTIVE", "INFO", "UFW meldet eine aktive Host-Firewall.")
		} else {
			inactiveFirewallFound = true
		}
	}

	if firewalldPath, err := exec.LookPath("firewall-cmd"); err == nil {
		checksRun++
		output, commandErr := exec.CommandContext(ctx, firewalldPath, "--state").CombinedOutput()
		if ctx.Err() != nil {
			return firewallFinding("WARN", "FIREWALL_CHECK_INTERRUPTED", "MEDIUM", "Firewall-Prüfung wurde abgebrochen.")
		}
		active, known := parseFirewalldState(string(output))
		if !known || (commandErr != nil && active) {
			checkFailed = true
		} else if active {
			return firewallFinding("PASS", "FIREWALL_ACTIVE", "INFO", "firewalld meldet eine aktive Host-Firewall.")
		} else {
			inactiveFirewallFound = true
		}
	}

	if checksRun == 0 {
		return firewallFinding("WARN", "FIREWALL_CHECK_UNAVAILABLE", "MEDIUM", "Weder ufw noch firewalld ist verfügbar; Firewall-Status konnte nicht ermittelt werden.")
	}
	if checkFailed {
		return firewallFinding("WARN", "FIREWALL_CHECK_INDETERMINATE", "MEDIUM", "Firewall-Status konnte nicht zuverlässig ermittelt werden; bitte Agent-Berechtigungen und Firewall-Werkzeuge prüfen.")
	}
	if inactiveFirewallFound {
		return firewallFinding("FAIL", "FIREWALL_NOT_ACTIVE", "HIGH", "UFW und firewalld melden keine aktive Host-Firewall.")
	}
	return firewallFinding("WARN", "FIREWALL_CHECK_INDETERMINATE", "MEDIUM", "Firewall-Status konnte nicht zuverlässig ermittelt werden.")
}

func parseUFWStatus(output string) (active bool, known bool) {
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "Status") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "active":
			return true, true
		case "inactive":
			return false, true
		}
	}
	return false, false
}

func parseFirewalldState(output string) (active bool, known bool) {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "running":
		return true, true
	case "not running", "not-running":
		return false, true
	default:
		return false, false
	}
}

func firewallFinding(status, code, severity, message string) []Finding {
	return []Finding{{
		Status:     status,
		Code:       code,
		Severity:   severity,
		Message:    message,
		Compliance: []string{"NIS2:Art21.2.e", "ISO27001:A.8.20"},
	}}
}
