package core

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"runtime"
)

// AttemptRemediation prüft, ob automatische Remediation erlaubt ist und führt diese aus.
func AttemptRemediation(ctx context.Context, autoRemediate bool, remediationMode string, moduleName string, code string) (bool, string, error) {
	if !autoRemediate {
		return false, "Remediation im Dry-Run-Modus (nur Logging, Auto-Remediation deaktiviert)", nil
	}

	// Risiko 1: Strikte Unterscheidung des Auto-Remediation-Modus (audit vs enforce)
	if remediationMode == "audit" {
		log.Printf("[REMEDIATION AUDIT] Audit-Modus aktiv für Modul %s / Code %s. Keine automatischen Änderungen.", moduleName, code)
		return false, fmt.Sprintf("Audit-Modus aktiv: Drift für %s (%s) erkannt, aber keine automatische Durchsetzung erfolgt.", moduleName, code), nil
	}

	switch moduleName {
	case "firewall_status":
		if code == "FIREWALL_NOT_ACTIVE" {
			return remediateFirewall(ctx)
		}
	case "security_probe":
		if code == "AV_REALTIME_DISABLED" && runtime.GOOS == "windows" {
			return remediateWindowsDefender(ctx)
		}
	case "cis_hardening":
		if code == "SSH_ROOT_ALLOWED" && runtime.GOOS == "linux" {
			return remediateSSHRootLogin(ctx)
		}
	}
	return false, "", fmt.Errorf("keine automatische Remediation für Modul %s / Code %s definiert", moduleName, code)
}

func remediateFirewall(ctx context.Context) (bool, string, error) {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
		if err := cmd.Run(); err != nil {
			return false, "", fmt.Errorf("Windows-Firewall konnte nicht aktiviert werden: %w", err)
		}
		return true, "Windows-Firewall-Profile (Domain, Public, Private) wurden automatisch aktiviert.", nil
	case "linux":
		if path, err := exec.LookPath("ufw"); err == nil {
			cmd := exec.CommandContext(ctx, path, "--force", "enable")
			if err := cmd.Run(); err != nil {
				return false, "", fmt.Errorf("UFW konnte nicht aktiviert werden: %w", err)
			}
			return true, "UFW-Firewall wurde automatisch eingeschaltet.", nil
		} else if path, err := exec.LookPath("firewall-cmd"); err == nil {
			cmd := exec.CommandContext(ctx, path, "--set-default-zone=public", "--complete-reload")
			if err := cmd.Run(); err != nil {
				return false, "", fmt.Errorf("firewalld konnte nicht neu geladen werden: %w", err)
			}
			return true, "firewalld wurde reaktiviert.", nil
		}
		return false, "", fmt.Errorf("kein unterstütztes Firewall-Tool (ufw/firewalld) gefunden")
	}
	return false, "", fmt.Errorf("Firewall-Remediation für OS %s nicht unterstützt", runtime.GOOS)
}

func remediateWindowsDefender(ctx context.Context) (bool, string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"Set-MpPreference -DisableRealtimeMonitoring $false")
	if err := cmd.Run(); err != nil {
		return false, "", fmt.Errorf("Windows Defender Echtzeitschutz konnte nicht aktiviert werden: %w", err)
	}
	return true, "Windows Defender Echtzeitschutz wurde über Set-MpPreference automatisch reaktiviert.", nil
}

func remediateSSHRootLogin(ctx context.Context) (bool, string, error) {
	cmd := exec.CommandContext(ctx, "sed", "-i", "s/PermitRootLogin yes/PermitRootLogin no/g", "/etc/ssh/sshd_config")
	if err := cmd.Run(); err != nil {
		return false, "", fmt.Errorf("sshd_config konnte nicht angepasst werden: %w", err)
	}
	_ = exec.CommandContext(ctx, "systemctl", "restart", "ssh").Run()
	return true, "SSH PermitRootLogin wurde in /etc/ssh/sshd_config auf 'no' gesetzt und SSH neu gestartet.", nil
}
