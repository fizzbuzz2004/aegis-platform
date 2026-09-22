//go:build windows

package probes

import (
	"golang.org/x/sys/windows/registry"
)

func RunUpdatesProbe(ctx ProbeContext) []Finding {
	var findings []Finding
	rebootPending := false

	// Check 1: Component Based Servicing
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`, registry.READ); err == nil {
		rebootPending = true
		key.Close()
	}

	// Check 2: Windows Update Auto Update
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`, registry.READ); err == nil {
		rebootPending = true
		key.Close()
	}

	// Check 3: PendingFileRenameOperations
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.READ); err == nil {
		if _, _, err := key.GetStringsValue("PendingFileRenameOperations"); err == nil {
			rebootPending = true
		}
		key.Close()
	}

	if rebootPending {
		findings = append(findings, Finding{
			Status:     "WARN",
			Code:       "PENDING_REBOOT",
			Severity:   "MEDIUM",
			Message:    "System erfordert einen Neustart für ausstehende Updates (Registry-Check).",
			Compliance: []string{"NIS2:Art21.2.e", "BSI:SYS.1.1.A12", "ISO27001:A.8.8"},
		})
	} else {
		findings = append(findings, Finding{
			Status:     "PASS",
			Code:       "NO_PENDING_REBOOT",
			Severity:   "INFO",
			Message:    "Kein ausstehender Systemneustart erkannt.",
			Compliance: []string{"NIS2:Art21.2.e", "BSI:SYS.1.1.A12", "ISO27001:A.8.8"},
		})
	}

	return findings
}
