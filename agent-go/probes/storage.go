package probes

import (
	"fmt"
)

func RunStorageProbe(ctx ProbeContext) []Finding {
	var findings []Finding

	if ctx.OSName == "windows" {
		drives := []string{"C:\\", "D:\\"}
		for _, drive := range drives {
			freeBytes, totalBytes, err := getDiskSpace(drive)
			if err != nil {
				continue
			}
			usedBytes := totalBytes - freeBytes
			usedPercent := (float64(usedBytes) / float64(totalBytes)) * 100.0

			if usedPercent >= 90.0 {
				findings = append(findings, Finding{
					Status:     "FAIL",
					Code:       "STORAGE_CRITICAL",
					Severity:   "HIGH",
					Message:    fmt.Sprintf("Speicherbelegung auf Laufwerk %s kritisch: %.2f%% belegt (%d GB frei von %d GB)", drive, usedPercent, freeBytes/(1024*1024*1024), totalBytes/(1024*1024*1024)),
					Compliance: []string{"BSI:SYS.1.1", "ISO27001:A.8.14", "NIS2:Art21.2"},
				})
			} else if usedPercent >= 80.0 {
				findings = append(findings, Finding{
					Status:     "WARN",
					Code:       "STORAGE_WARNING",
					Severity:   "MEDIUM",
					Message:    fmt.Sprintf("Speicherbelegung auf Laufwerk %s hoch: %.2f%% belegt", drive, usedPercent),
					Compliance: []string{"BSI:SYS.1.1", "ISO27001:A.8.14"},
				})
			} else {
				findings = append(findings, Finding{
					Status:     "PASS",
					Code:       "STORAGE_OK",
					Severity:   "INFO",
					Message:    fmt.Sprintf("Speicherbelegung auf Laufwerk %s im Normbereich: %.2f%% belegt", drive, usedPercent),
					Compliance: []string{"BSI:SYS.1.1", "ISO27001:A.8.14"},
				})
			}
		}
	} else {
		freeBytes, totalBytes, err := getDiskSpace("/")
		if err == nil {
			usedBytes := totalBytes - freeBytes
			usedPercent := (float64(usedBytes) / float64(totalBytes)) * 100.0

			if usedPercent >= 90.0 {
				findings = append(findings, Finding{
					Status:     "FAIL",
					Code:       "STORAGE_CRITICAL",
					Severity:   "HIGH",
					Message:    fmt.Sprintf("Speicherbelegung auf Partition '/' kritisch: %.2f%% belegt (%d GB frei von %d GB)", usedPercent, freeBytes/(1024*1024*1024), totalBytes/(1024*1024*1024)),
					Compliance: []string{"BSI:SYS.1.1", "ISO27001:A.8.14", "NIS2:Art21.2"},
				})
			} else if usedPercent >= 80.0 {
				findings = append(findings, Finding{
					Status:     "WARN",
					Code:       "STORAGE_WARNING",
					Severity:   "MEDIUM",
					Message:    fmt.Sprintf("Speicherbelegung auf Partition '/' hoch: %.2f%% belegt", usedPercent),
					Compliance: []string{"BSI:SYS.1.1", "ISO27001:A.8.14"},
				})
			} else {
				findings = append(findings, Finding{
					Status:     "PASS",
					Code:       "STORAGE_OK",
					Severity:   "INFO",
					Message:    fmt.Sprintf("Speicherbelegung auf Partition '/' im Normbereich: %.2f%% belegt", usedPercent),
					Compliance: []string{"BSI:SYS.1.1", "ISO27001:A.8.14"},
				})
			}
		}
	}

	return findings
}
