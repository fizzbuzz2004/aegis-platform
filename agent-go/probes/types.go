package probes

type Finding struct {
	Status     string   `json:"status"`     // PASS, FAIL, WARN, INFO
	Code       string   `json:"code"`       // z.B. SSH_ROOT_ALLOWED
	Severity   string   `json:"severity"`   // HIGH, MEDIUM, LOW, INFO
	Message    string   `json:"message"`    // Detailbeschreibung
	Compliance []string `json:"compliance"` // z.B. ["ISO27001:A.8.9", "NIS2:Art21.2.i"]
}

type ProbeContext struct {
	OSName   string
	Hostname string
}
