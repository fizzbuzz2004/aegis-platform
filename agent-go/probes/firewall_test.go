package probes

import "testing"

func TestParseUFWStatus(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantActive bool
		wantKnown  bool
	}{
		{name: "active", output: "Status: active\n", wantActive: true, wantKnown: true},
		{name: "inactive", output: "Status: inactive\n", wantKnown: true},
		{name: "unknown output", output: "ufw: command failed\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			active, known := parseUFWStatus(test.output)
			if active != test.wantActive || known != test.wantKnown {
				t.Fatalf("parseUFWStatus(%q) = (%t, %t), want (%t, %t)", test.output, active, known, test.wantActive, test.wantKnown)
			}
		})
	}
}

func TestParseFirewalldState(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantActive bool
		wantKnown  bool
	}{
		{name: "running", output: "running\n", wantActive: true, wantKnown: true},
		{name: "not running", output: "not running\n", wantKnown: true},
		{name: "unknown output", output: "permission denied\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			active, known := parseFirewalldState(test.output)
			if active != test.wantActive || known != test.wantKnown {
				t.Fatalf("parseFirewalldState(%q) = (%t, %t), want (%t, %t)", test.output, active, known, test.wantActive, test.wantKnown)
			}
		})
	}
}
