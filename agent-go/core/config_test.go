package core

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAgentConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aegis", "config.json")
	want := AgentConfig{HostToken: "ath_test-token", WormSecret: "stable-worm-secret"}
	if err := saveAgentConfig(path, want); err != nil {
		t.Fatalf("saveAgentConfig() error = %v", err)
	}

	got, err := loadAgentConfig(path)
	if err != nil {
		t.Fatalf("loadAgentConfig() error = %v", err)
	}
	if got != want {
		t.Fatalf("loaded config = %#v, want %#v", got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat config: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("config permissions = %04o, want 0600", info.Mode().Perm())
		}
	}
}
