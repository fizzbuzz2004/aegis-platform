package core

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAgentConfigRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows config writes use a SYSTEM/Administrators-only ACL; validate them in an elevated agent run")
	}
	path := filepath.Join(t.TempDir(), "aegis", "config.json")
	want := AgentConfig{
		HostToken:  "ath_test-token",
		ServerURL:  "http://192.168.56.10:8000",
		WormSecret: "stable-worm-secret",
	}
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

func TestLoadAgentConfigMissingFileReturnsEmptyConfig(t *testing.T) {
	config, err := loadAgentConfig(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("loadAgentConfig() error = %v, want nil for a missing file", err)
	}
	if config != (AgentConfig{}) {
		t.Fatalf("loadAgentConfig() = %#v, want an empty config", config)
	}
}

func TestLoadAgentConfigRejectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if _, err := loadAgentConfig(path); err == nil {
		t.Fatal("loadAgentConfig() error = nil, want invalid JSON error")
	}
}
