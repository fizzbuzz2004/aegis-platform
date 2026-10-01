package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type AgentConfig struct {
	HostToken  string `json:"host_token"`
	ServerURL  string `json:"server_url,omitempty"`
	WormSecret string `json:"worm_secret"`
}

func AgentConfigPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "Aegis", "config.json")
	}
	if runtime.GOOS == "linux" {
		return "/etc/aegis/config.json"
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "aegis", "config.json")
	}
	return filepath.Join(configDir, "aegis", "config.json")
}

func LoadAgentConfig() (AgentConfig, error) {
	return loadAgentConfig(AgentConfigPath())
}

func loadAgentConfig(path string) (AgentConfig, error) {
	var config AgentConfig
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return config, nil
	}
	if err != nil {
		return config, fmt.Errorf("Agent-Konfiguration kann nicht gelesen werden: %w", err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("Agent-Konfiguration ist ungültig: %w", err)
	}
	return config, nil
}

func SaveAgentConfig(config AgentConfig) error {
	return saveAgentConfig(AgentConfigPath(), config)
}

func saveAgentConfig(path string, config AgentConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("Konfigurationsverzeichnis kann nicht erstellt werden: %w", err)
	}
	if err := secureConfigDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("Konfigurationsverzeichnis kann nicht geschützt werden: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("Agent-Konfiguration kann nicht serialisiert werden: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return fmt.Errorf("temporäre Agent-Konfiguration kann nicht erstellt werden: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := secureConfigFile(file); err != nil {
		file.Close()
		return fmt.Errorf("Konfigurationsrechte können nicht gesetzt werden: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("Agent-Konfiguration kann nicht geschrieben werden: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("Agent-Konfiguration kann nicht synchronisiert werden: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("Agent-Konfiguration kann nicht geschlossen werden: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("Agent-Konfiguration kann nicht aktiviert werden: %w", err)
	}
	return nil
}
