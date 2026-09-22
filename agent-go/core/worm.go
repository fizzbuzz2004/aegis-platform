package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type WormLogger struct {
	filePath string
	mu       sync.Mutex
}

func NewWormLogger(customPath string) (*WormLogger, error) {
	path := customPath
	if path == "" {
		if os.Getenv("OS") == "Windows_NT" {
			path = `C:\ProgramData\Aegis\aegis_chain.dat`
		} else {
			path = "/var/log/aegis/aegis_chain.dat"
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	return &WormLogger{filePath: path}, nil
}

func (w *WormLogger) getLastHash() string {
	data, err := os.ReadFile(w.filePath)
	if err != nil || len(data) == 0 {
		return strings.Repeat("0", 64)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		return strings.Repeat("0", 64)
	}

	lastLine := lines[len(lines)-1]
	parts := strings.Split(lastLine, "|")
	if len(parts) < 1 {
		return strings.Repeat("0", 64)
	}

	return parts[0]
}

func (w *WormLogger) Log(event string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	prevHash := w.getLastHash()
	utcTs := time.Now().UTC().Format(time.RFC3339)

	payload := fmt.Sprintf("%s:%s:%s", prevHash, utcTs, event)
	hashBytes := sha256.Sum256([]byte(payload))
	currentHash := hex.EncodeToString(hashBytes[:])

	entry := fmt.Sprintf("%s|%s|%s|%s\n", currentHash, prevHash, utcTs, event)

	file, err := os.OpenFile(w.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Plattformunabhängiges Dateilocking
	_ = lockFile(file)
	defer unlockFile(file)

	if _, err := file.WriteString(entry); err != nil {
		return "", err
	}

	return currentHash, nil
}

func (w *WormLogger) VerifyIntegrity() (bool, string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := os.Stat(w.filePath); os.IsNotExist(err) {
		return true, "Logfile existiert noch nicht (Sauberer Zustand).", nil
	}

	data, err := os.ReadFile(w.filePath)
	if err != nil {
		return false, "", err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	expectedPrev := strings.Repeat("0", 64)

	for idx, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 4 {
			return false, fmt.Sprintf("Zeile %d: Ungültiges Datenformat.", idx+1), nil
		}

		storedHash := parts[0]
		prevHash := parts[1]
		utcTs := parts[2]
		event := parts[3]

		if prevHash != expectedPrev {
			return false, fmt.Sprintf("Zeile %d: Kettenglied unterbrochen (PrevHash Mismatch).", idx+1), nil
		}

		payload := fmt.Sprintf("%s:%s:%s", prevHash, utcTs, event)
		calcBytes := sha256.Sum256([]byte(payload))
		calcHash := hex.EncodeToString(calcBytes[:])

		if calcHash != storedHash {
			return false, fmt.Sprintf("Zeile %d: MANIPULATION ERKANNT! Stored Hash und Calculated Hash weichen ab.", idx+1), nil
		}

		expectedPrev = storedHash
	}

	return true, fmt.Sprintf("Integrität bestätigt. %d Blöcke erfolgreich geprüft.", len(lines)), nil
}
