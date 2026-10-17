package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type WormLogger struct {
	filePath  string
	secretKey []byte
	mu        sync.Mutex
}

func NewWormLogger(customPath string, secretToken string) (*WormLogger, error) {
	path := customPath
	if path == "" {
		path = DefaultWormLogPath()
	}

	// Sicherheitsprüfung: Verhindere unsichere Fallback- oder leere Secrets (Behebung von Finding 1)
	if secretToken == "" || secretToken == "fallback_offline_secret_key" {
		return nil, fmt.Errorf("ungültiges oder unsicheres WORM-Secret: Ein kryptografisch abgesichertes Secret ist zwingend erforderlich")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	return &WormLogger{
		filePath:  path,
		secretKey: []byte(secretToken),
	}, nil
}

func DefaultWormLogPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "Aegis", "aegis_chain.dat")
	}
	return "/var/log/aegis/aegis_chain.dat"
}

func NewWormSecret() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("WORM-Schlüssel kann nicht erzeugt werden: %w", err)
	}
	return hex.EncodeToString(secret), nil
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

func (w *WormLogger) generateHMAC(payload string) string {
	mac := hmac.New(sha256.New, w.secretKey)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func (w *WormLogger) Log(event string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	prevHash := w.getLastHash()
	utcTs := time.Now().UTC().Format(time.RFC3339)

	payload := fmt.Sprintf("%s:%s:%s", prevHash, utcTs, event)
	currentHash := w.generateHMAC(payload)

	entry := fmt.Sprintf("%s|%s|%s|%s\n", currentHash, prevHash, utcTs, event)

	// Unter Linux das Append-Only-Attribut vor dem Öffnen temporär aufheben
	if runtime.GOOS == "linux" {
		_ = exec.Command("chattr", "-a", w.filePath).Run()
	}

	file, err := os.OpenFile(w.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		if runtime.GOOS == "linux" {
			_ = exec.Command("chattr", "+a", w.filePath).Run()
		}
		return "", err
	}

	_ = lockFile(file)

	if _, err := file.WriteString(entry); err != nil {
		unlockFile(file)
		_ = file.Close()
		if runtime.GOOS == "linux" {
			_ = exec.Command("chattr", "+a", w.filePath).Run()
		}
		return "", err
	}

	unlockFile(file)
	if err := file.Close(); err != nil {
		if runtime.GOOS == "linux" {
			_ = exec.Command("chattr", "+a", w.filePath).Run()
		}
		return "", err
	}

	// Setzen des Linux Append-Only-Attributs (+a) nach dem erfolgreichen Schreiben zur Manipulationseinschränkung
	if runtime.GOOS == "linux" {
		_ = exec.Command("chattr", "+a", w.filePath).Run()
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
		calcHash := w.generateHMAC(payload)

		if calcHash != storedHash {
			return false, fmt.Sprintf("Zeile %d: MANIPULATION ERKANNT! Ungültige kryptografische Signatur.", idx+1), nil
		}

		expectedPrev = storedHash
	}

	return true, fmt.Sprintf("Integrität bestätigt. %d Blöcke erfolgreich kryptografisch geprüft.", len(lines)), nil
}
