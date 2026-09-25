package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aegis-platform/agent-go/probes"
	_ "modernc.org/sqlite"
)

type SyncClient struct {
	ServerURL  string
	HostToken  string
	Hostname   string
	OSInfo     string
	QueueDB    string
	HTTPClient *http.Client
}

type ResultPayload struct {
	Hostname   string           `json:"hostname"`
	ModuleName string           `json:"module_name"`
	Findings   []probes.Finding `json:"findings"`
}

func NewSyncClient(serverURL, hostToken, hostname, osInfo string) (*SyncClient, error) {
	queuePath := "/var/log/aegis/queue.db"
	if os.Getenv("OS") == "Windows_NT" {
		queuePath = `C:\ProgramData\Aegis\queue.db`
	}

	if err := os.MkdirAll(filepath.Dir(queuePath), 0700); err != nil {
		return nil, fmt.Errorf("Konnte Verzeichnis nicht erstellen: %w", err)
	}

	client := &SyncClient{
		ServerURL: serverURL,
		HostToken: hostToken,
		Hostname:  hostname,
		OSInfo:    osInfo,
		QueueDB:   queuePath,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:      10,
				IdleConnTimeout:   30 * time.Second,
				DisableKeepAlives: false,
			},
			Timeout: 10 * time.Second,
		},
	}

	if err := client.initQueueDB(); err != nil {
		return nil, err
	}
	return client, nil
}

func (s *SyncClient) initQueueDB() error {
	db, err := sql.Open("sqlite", s.QueueDB)
	if err != nil {
		return fmt.Errorf("DB Open failed: %w", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS offline_findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		module_name TEXT NOT NULL,
		findings_json TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`)
	return err
}

func (s *SyncClient) PushResults(ctx context.Context, moduleName string, findings []probes.Finding) error {
	payload := ResultPayload{
		Hostname:   s.Hostname,
		ModuleName: moduleName,
		Findings:   findings,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("JSON Marshal Fehler: %w", err)
	}

	maxRetries := 3
	baseBackoff := 1 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", s.ServerURL+"/api/v1/sync/results", bytes.NewBuffer(data))
		if err != nil {
			return err
		}

		req.Header.Set("Authorization", "Bearer "+s.HostToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.HTTPClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}

		select {
		case <-ctx.Done():
			s.enqueueOffline(moduleName, data)
			return ctx.Err()
		case <-time.After(baseBackoff * time.Duration(1<<attempt)):
		}
	}

	s.enqueueOffline(moduleName, data)
	return fmt.Errorf("übertragung fehlgeschlagen, lokal gepuffert")
}

func (s *SyncClient) FlushOfflineQueue(ctx context.Context) (int, int) {
	db, err := sql.Open("sqlite", s.QueueDB)
	if err != nil {
		return 0, 0
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, "SELECT id, module_name, findings_json FROM offline_findings ORDER BY id ASC LIMIT 50")
	if err != nil {
		return 0, 0
	}
	defer rows.Close()

	succeeded := 0
	failed := 0

	for rows.Next() {
		var id int
		var modName, jsonStr string
		if err := rows.Scan(&id, &modName, &jsonStr); err != nil {
			failed++
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "POST", s.ServerURL+"/api/v1/sync/results", bytes.NewBufferString(jsonStr))
		if err != nil {
			failed++
			continue
		}
		req.Header.Set("Authorization", "Bearer "+s.HostToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.HTTPClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			_, _ = db.ExecContext(ctx, "DELETE FROM offline_findings WHERE id = ?", id)
			succeeded++
		} else {
			if resp != nil {
				resp.Body.Close()
			}
			failed++
		}
	}

	// Behebt die Linter-Warnung (sqlrowserr)
	if err := rows.Err(); err != nil {
		fmt.Printf("[QUEUE WARN] Fehler während der DB-Iteration: %v\n", err)
	}

	return succeeded, failed
}

func (s *SyncClient) enqueueOffline(moduleName string, payloadJson []byte) {
	s.checkQueueSizeAndRotate()
	db, err := sql.Open("sqlite", s.QueueDB)
	if err != nil {
		return
	}
	defer db.Close()
	_, _ = db.Exec("INSERT INTO offline_findings (module_name, findings_json) VALUES (?, ?)", moduleName, string(payloadJson))
}

func (s *SyncClient) checkQueueSizeAndRotate() bool {
	info, err := os.Stat(s.QueueDB)
	if err != nil || info.Size() < 50*1024*1024 {
		return false
	}

	archiveName := fmt.Sprintf("%s.%d.gz", s.QueueDB, time.Now().Unix())
	src, _ := os.Open(s.QueueDB)
	dst, _ := os.Create(archiveName)
	gw := gzip.NewWriter(dst)

	_, _ = io.Copy(gw, src)
	gw.Close()
	dst.Close()
	src.Close()

	_ = os.Remove(s.QueueDB)
	_ = s.initQueueDB()
	return true
}

func (s *SyncClient) RegisterDevice(ctx context.Context, enrollCode string) (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"enrollment_code": enrollCode,
		"hostname":        s.Hostname,
		"os_info":         s.OSInfo,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", s.ServerURL+"/api/v1/agents/register", bytes.NewBuffer(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var res struct {
		HostToken string `json:"host_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	s.HostToken = res.HostToken
	return res.HostToken, nil
}

func (s *SyncClient) FetchDesiredState(ctx context.Context) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.ServerURL+"/api/v1/agents/desired-state", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.HostToken)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	state := make(map[string]bool)
	_ = json.NewDecoder(resp.Body).Decode(&state)
	return state, nil
}
