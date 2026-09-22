package core

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
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

type SyncConfigResponse struct {
	Status     string          `json:"status"`
	TenantID   int             `json:"tenant_id"`
	TenantName string          `json:"tenant_name"`
	Modules    map[string]bool `json:"modules"`
}

type ResultPayload struct {
	Hostname   string           `json:"hostname"`
	ModuleName string           `json:"module_name"`
	Findings   []probes.Finding `json:"findings"`
}

type RegisterRequest struct {
	EnrollmentCode string `json:"enrollment_code"`
	Hostname       string `json:"hostname"`
	OSInfo         string `json:"os_info"`
}

type RegisterResponse struct {
	Status    string `json:"status"`
	HostToken string `json:"host_token"`
}

func NewSyncClient(serverURL, hostToken, hostname, osInfo string) (*SyncClient, error) {
	var queuePath string
	if os.Getenv("OS") == "Windows_NT" {
		queuePath = `C:\ProgramData\Aegis\queue.db`
	} else {
		queuePath = "/var/log/aegis/queue.db"
	}

	if err := os.MkdirAll(filepath.Dir(queuePath), 0700); err != nil {
		return nil, err
	}

	client := &SyncClient{
		ServerURL: serverURL,
		HostToken: hostToken,
		Hostname:  hostname,
		OSInfo:    osInfo,
		QueueDB:   queuePath,
		HTTPClient: &http.Client{
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
		return err
	}
	defer db.Close()

	query := `CREATE TABLE IF NOT EXISTS offline_findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		module_name TEXT NOT NULL,
		findings_json TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(query)
	return err
}

func (s *SyncClient) RegisterDevice(enrollmentCode string) (string, error) {
	reqBody, _ := json.Marshal(RegisterRequest{
		EnrollmentCode: enrollmentCode,
		Hostname:       s.Hostname,
		OSInfo:         s.OSInfo,
	})

	resp, err := s.HTTPClient.Post(s.ServerURL+"/api/v1/sync/register", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Registrierung fehlgeschlagen: HTTP %d", resp.StatusCode)
	}

	var res RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	s.HostToken = res.HostToken
	return res.HostToken, nil
}

func (s *SyncClient) FetchDesiredState() (map[string]bool, error) {
	req, err := http.NewRequest("GET", s.ServerURL+"/api/v1/sync/config", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+s.HostToken)
	q := req.URL.Query()
	q.Add("hostname", s.Hostname)
	q.Add("os", s.OSInfo)
	req.URL.RawQuery = q.Encode()

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		s.FlushOfflineQueue()
		var cfg SyncConfigResponse
		if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
			return nil, err
		}
		return cfg.Modules, nil
	}

	return nil, fmt.Errorf("HTTP Fehler: %d", resp.StatusCode)
}

func (s *SyncClient) PushResults(moduleName string, findings []probes.Finding) error {
	payload := ResultPayload{
		Hostname:   s.Hostname,
		ModuleName: moduleName,
		Findings:   findings,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", s.ServerURL+"/api/v1/sync/results", bytes.NewBuffer(data))
	if err != nil {
		s.enqueueOffline(moduleName, data)
		return err
	}

	req.Header.Set("Authorization", "Bearer "+s.HostToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		s.enqueueOffline(moduleName, data)
		return fmt.Errorf("Übertragung fehlgeschlagen, lokal gepuffert")
	}
	defer resp.Body.Close()

	return nil
}

func (s *SyncClient) enqueueOffline(moduleName string, payloadJson []byte) {
	db, err := sql.Open("sqlite", s.QueueDB)
	if err != nil {
		return
	}
	defer db.Close()

	_, _ = db.Exec("INSERT INTO offline_findings (module_name, findings_json) VALUES (?, ?)", moduleName, string(payloadJson))
}

func (s *SyncClient) FlushOfflineQueue() {
	db, err := sql.Open("sqlite", s.QueueDB)
	if err != nil {
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, module_name, findings_json FROM offline_findings")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var moduleName, findingsJson string
		if err := rows.Scan(&id, &moduleName, &findingsJson); err != nil {
			continue
		}

		req, err := http.NewRequest("POST", s.ServerURL+"/api/v1/sync/results", bytes.NewBuffer([]byte(findingsJson)))
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+s.HostToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.HTTPClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			_, _ = db.Exec("DELETE FROM offline_findings WHERE id = ?", id)
			resp.Body.Close()
		}
	}

	// KORREKTUR: Abfangen von Fehlern, die während des Durchlaufs aufgetreten sind
	if err := rows.Err(); err != nil {
		return
	}
}
