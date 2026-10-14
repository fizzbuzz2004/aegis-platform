package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
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
	Debug      bool
}

type ResultPayload struct {
	Hostname   string           `json:"hostname"`
	ModuleName string           `json:"module_name"`
	Findings   []probes.Finding `json:"findings"`
}

func NewSyncClient(serverURL, hostToken, hostname, osInfo string) (*SyncClient, error) {
	parsedURL, err := url.ParseRequestURI(serverURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil {
		return nil, fmt.Errorf("control-plane URL must be HTTPS for mutual TLS")
	}
	transport, err := newMTLSTransport()
	if err != nil {
		return nil, err
	}

	queuePath := DefaultQueuePath()

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
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}

	if err := client.initQueueDB(); err != nil {
		return nil, err
	}
	return client, nil
}

func newMTLSTransport() (*http.Transport, error) {
	caPath := os.Getenv("AEGIS_CA_CERT")
	clientCertPath := os.Getenv("AEGIS_CLIENT_CERT")
	clientKeyPath := os.Getenv("AEGIS_CLIENT_KEY")
	if runtime.GOOS == "windows" {
		pkiDir := filepath.Join(os.Getenv("ProgramData"), "Aegis", "pki")
		if os.Getenv("ProgramData") == "" {
			pkiDir = `C:\ProgramData\Aegis\pki`
		}
		if caPath == "" {
			caPath = filepath.Join(pkiDir, "ca.crt")
		}
		if clientCertPath == "" {
			clientCertPath = filepath.Join(pkiDir, "client.crt")
		}
		if clientKeyPath == "" {
			clientKeyPath = filepath.Join(pkiDir, "client.key")
		}
	} else {
		if caPath == "" {
			caPath = "/etc/aegis/pki/ca.crt"
		}
		if clientCertPath == "" {
			clientCertPath = "/etc/aegis/pki/client.crt"
		}
		if clientKeyPath == "" {
			clientKeyPath = "/etc/aegis/pki/client.key"
		}
	}

	if runtime.GOOS != "windows" {
		keyInfo, err := os.Stat(clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("cannot inspect mTLS client key: %w", err)
		}
		if keyInfo.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("mTLS client key permissions must not grant group or other access")
		}
	}

	clientCertificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load mTLS client certificate and key: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read mTLS CA certificate: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mTLS CA file contains no valid certificates")
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      rootCAs,
			Certificates: []tls.Certificate{clientCertificate},
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ForceAttemptHTTP2:     true,
	}, nil
}

func DefaultQueuePath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "Aegis", "queue.db")
	}
	return "/var/log/aegis/queue.db"
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
			s.logResponse("POST /api/v1/sync/results", resp.StatusCode)
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			s.logResponse("POST /api/v1/sync/results", resp.StatusCode)
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				resp.Body.Close()
				return authFailure(resp.StatusCode)
			}
			resp.Body.Close()
		} else if err != nil && s.Debug {
			log.Printf("[DEBUG] POST /api/v1/sync/results network error: %v", err)
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
	failed := 0
	type queuedFinding struct {
		id       int
		module   string
		jsonBody string
	}
	queued := make([]queuedFinding, 0, 50)

	for rows.Next() {
		var item queuedFinding
		if err := rows.Scan(&item.id, &item.module, &item.jsonBody); err != nil {
			failed++
			continue
		}
		queued = append(queued, item)
	}
	if err := rows.Err(); err != nil {
		fmt.Printf("[QUEUE WARN] Fehler während der DB-Iteration: %v\n", err)
		failed++
	}
	if err := rows.Close(); err != nil {
		fmt.Printf("[QUEUE WARN] Queue-Ergebnismenge konnte nicht geschlossen werden: %v\n", err)
		return 0, failed + len(queued)
	}

	succeeded := 0
	for _, item := range queued {
		req, err := http.NewRequestWithContext(ctx, "POST", s.ServerURL+"/api/v1/sync/results", bytes.NewBufferString(item.jsonBody))
		if err != nil {
			failed++
			continue
		}
		req.Header.Set("Authorization", "Bearer "+s.HostToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.HTTPClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			s.logResponse("POST /api/v1/sync/results (offline queue)", resp.StatusCode)
			resp.Body.Close()
			if _, err := db.ExecContext(ctx, "DELETE FROM offline_findings WHERE id = ?", item.id); err != nil {
				fmt.Printf("[QUEUE WARN] Übertragenes Ergebnis %d konnte nicht aus der Queue entfernt werden: %v\n", item.id, err)
				failed++
				continue
			}
			succeeded++
		} else {
			if resp != nil {
				s.logResponse("POST /api/v1/sync/results (offline queue)", resp.StatusCode)
				if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
					resp.Body.Close()
					failed++
					break
				}
				resp.Body.Close()
			} else if err != nil && s.Debug {
				log.Printf("[DEBUG] POST /api/v1/sync/results (offline queue) network error: %v", err)
			}
			failed++
		}
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
		if s.Debug {
			log.Printf("[DEBUG] POST /api/v1/agents/register network error: %v", err)
		}
		return "", err
	}
	defer resp.Body.Close()

	s.logResponse("POST /api/v1/agents/register", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Registrierung fehlgeschlagen: HTTP %d", resp.StatusCode)
	}

	var res struct {
		HostToken string `json:"host_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	s.HostToken = res.HostToken
	if s.HostToken == "" {
		return "", fmt.Errorf("Registrierung lieferte kein Host-Token")
	}
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
		if s.Debug {
			log.Printf("[DEBUG] GET /api/v1/agents/desired-state network error: %v", err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	s.logResponse("GET /api/v1/agents/desired-state", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, authFailure(resp.StatusCode)
		}
		return nil, fmt.Errorf("Soll-Zustand konnte nicht geladen werden: HTTP %d", resp.StatusCode)
	}

	state := make(map[string]bool)
	_ = json.NewDecoder(resp.Body).Decode(&state)
	return state, nil
}

func (s *SyncClient) logResponse(endpoint string, statusCode int) {
	if s.Debug {
		log.Printf("[DEBUG] %s -> HTTP %d (Authorization: Bearer [redacted])", endpoint, statusCode)
	}
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		log.Printf("[AUTH ERROR] %s wurde mit HTTP %d abgelehnt. Host-Token ist ungültig oder revokiert; Agent erneut registrieren.", endpoint, statusCode)
	}
}

func authFailure(statusCode int) error {
	return fmt.Errorf("Host-Token abgelehnt (HTTP %d); Token möglicherweise revokiert, Agent mit -register erneut registrieren", statusCode)
}
