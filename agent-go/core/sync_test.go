package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegis-platform/agent-go/probes"
)

func TestMTLSTransportTrustsCAAndPresentsClientCertificate(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("request did not present a client certificate")
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	certificate := server.Certificate()
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	certificatePath := filepath.Join(t.TempDir(), "client.crt")
	privateKeyPath := filepath.Join(t.TempDir(), "client.key")
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(certificatePath, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEGIS_CLIENT_CERT", certificatePath)
	t.Setenv("AEGIS_CLIENT_KEY", privateKeyPath)
	t.Setenv("AEGIS_CA_CERT", caPath)

	transport, err := newMTLSTransport()
	if err != nil {
		t.Fatalf("newMTLSTransport() error = %v", err)
	}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get(server.URL)
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP status = %d, want %d", response.StatusCode, http.StatusOK)
	}
}

func TestFetchDesiredStateSendsBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ath_test-token" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"firewall_status":true}`)
	}))
	defer server.Close()

	client := &SyncClient{ServerURL: server.URL, HostToken: "ath_test-token", HTTPClient: server.Client()}
	state, err := client.FetchDesiredState(context.Background())
	if err != nil {
		t.Fatalf("FetchDesiredState() error = %v", err)
	}
	if !state["firewall_status"] {
		t.Fatalf("desired state = %#v", state)
	}
}

func TestPushResultsDoesNotRetryRevokedToken(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer ath_revoked-token" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		http.Error(w, "revoked", http.StatusForbidden)
	}))
	defer server.Close()

	client := &SyncClient{
		ServerURL:  server.URL,
		HostToken:  "ath_revoked-token",
		Hostname:   "test-host",
		QueueDB:    t.TempDir() + "/queue.db",
		HTTPClient: server.Client(),
	}
	err := client.PushResults(context.Background(), "firewall_status", []probes.Finding{{Status: "PASS"}})
	if err == nil || !strings.Contains(err.Error(), "revokiert") {
		t.Fatalf("PushResults() error = %v, want revoked-token error", err)
	}
	if requests != 1 {
		t.Errorf("request count = %d, want 1", requests)
	}
}

func TestFlushOfflineQueueDeliversAndRemovesQueuedResults(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer ath_test-token" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &SyncClient{
		ServerURL:  server.URL,
		HostToken:  "ath_test-token",
		QueueDB:    filepath.Join(t.TempDir(), "queue.db"),
		HTTPClient: server.Client(),
	}
	if err := client.initQueueDB(); err != nil {
		t.Fatalf("initQueueDB() error = %v", err)
	}
	client.enqueueOffline("firewall_status", []byte(`{"hostname":"test-host","module_name":"firewall_status","findings":[]}`))

	succeeded, failed := client.FlushOfflineQueue(context.Background())
	if succeeded != 1 || failed != 0 {
		t.Fatalf("FlushOfflineQueue() = (%d, %d), want (1, 0)", succeeded, failed)
	}
	if requests != 1 {
		t.Fatalf("request count = %d, want 1", requests)
	}

	succeeded, failed = client.FlushOfflineQueue(context.Background())
	if succeeded != 0 || failed != 0 {
		t.Fatalf("second FlushOfflineQueue() = (%d, %d), want (0, 0)", succeeded, failed)
	}
	if requests != 1 {
		t.Fatalf("request count after second flush = %d, want 1", requests)
	}
}
