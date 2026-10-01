package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegis-platform/agent-go/probes"
)

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
