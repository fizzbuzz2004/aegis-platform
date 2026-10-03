package core

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchUpdateMetadataUsesHostBearerToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/update" {
			t.Errorf("path = %q, want update endpoint", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer ath_update-token" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"version":"1.2.3","download_url":"https://updates.example/aegis","sha256":"`+strings.Repeat("a", 64)+`","os_info":"linux-amd64","signature":"`+base64.StdEncoding.EncodeToString([]byte("test-signature"))+`"}`)
	}))
	defer server.Close()

	client := &SyncClient{ServerURL: server.URL, HostToken: "ath_update-token", HTTPClient: server.Client()}
	metadata, err := client.FetchUpdateMetadata(context.Background())
	if err != nil {
		t.Fatalf("FetchUpdateMetadata() error = %v", err)
	}
	if metadata == nil || metadata.Version != "1.2.3" || metadata.SHA256 != strings.Repeat("a", 64) || metadata.OSInfo != "linux-amd64" {
		t.Fatalf("FetchUpdateMetadata() = %#v", metadata)
	}
}

func TestFetchUpdateMetadataNoContentMeansNoRelease(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &SyncClient{ServerURL: server.URL, HTTPClient: server.Client()}
	metadata, err := client.FetchUpdateMetadata(context.Background())
	if err != nil || metadata != nil {
		t.Fatalf("FetchUpdateMetadata() = (%#v, %v), want (nil, nil)", metadata, err)
	}
}

func TestFetchUpdateMetadataRequiresHTTPS(t *testing.T) {
	client := &SyncClient{ServerURL: "http://control.example", HTTPClient: &http.Client{}}
	if _, err := client.FetchUpdateMetadata(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("FetchUpdateMetadata() error = %v, want HTTPS requirement", err)
	}
}

func TestDownloadUpdateVerifiesTLSPayloadDigest(t *testing.T) {
	const payload = "verified agent binary"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("artifact request unexpectedly carried Authorization: %q", got)
		}
		_, _ = fmt.Fprint(w, payload)
	}))
	defer server.Close()

	hasher := sha256.Sum256([]byte(payload))
	var staged strings.Builder
	digest, err := downloadUpdate(context.Background(), server.Client(), server.URL, &staged)
	if err != nil {
		t.Fatalf("downloadUpdate() error = %v", err)
	}
	if digest != hex.EncodeToString(hasher[:]) || staged.String() != payload {
		t.Fatalf("download digest/content = (%s, %q), want (%s, %q)", digest, staged.String(), hex.EncodeToString(hasher[:]), payload)
	}
}

func TestDownloadUpdateRejectsNonHTTPSURL(t *testing.T) {
	_, err := downloadUpdate(context.Background(), &http.Client{}, "http://updates.example/aegis", &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("downloadUpdate() error = %v, want HTTPS rejection", err)
	}
}

func TestIsNewerVersionUsesSemanticOrdering(t *testing.T) {
	tests := []struct {
		current   string
		candidate string
		want      bool
	}{
		{current: "1.2.3", candidate: "1.2.4", want: true},
		{current: "v1.2.3-rc.1", candidate: "1.2.3", want: true},
		{current: "1.2.3-rc.2", candidate: "1.2.3-rc.10", want: true},
		{current: "1.2.3", candidate: "1.2.2", want: false},
		{current: "1.2.3", candidate: "1.2.3+build.4", want: false},
		{current: "dev", candidate: "1.0.0", want: true},
	}
	for _, test := range tests {
		got, err := isNewerVersion(test.current, test.candidate)
		if err != nil || got != test.want {
			t.Errorf("isNewerVersion(%q, %q) = (%t, %v), want (%t, nil)", test.current, test.candidate, got, err, test.want)
		}
	}
}

func TestUpdateMetadataRejectsInsecureOrMalformedFields(t *testing.T) {
	valid := UpdateMetadata{Version: "1.2.3", DownloadURL: "https://updates.example/agent", SHA256: strings.Repeat("a", 64), Signature: base64.StdEncoding.EncodeToString([]byte("test-signature"))}
	tests := []UpdateMetadata{
		{Version: "01.2.3", DownloadURL: valid.DownloadURL, SHA256: valid.SHA256},
		{Version: valid.Version, DownloadURL: "http://updates.example/agent", SHA256: valid.SHA256},
		{Version: valid.Version, DownloadURL: valid.DownloadURL, SHA256: "not-a-digest"},
	}
	for _, metadata := range tests {
		if err := metadata.validate(); err == nil {
			t.Errorf("metadata.validate() accepted %#v", metadata)
		}
	}
}

func TestVerifyUpdateSignatureChecksReleaseIdentityAndDigest(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	previousPublicKey := updateSigningPublicKeyB64
	updateSigningPublicKeyB64 = base64.StdEncoding.EncodeToString(publicKeyDER)
	t.Cleanup(func() { updateSigningPublicKeyB64 = previousPublicKey })

	metadata := UpdateMetadata{
		Version:     "1.2.3",
		DownloadURL: "https://updates.example/agent",
		SHA256:      strings.Repeat("a", 64),
		OSInfo:      "windows-amd64",
	}
	digest := sha256.Sum256(updateSignatureMessage(metadata))
	metadata.Signature = base64.StdEncoding.EncodeToString(mustSignPSS(t, privateKey, digest[:]))
	if err := verifyUpdateSignature(metadata); err != nil {
		t.Fatalf("verifyUpdateSignature() error = %v", err)
	}

	metadata.OSInfo = "linux-amd64"
	if err := verifyUpdateSignature(metadata); err == nil {
		t.Fatal("verifyUpdateSignature() accepted metadata with a tampered platform")
	}
}

func mustSignPSS(t *testing.T, privateKey *rsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("SignPSS() error = %v", err)
	}
	return signature
}
