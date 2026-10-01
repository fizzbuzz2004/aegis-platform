package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const maxUpdateSize = 512 << 20

var semanticVersionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var updateOSInfoPattern = regexp.MustCompile(`^(linux|windows|darwin)-(amd64|arm64)$`)

type UpdateMetadata struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
	OSInfo      string `json:"os_info"`
}

func (s *SyncClient) FetchUpdateMetadata(ctx context.Context) (*UpdateMetadata, error) {
	serverURL, err := url.ParseRequestURI(s.ServerURL)
	if err != nil || serverURL.Scheme != "https" || serverURL.Host == "" {
		return nil, fmt.Errorf("update metadata requires an HTTPS control-plane URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.ServerURL+"/api/v1/agents/update", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+s.HostToken)

	response, err := s.HTTPClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("update metadata request failed: %w", err)
	}
	defer response.Body.Close()
	s.logResponse("GET /api/v1/agents/update", response.StatusCode)
	if response.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return nil, authFailure(response.StatusCode)
		}
		return nil, fmt.Errorf("update metadata request returned HTTP %d", response.StatusCode)
	}

	var metadata UpdateMetadata
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	if err := decoder.Decode(&metadata); err != nil {
		return nil, fmt.Errorf("invalid update metadata: %w", err)
	}
	if err := metadata.validate(); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func (m UpdateMetadata) validate() error {
	if _, _, err := parseSemanticVersion(m.Version); err != nil {
		return fmt.Errorf("invalid update version: %w", err)
	}
	parsedURL, err := url.ParseRequestURI(m.DownloadURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil {
		return fmt.Errorf("update download URL must be an HTTPS URL without user information")
	}
	if len(m.SHA256) != sha256.Size*2 {
		return fmt.Errorf("update SHA-256 must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(m.SHA256); err != nil {
		return fmt.Errorf("invalid update SHA-256: %w", err)
	}
	if !updateOSInfoPattern.MatchString(m.OSInfo) {
		return fmt.Errorf("update OS info is invalid")
	}
	return nil
}

// CheckAndApplyUpdate downloads only newer releases and atomically replaces the Linux executable.
// The audit callback records lifecycle events in the agent's existing WORM log.
func (s *SyncClient) CheckAndApplyUpdate(ctx context.Context, currentVersion string, audit func(string)) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, nil
	}
	controlPlaneURL, err := url.ParseRequestURI(s.ServerURL)
	if err != nil || controlPlaneURL.Scheme != "https" || controlPlaneURL.Host == "" {
		return false, nil
	}
	writeAudit := func(event string) {
		if audit != nil {
			audit(event)
		}
	}

	metadata, err := s.FetchUpdateMetadata(ctx)
	if err != nil {
		writeAudit("update check failed: " + err.Error())
		return false, err
	}
	if metadata == nil {
		return false, nil
	}
	if metadata.OSInfo != runtime.GOOS+"-"+runtime.GOARCH {
		return false, nil
	}
	newer, err := isNewerVersion(currentVersion, metadata.Version)
	if err != nil {
		writeAudit("update version comparison failed: " + err.Error())
		return false, err
	}
	if !newer {
		return false, nil
	}

	writeAudit(fmt.Sprintf("update detected: %s -> %s", currentVersion, metadata.Version))
	executable, err := os.Executable()
	if err != nil {
		writeAudit("update failed to locate current executable: " + err.Error())
		return false, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		writeAudit("update failed to resolve current executable: " + err.Error())
		return false, err
	}
	fileInfo, err := os.Stat(executable)
	if err != nil {
		writeAudit("update failed to inspect current executable: " + err.Error())
		return false, err
	}
	if !fileInfo.Mode().IsRegular() {
		err := fmt.Errorf("current executable is not a regular file")
		writeAudit("update failed: " + err.Error())
		return false, err
	}

	stagedFile, err := os.CreateTemp(filepath.Dir(executable), ".aegis-update-*")
	if err != nil {
		writeAudit("update failed to create staging file: " + err.Error())
		return false, err
	}
	stagedPath := stagedFile.Name()
	defer os.Remove(stagedPath)
	if err := stagedFile.Chmod(0600); err != nil {
		stagedFile.Close()
		writeAudit("update failed to secure staging file: " + err.Error())
		return false, err
	}

	writeAudit("update download started")
	digest, err := downloadUpdate(ctx, s.HTTPClient, metadata.DownloadURL, stagedFile)
	if err != nil {
		stagedFile.Close()
		writeAudit("update download failed: " + err.Error())
		return false, err
	}
	if !strings.EqualFold(digest, metadata.SHA256) {
		stagedFile.Close()
		err := fmt.Errorf("update checksum mismatch")
		writeAudit("update checksum verification failed")
		return false, err
	}
	writeAudit("update checksum verified")
	if err := stagedFile.Chmod(fileInfo.Mode().Perm()); err != nil {
		stagedFile.Close()
		writeAudit("update failed to set executable permissions: " + err.Error())
		return false, err
	}
	if err := stagedFile.Sync(); err != nil {
		stagedFile.Close()
		writeAudit("update failed to sync staged binary: " + err.Error())
		return false, err
	}
	if err := stagedFile.Close(); err != nil {
		writeAudit("update failed to close staged binary: " + err.Error())
		return false, err
	}

	replaced, err := replaceExecutable(executable, stagedPath)
	if replaced {
		writeAudit("update binary replaced atomically")
		writeAudit("restarting agent for updated binary")
	}
	if err != nil {
		writeAudit("update replacement warning: " + err.Error())
		return replaced, err
	}
	return true, nil
}

func downloadUpdate(ctx context.Context, baseClient *http.Client, downloadURL string, destination io.Writer) (string, error) {
	parsedURL, err := url.ParseRequestURI(downloadURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil {
		return "", fmt.Errorf("update download URL must be HTTPS")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}
	client := *baseClient
	client.Timeout = 10 * time.Minute
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != "https" || request.URL.User != nil {
			return fmt.Errorf("refusing insecure update redirect")
		}
		if previousRedirect != nil {
			return previousRedirect(request, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many update redirects")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxUpdateSize {
		return "", fmt.Errorf("update binary exceeds maximum size")
	}

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hasher), io.LimitReader(response.Body, maxUpdateSize+1))
	if err != nil {
		return "", fmt.Errorf("download could not be written: %w", err)
	}
	if written == 0 || written > maxUpdateSize {
		return "", fmt.Errorf("update binary has an invalid size")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func isNewerVersion(current, candidate string) (bool, error) {
	if strings.TrimSpace(current) == "dev" {
		return true, nil
	}
	currentCore, currentPre, err := parseSemanticVersion(current)
	if err != nil {
		return false, fmt.Errorf("current version: %w", err)
	}
	candidateCore, candidatePre, err := parseSemanticVersion(candidate)
	if err != nil {
		return false, fmt.Errorf("candidate version: %w", err)
	}
	for index := range currentCore {
		if candidateCore[index] != currentCore[index] {
			return candidateCore[index] > currentCore[index], nil
		}
	}
	if len(currentPre) == 0 || len(candidatePre) == 0 {
		return len(currentPre) > 0 && len(candidatePre) == 0, nil
	}
	for index := 0; index < len(currentPre) && index < len(candidatePre); index++ {
		left, right := currentPre[index], candidatePre[index]
		leftNumeric := allDigits(left)
		rightNumeric := allDigits(right)
		switch {
		case leftNumeric && rightNumeric && len(left) != len(right):
			return len(right) > len(left), nil
		case leftNumeric && rightNumeric && left != right:
			return right > left, nil
		case leftNumeric != rightNumeric:
			return leftNumeric, nil
		case left != right:
			return right > left, nil
		}
	}
	return len(candidatePre) > len(currentPre), nil
}

func parseSemanticVersion(version string) ([3]uint64, []string, error) {
	match := semanticVersionPattern.FindStringSubmatch(version)
	if match == nil {
		return [3]uint64{}, nil, fmt.Errorf("%q is not a semantic version", version)
	}
	var core [3]uint64
	for index := range core {
		value, err := strconv.ParseUint(match[index+1], 10, 64)
		if err != nil {
			return [3]uint64{}, nil, fmt.Errorf("invalid numeric version component: %w", err)
		}
		core[index] = value
	}
	preRelease := strings.Split(match[4], ".")
	if match[4] == "" {
		preRelease = nil
	}
	return core, preRelease, nil
}

func allDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return value != ""
}
