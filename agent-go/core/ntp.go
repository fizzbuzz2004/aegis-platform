package core

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// MaxAllowedDrift definiert die maximal tolerierte Abweichung der Systemzeit
// gegenüber der vertrauenswürdigen Control-Plane (NIS2 Art. 21 / ISO 27001 A.8.15).
const MaxAllowedDrift = 5 * time.Second

// NTPChecker überwacht kontinuierlich den Zeitdrift des Endpunkts.
type NTPChecker struct {
	mu         sync.Mutex
	lastDrift  time.Duration
	isDrifted  bool
	wormLogger *WormLogger
	httpClient *http.Client
}

// NewNTPChecker initialisiert eine neue Instanz des NTP-Drift-Monitors.
func NewNTPChecker(wormLogger *WormLogger, client *http.Client) *NTPChecker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &NTPChecker{
		wormLogger: wormLogger,
		httpClient: client,
	}
}

// CheckTimeDriftAgainstHeader prüft den Zeitdrift anhand des HTTP-Date-Headers
// der Control-Plane-Antwort und protokolliert kritische Abweichungen im lokalen WORM-Log.
func (nc *NTPChecker) CheckTimeDriftAgainstHeader(resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("ungültige HTTP-Antwort für NTP-Prüfung")
	}

	dateHeader := resp.Header.Get("Date")
	if dateHeader == "" {
		// Kein Datum-Header vorhanden; Fallback auf NTP-Server oder Warnung überspringen
		return nil
	}

	serverTime, err := time.Parse(time.RFC1123, dateHeader)
	if err != nil {
		return fmt.Errorf("fehlgeschlagenes Parsen des Server-Datumsheaders (%s): %w", dateHeader, err)
	}

	localTime := time.Now().UTC()
	drift := localTime.Sub(serverTime)
	if drift < 0 {
		drift = -drift
	}

	nc.mu.Lock()
	nc.lastDrift = drift
	nc.isDrifted = drift > MaxAllowedDrift
	nc.mu.Unlock()

	if drift > MaxAllowedDrift {
		warningMsg := fmt.Sprintf(
			"WORM_TIME_DRIFT_WARNING: Lokale Systemzeit weicht um %.2fs von der Control-Plane ab (Toleranz: %.0fs). Integritätsrisiko für WORM-HMAC-Zeitstempel.",
			drift.Seconds(),
			MaxAllowedDrift.Seconds(),
		)

		// Protokollierung im lokalen manipulationssicheren WORM-Log des Agents
		if nc.wormLogger != nil {
			if _, logErr := nc.wormLogger.Log("AUDIT [ntp_sync] FAIL: " + warningMsg); logErr != nil {
				return fmt.Errorf("kritischer Fehler beim Schreiben in das WORM-Log: %w", logErr)
			}
		}

		return fmt.Errorf("%s", warningMsg)
	}

	return nil
}

// StartPeriodicDriftCheck startet eine Hintergrund-Routine zur regelmäßigen Drift-Überprüfung
// via NTP-Heartbeat an die Control-Plane.
func (nc *NTPChecker) StartPeriodicDriftCheck(ctx context.Context, controlPlaneURL string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				req, err := http.NewRequestWithContext(ctx, http.MethodHead, controlPlaneURL+"/api/v1/health", nil)
				if err != nil {
					continue
				}

				resp, err := nc.httpClient.Do(req)
				if err != nil {
					continue
				}
				_ = resp.Body.Close()

				if err := nc.CheckTimeDriftAgainstHeader(resp); err != nil {
					// Drift erkannt - hier kann ein Notfall-Signal an den Agent-Dispatcher gesendet werden
					fmt.Printf("[AEGIS-SECURITY-ALERT] %v\n", err)
				}
			}
		}
	}()
}

// GetStatus liefert den aktuellen Drift-Status für Status-Berichte an die Control-Plane.
func (nc *NTPChecker) GetStatus() (time.Duration, bool) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return nc.lastDrift, nc.isDrifted
}
