package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/aegis-platform/agent-go/core"
	"github.com/aegis-platform/agent-go/probes"
)

var version = "dev"

func main() {
	onceFlag := flag.Bool("once", false, "Einmalige Ausführung")
	verifyFlag := flag.Bool("verify", false, "WORM Log-Integrität verifizieren")
	serverURL := flag.String("server", "", "Control Plane Server URL")
	hostToken := flag.String("token", "", "Host Authentifizierungstoken")
	enrollCode := flag.String("register", "", "Einmaliger Registrierungscode")
	debugFlag := flag.Bool("debug", false, "Detailliertes Network- und Auth-Logging")
	flag.Parse()

	config, configErr := core.LoadAgentConfig()
	if configErr != nil {
		log.Printf("[CONFIG WARN] %v", configErr)
	}
	serverURLValue := config.ServerURL
	if serverURLValue == "" {
		serverURLValue = "https://127.0.0.1:8000"
	}
	if envServerURL := os.Getenv("AEGIS_SERVER_URL"); envServerURL != "" {
		serverURLValue = envServerURL
	}
	tokenValue := config.HostToken
	if envToken := os.Getenv("AEGIS_HOST_TOKEN"); envToken != "" {
		tokenValue = envToken
	}
	flag.Visit(func(value *flag.Flag) {
		switch value.Name {
		case "token":
			tokenValue = *hostToken
		case "server":
			serverURLValue = *serverURL
		}
	})
	if *debugFlag {
		log.Printf("[DEBUG] Agent-Konfiguration: %s; Control Plane: %s; Host-Token vorhanden: %t", core.AgentConfigPath(), serverURLValue, tokenValue != "")
	}

	// -------------------------------------------------------------------------
	// FIX FÜR FINDING 1: Erzwinge ein echtes, lokales und sicheres WORM-Secret.
	// -------------------------------------------------------------------------
	wormSecret := config.WormSecret
	if wormSecret == "" {
		generatedSecret, secretErr := core.NewWormSecret()
		if secretErr != nil {
			log.Printf("[FATAL] WORM-Schlüssel konnte nicht erzeugt werden: %v", secretErr)
			os.Exit(1)
		}
		wormSecret = generatedSecret
		config.WormSecret = wormSecret
		if err := core.SaveAgentConfig(config); err != nil {
			log.Printf("[FATAL] WORM-Schlüssel kann nicht dauerhaft unter %s gespeichert werden: %v", core.AgentConfigPath(), err)
			os.Exit(1)
		}
	}

	worm, err := core.NewWormLogger("", wormSecret)
	if err != nil {
		fmt.Printf("[FATAL] WORM Logger Init fehlgeschlagen: %v\n", err)
		os.Exit(1)
	}

	if *verifyFlag {
		ok, msg, err := worm.VerifyIntegrity()
		if err != nil || !ok {
			fmt.Printf("🚨 INTEGRITÄTSVERLETZUNG: %s (Err: %v)\n", msg, err)
			os.Exit(1)
		}
		fmt.Printf("✅ INTEGRITÄT VALIDATED: %s\n", msg)
		os.Exit(0)
	}

	if tokenValue == "" && *enrollCode == "" {
		log.Printf("[FATAL] Kein Host-Token konfiguriert. Unregistrierte Agenten dürfen keine Audit-Events in der Kette persistieren. Bitte mit -register <enroll_code> registrieren.")
		os.Exit(1)
	}

	hostname, _ := os.Hostname()
	osInfo := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)

	syncClient, err := core.NewSyncClient(serverURLValue, tokenValue, hostname, osInfo)
	if err != nil {
		fmt.Printf("[FATAL] Sync Client Fehler: %v\n", err)
		os.Exit(1)
	}
	syncClient.Debug = *debugFlag

	if (runtime.GOOS == "linux" || runtime.GOOS == "windows") && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(serverURLValue)), "https://") {
		log.Printf("[UPDATE WARN] Auto-Update deaktiviert: Die Control-Plane-URL muss HTTPS verwenden. Sync-Zyklen laufen weiter.")
	}

	if *enrollCode != "" {
		newToken, err := syncClient.RegisterDevice(context.Background(), *enrollCode)
		if err != nil {
			fmt.Printf("[FATAL] Registrierung fehlgeschlagen: %v\n", err)
			os.Exit(1)
		}
		tokenValue = newToken
		syncClient.HostToken = newToken
		if err := core.SaveAgentConfig(core.AgentConfig{HostToken: newToken, ServerURL: serverURLValue, WormSecret: wormSecret}); err != nil {
			fmt.Printf("[FATAL] Registrierung erfolgreich, Token konnte aber nicht unter %s gespeichert werden: %v\n", core.AgentConfigPath(), err)
			os.Exit(1)
		}
		fmt.Printf("✅ Registriert. Token dauerhaft unter %s gespeichert.\n", core.AgentConfigPath())
	}

	pCtx := probes.ProbeContext{OSName: runtime.GOOS, Hostname: hostname}

	runCycle := func(ctx context.Context) bool {
		fmt.Println("[RECONCILE] Fragt Soll-Zustand ab...")
		modules, err := syncClient.FetchDesiredState(ctx)
		if err != nil {
			fmt.Printf("[SYNC WARN] State Fetch fehlgeschlagen: %v. Verarbeite Offline-Puffer...\n", err)
			succeeded, failed := syncClient.FlushOfflineQueue(ctx)
			if succeeded > 0 || failed > 0 {
				fmt.Printf("[TELEMETRY] Puffer-Flush: %d erfolgreich, %d verbleibend\n", succeeded, failed)
			}
			return false
		}
		succeeded, failed := syncClient.FlushOfflineQueue(ctx)
		if succeeded > 0 || failed > 0 {
			fmt.Printf("[TELEMETRY] Puffer-Flush: %d erfolgreich, %d verbleibend\n", succeeded, failed)
		}

		// --- ZENTRALE WORM-INTEGRITÄTSPRÜFUNG PRO ZYKLUS ---
		ok, wormMsg, wormErr := worm.VerifyIntegrity()
		wormStatus := "PASS"
		wormSeverity := "INFO"
		if !ok || wormErr != nil {
			wormStatus = "FAIL"
			wormSeverity = "CRITICAL"
			if wormErr != nil {
				wormMsg = fmt.Sprintf("%s (Fehler: %v)", wormMsg, wormErr)
			}
		}

		wormFindings := []probes.Finding{{
			Status:     wormStatus,
			Code:       "WORM_INTEGRITY_CHECK",
			Severity:   wormSeverity,
			Message:    wormMsg,
			Compliance: []string{"ISO27001:A.8.15", "NIS2:Art21.2.j"},
		}}

		_, _ = worm.Log(fmt.Sprintf("AUDIT [worm_audit] %s: %s", wormStatus, wormMsg))
		if err := syncClient.PushResults(ctx, "worm_audit", wormFindings); err != nil {
			fmt.Printf("[PUSH WARN] worm_audit lokal gepuffert: %v\n", err)
		} else {
			fmt.Println("[PUSH OK] worm_audit Ergebnisse übertragen.")
		}

		type ReportItem struct {
			Module     string
			Code       string
			Status     string
			Severity   string
			Message    string
			Compliance []string
		}
		var reportItems []ReportItem

		for _, wf := range wormFindings {
			reportItems = append(reportItems, ReportItem{
				Module:     "worm_audit",
				Code:       wf.Code,
				Status:     wf.Status,
				Severity:   wf.Severity,
				Message:    wf.Message,
				Compliance: wf.Compliance,
			})
		}

		// --- DYNAMISCHE AUSFÜHRUNG ALLER REGISTRIERTEN PROBES & REMEDIATION ---
		for modName, enabled := range modules {
			if !enabled {
				continue
			}

			findings, err := probes.RunModule(ctx, modName, pCtx)
			if err != nil {
				continue
			}

			if len(findings) > 0 {
				for i, f := range findings {
					_, _ = worm.Log(fmt.Sprintf("AUDIT [%s] %s: %s", modName, f.Status, f.Message))

					if f.Status == "FAIL" {
						if config.AutoRemediationMode == "enforce" {
							success, remediationMsg, remErr := core.AttemptRemediation(ctx, config.AutoRemediationEnabled, config.AutoRemediationMode, modName, f.Code)
							if remErr == nil && success {
								log.Printf("[REMEDIATION ENFORCE SUCCESS] %s (%s): %s", modName, f.Code, remediationMsg)
								_, _ = worm.Log(fmt.Sprintf("REMEDIATION [%s] ENFORCE SUCCESS: %s (Fix für Code: %s)", modName, remediationMsg, f.Code))

								findings[i].Status = "PASS"
								findings[i].Message = fmt.Sprintf("%s [Auto-Remediated: %s]", f.Message, remediationMsg)
							} else if remErr != nil {
								log.Printf("[REMEDIATION ERROR] %s (%s): %v", modName, f.Code, remErr)
								_, _ = worm.Log(fmt.Sprintf("REMEDIATION [%s] ERROR: %v", modName, remErr))
							}
						} else {
							log.Printf("[REMEDIATION AUDIT] Dry-Run / Audit-Modus aktiv für %s (%s). Keine automatischen Änderungen.", modName, f.Code)
							_, _ = worm.Log(fmt.Sprintf("REMEDIATION [%s] AUDIT-ONLY: Erkannter Drift gemeldet für Code: %s", modName, f.Code))
						}
					}

					reportItems = append(reportItems, ReportItem{
						Module:     modName,
						Code:       f.Code,
						Status:     findings[i].Status,
						Severity:   f.Severity,
						Message:    findings[i].Message,
						Compliance: f.Compliance,
					})
				}

				if err := syncClient.PushResults(ctx, modName, findings); err != nil {
					fmt.Printf("[PUSH WARN] %s lokal gepuffert: %v\n", modName, err)
				} else {
					fmt.Printf("[PUSH OK] %s Ergebnisse übertragen.\n", modName)
				}
			}
		}

		// --- AUSGABE DES FINAL COMPLIANCE-BERICHTS ---
		fmt.Println("\n==================================================================")
		fmt.Println("            AEGIS COMPLIANCE & REMEDIATION REPORT                 ")
		fmt.Println("==================================================================")
		passCount := 0
		failCount := 0
		for _, item := range reportItems {
			icon := "✅"
			if item.Status == "FAIL" {
				icon = "❌"
				failCount++
			} else {
				passCount++
			}
			fmt.Printf("%s [%s] Modul: %s | Code: %s\n", icon, item.Status, item.Module, item.Code)
			fmt.Printf("  Meldung: %s\n", item.Message)
			if len(item.Compliance) > 0 {
				fmt.Printf("  Compliance: %s\n", strings.Join(item.Compliance, ", "))
			}
			fmt.Println("------------------------------------------------------------------")
		}
		fmt.Printf("Zusammenfassung: Erfolgreich (PASS): %d | Fehlgeschlagen (FAIL): %d\n", passCount, failCount)
		fmt.Println("==================================================================\n")

		updated, updateErr := syncClient.CheckAndApplyUpdate(ctx, version, func(event string) {
			if _, logErr := worm.Log("AUDIT [agent_update] " + event); logErr != nil {
				log.Printf("[WORM ERROR] Update-Ereignis konnte nicht protokolliert werden: %v", logErr)
			}
		})
		if updateErr != nil {
			fmt.Printf("[UPDATE WARN] Update wurde nicht angewendet: %v\n", updateErr)
		}
		if updated {
			fmt.Println("[UPDATE] Ersatz geplant; Agent wird beendet und mit der aktualisierten Binary neu gestartet.")
		}
		return updated
	}

	if *onceFlag {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		runCycle(ctx)
		os.Exit(0)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	rootCtx, rootCancel := context.WithCancel(context.Background())

	go func() {
		sig := <-sigChan
		fmt.Printf("\n[SHUTDOWN] Signal %v empfangen. Sauberes Beenden...\n", sig)
		rootCancel()
	}()

	if runCycle(rootCtx) {
		rootCancel()
	}

	for {
		select {
		case <-ticker.C:
			if runCycle(rootCtx) {
				rootCancel()
			}
		case <-rootCtx.Done():
			fmt.Println("[SHUTDOWN] Flush verbleibender Telemetrie...")
			flushCtx, fCancel := context.WithTimeout(context.Background(), 5*time.Second)
			syncClient.FlushOfflineQueue(flushCtx)
			fCancel()
			os.Exit(0)
		}
	}
}
