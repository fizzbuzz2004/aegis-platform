package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/aegis-platform/agent-go/core"
	"github.com/aegis-platform/agent-go/probes"
)

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
		serverURLValue = "http://127.0.0.1:8000"
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

	// Initialisierung: Host-Token als HMAC-Secret für den WORM Logger sichern
	hostTokenValue := tokenValue
	if hostTokenValue == "" {
		hostTokenValue = "fallback_offline_secret_key"
	}
	wormSecret := config.WormSecret
	if wormSecret == "" {
		if tokenValue != "" {
			wormSecret = tokenValue
		} else {
			_, statErr := os.Stat(core.DefaultWormLogPath())
			if statErr == nil {
				wormSecret = hostTokenValue
			} else if !os.IsNotExist(statErr) {
				log.Printf("[FATAL] WORM-Log kann nicht geprüft werden: %v", statErr)
				os.Exit(1)
			} else {
				generatedSecret, secretErr := core.NewWormSecret()
				if secretErr != nil {
					log.Printf("[FATAL] %v", secretErr)
					os.Exit(1)
				}
				wormSecret = generatedSecret
			}
		}
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

	hostname, _ := os.Hostname()
	osInfo := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)

	syncClient, err := core.NewSyncClient(serverURLValue, tokenValue, hostname, osInfo)
	if err != nil {
		fmt.Printf("[FATAL] Sync Client Fehler: %v\n", err)
		os.Exit(1)
	}
	syncClient.Debug = *debugFlag
	if tokenValue == "" && *enrollCode == "" {
		log.Printf("[AUTH WARN] Kein Host-Token konfiguriert. Agent zuerst mit -register <enroll_code> registrieren.")
	}

	if *enrollCode != "" {
		newToken, err := syncClient.RegisterDevice(context.Background(), *enrollCode)
		if err != nil {
			fmt.Printf("[FATAL] Registrierung fehlgeschlagen: %v\n", err)
			os.Exit(1)
		}
		if err := core.SaveAgentConfig(core.AgentConfig{HostToken: newToken, ServerURL: serverURLValue, WormSecret: wormSecret}); err != nil {
			fmt.Printf("[FATAL] Registrierung erfolgreich, Token konnte aber nicht unter %s gespeichert werden: %v\n", core.AgentConfigPath(), err)
			os.Exit(1)
		}
		fmt.Printf("✅ Registriert. Token dauerhaft unter %s gespeichert.\n", core.AgentConfigPath())
	}

	pCtx := probes.ProbeContext{OSName: runtime.GOOS, Hostname: hostname}

	runCycle := func(ctx context.Context) {
		fmt.Println("[RECONCILE] Fragt Soll-Zustand ab...")
		modules, err := syncClient.FetchDesiredState(ctx)
		if err != nil {
			fmt.Printf("[SYNC WARN] State Fetch fehlgeschlagen: %v. Verarbeite Offline-Puffer...\n", err)
			succeeded, failed := syncClient.FlushOfflineQueue(ctx)
			if succeeded > 0 || failed > 0 {
				fmt.Printf("[TELEMETRY] Puffer-Flush: %d erfolgreich, %d verbleibend\n", succeeded, failed)
			}
			return
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

		// --- DYNAMISCHE AUSFÜHRUNG ALLER REGISTRIERTEN PROBES ---
		for modName, enabled := range modules {
			if !enabled {
				continue
			}

			findings, err := probes.RunModule(ctx, modName, pCtx)
			if err != nil {
				continue // Modul existiert nicht auf diesem Agenten
			}

			if len(findings) > 0 {
				for _, f := range findings {
					_, _ = worm.Log(fmt.Sprintf("AUDIT [%s] %s: %s", modName, f.Status, f.Message))
				}
				if err := syncClient.PushResults(ctx, modName, findings); err != nil {
					fmt.Printf("[PUSH WARN] %s lokal gepuffert: %v\n", modName, err)
				} else {
					fmt.Printf("[PUSH OK] %s Ergebnisse übertragen.\n", modName)
				}
			}
		}
	}

	if *onceFlag {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		runCycle(ctx)
		os.Exit(0)
	}

	// Graceful Shutdown & Signal Handling
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

	runCycle(rootCtx)

	for {
		select {
		case <-ticker.C:
			runCycle(rootCtx)
		case <-rootCtx.Done():
			fmt.Println("[SHUTDOWN] Flush verbleibender Telemetrie...")
			flushCtx, fCancel := context.WithTimeout(context.Background(), 5*time.Second)
			syncClient.FlushOfflineQueue(flushCtx)
			fCancel()
			os.Exit(0)
		}
	}
}
