package main

import (
	"context"
	"flag"
	"fmt"
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
	serverURL := flag.String("server", "http://127.0.0.1:8000", "Control Plane Server URL")
	hostToken := flag.String("token", os.Getenv("AEGIS_HOST_TOKEN"), "Host Authentifizierungstoken")
	enrollCode := flag.String("register", "", "Einmaliger Registrierungscode")
	flag.Parse()

	worm, err := core.NewWormLogger("")
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

	syncClient, err := core.NewSyncClient(*serverURL, *hostToken, hostname, osInfo)
	if err != nil {
		fmt.Printf("[FATAL] Sync Client Fehler: %v\n", err)
		os.Exit(1)
	}

	if *enrollCode != "" {
		newToken, err := syncClient.RegisterDevice(context.Background(), *enrollCode)
		if err != nil {
			fmt.Printf("[FATAL] Registrierung fehlgeschlagen: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Registriert. Token: %s\n", newToken)
		if *onceFlag {
			os.Exit(0)
		}
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

		// Dynamische Ausführung aller registrierten Probes ohne Code-Anpassung in main.go
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
