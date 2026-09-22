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
	onceFlag := flag.Bool("once", false, "Einmalige Ausführung (RMM Mode)")
	verifyFlag := flag.Bool("verify", false, "WORM Log-Integrität verifizieren")
	serverURL := flag.String("server", "http://127.0.0.1:8000", "Control Plane Server URL")
	hostToken := flag.String("token", os.Getenv("AEGIS_HOST_TOKEN"), "Host Authentifizierungstoken")
	enrollCode := flag.String("register", "", "Einmaliger Registrierungscode für das Gerät")
	flag.Parse()

	worm, err := core.NewWormLogger("")
	if err != nil {
		fmt.Printf("[FATAL] WORM Logger konnte nicht initialisiert werden: %v\n", err)
		os.Exit(1)
	}

	if *verifyFlag {
		ok, msg, err := worm.VerifyIntegrity()
		if err != nil || !ok {
			fmt.Printf("🚨 ALARM! INTEGRITÄTSVERLETZUNG: %s (Err: %v)\n", msg, err)
			os.Exit(1)
		}
		fmt.Printf("✅ INTEGRITÄT VALIDATED: %s\n", msg)
		os.Exit(0)
	}

	hostname, _ := os.Hostname()
	osInfo := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)

	syncClient, err := core.NewSyncClient(*serverURL, *hostToken, hostname, osInfo)
	if err != nil {
		fmt.Printf("[FATAL] Sync Engine Error: %v\n", err)
		os.Exit(1)
	}

	ctxRoot := context.Background()

	if *enrollCode != "" {
		fmt.Println("[REGISTER] Registriere Gerät bei der Control Plane...")
		newToken, err := syncClient.RegisterDevice(ctxRoot, *enrollCode)
		if err != nil {
			fmt.Printf("[FATAL] Geräte-Registrierung fehlgeschlagen: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Gerät erfolgreich registriert. Host-Token: %s\n", newToken)
		if *onceFlag {
			os.Exit(0)
		}
	}

	pCtx := probes.ProbeContext{
		OSName:   runtime.GOOS,
		Hostname: hostname,
	}

	runCycle := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		fmt.Println("\n[RECONCILE] Fragt Soll-Zustand ab...")
		modules, err := syncClient.FetchDesiredState(ctx)
		if err != nil {
			fmt.Printf("[SYNC WARN] State Fetch fehlgeschlagen: %v. Verarbeite Offline Queues...\n", err)
			return
		}

		for modName, enabled := range modules {
			if !enabled {
				continue
			}

			var findings []probes.Finding
			switch modName {
			case "cis_hardening":
				findings = probes.RunCISHardening(pCtx)
			case "backup_probe":
				findings = probes.RunBackupProbe(pCtx)
			case "registry_audit":
				findings = probes.RunRegistryAudit(pCtx)
			case "encryption_probe":
				findings = probes.RunEncryptionProbe(ctx, pCtx) // Korrigiert mit ctx
			case "updates_probe":
				findings = probes.RunUpdatesProbe(pCtx)
			case "security_probe":
				findings = probes.RunEndpointSecurityProbe(ctx, pCtx) // Korrigiert mit ctx
			case "storage_probe":
				findings = probes.RunStorageProbe(pCtx)
			}

			if len(findings) > 0 {
				for _, f := range findings {
					_, _ = worm.Log(fmt.Sprintf("AUDIT [%s] %s: %s", modName, f.Status, f.Message))
				}
				if err := syncClient.PushResults(ctx, modName, findings); err != nil {
					fmt.Printf("[PUSH WARN] %s Ergebnisse gepuffert: %v\n", modName, err)
				} else {
					fmt.Printf("[PUSH OK] %s Ergebnisse erfolgreich übertragen.\n", modName)
				}
			}
		}
	}

	if *onceFlag {
		runCycle()
		fmt.Println("=== Aegis Agent Durchlauf beendet (RMM Mode) ===")
		os.Exit(0)
	}

	fmt.Println("=== Aegis Agent läuft im Daemon-Modus (60s Intervall) ===")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	runCycle()

	for {
		select {
		case <-ticker.C:
			runCycle()
		case sig := <-sigChan:
			fmt.Printf("\n[SHUTDOWN] Beende Agent sauber auf Signal: %v\n", sig)
			os.Exit(0)
		}
	}
}
