import time
import os
from agent.core.worm_logger import WormChainLogger
from agent.core.registry import registry
from agent.core.config_pull import ConfigPullClient

SERVER_URL = os.getenv("AEGIS_SERVER_URL", "http://127.0.0.1:8000")
API_TOKEN = os.getenv("AEGIS_API_TOKEN", "aegis_test_token_001")
SYNC_INTERVAL = int(os.getenv("AEGIS_SYNC_INTERVAL", "60")) # Skalierbarer: Auf 60 Sekunden erhöht

def run_daemon():
    print("=== AegisCIS Agent Daemon gestartet ===")
    logger = WormChainLogger()
    client = ConfigPullClient(server_url=SERVER_URL, api_token=API_TOKEN)

    registry.discover_and_register()

    context = {
        "logger": logger,
        "client": client
    }

    while True:
        print("\n[RECONCILE] Fragt Control Plane nach Soll-Zustand ab...")
        desired_modules = client.fetch_desired_state()

        for mod_name, is_enabled in desired_modules.items():
            if is_enabled:
                runner = registry.get_runner(mod_name)
                if runner:
                    print(f"[RUNNER] Führe aktives Modul aus: {mod_name}")
                    try:
                        # Runner gibt Findings als Liste zurück
                        findings = runner(context)
                        if findings:
                            # 1. Sicher an das Control Plane senden
                            success = client.push_results(mod_name, findings)
                            if success:
                                print(f"[SYNC] Ergebnisse für {mod_name} erfolgreich übertragen.")
                    except Exception as e:
                        logger.log(f"ERROR: Module {mod_name} failed: {e}")
                else:
                    print(f"[WARN] Modul '{mod_name}' ist aktiv, aber lokal nicht registriert.")

        time.sleep(SYNC_INTERVAL)

if __name__ == "__main__":
    run_daemon()
