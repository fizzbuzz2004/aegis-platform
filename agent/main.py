import time
import os
import argparse
from agent.core.worm_logger import WormChainLogger
from agent.core.registry import registry
from agent.core.config_pull import ConfigPullClient

SERVER_URL = os.getenv("AEGIS_SERVER_URL", "http://127.0.0.1:8000")
API_TOKEN = os.getenv("AEGIS_API_TOKEN", "aegis_test_token_001")
SYNC_INTERVAL = int(os.getenv("AEGIS_SYNC_INTERVAL", "60"))

def run_execution_cycle(logger: WormChainLogger, client: ConfigPullClient, context: dict):
    print("\n[RECONCILE] Fragt Control Plane nach Soll-Zustand ab...")
    desired_modules = client.fetch_desired_state()

    for mod_name, is_enabled in desired_modules.items():
        if is_enabled:
            runner = registry.get_runner(mod_name)
            if runner:
                print(f"[RUNNER] Führe aktives Modul aus: {mod_name}")
                try:
                    findings = runner(context)
                    if findings:
                        success = client.push_results(mod_name, findings)
                        if success:
                            print(f"[SYNC] Ergebnisse für '{mod_name}' erfolgreich übertragen.")
                except Exception as e:
                    logger.log(f"ERROR: Module {mod_name} failed: {e}")
            else:
                print(f"[WARN] Modul '{mod_name}' ist serverseitig aktiv, aber lokal nicht vorhanden.")

def main():
    parser = argparse.ArgumentParser(description="AegisCIS Agent")
    parser.add_argument("--once", action="store_true", help="Einmalige Ausführung (RMM-Modus)")
    args = parser.parse_args()

    print("=== AegisCIS Agent gestartet ===")
    logger = WormChainLogger()
    client = ConfigPullClient(server_url=SERVER_URL, api_token=API_TOKEN)
    registry.discover_and_register()

    context = {"logger": logger, "client": client}

    if args.once:
        run_execution_cycle(logger, client, context)
        print("=== AegisCIS Agent Durchlauf beendet (RMM Mode) ===")
    else:
        print(f"=== AegisCIS Agent läuft im Daemon-Modus ({SYNC_INTERVAL}s Intervall) ===")
        while True:
            run_execution_cycle(logger, client, context)
            time.sleep(SYNC_INTERVAL)

if __name__ == "__main__":
    main()
