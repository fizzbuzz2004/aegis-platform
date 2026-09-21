import sys
import argparse
from agent.core.worm_logger import WormChainLogger
from agent.core.registry import registry

def main():
    parser = argparse.ArgumentParser(prog="aegis-cli", description="AegisCIS Agent Control CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Verify Command
    subparsers.add_parser("verify", help="Prüft die WORM-Hashchain auf Manipulation")

    # Status Command
    subparsers.add_parser("status", help="Listet geladene Module auf")

    args = parser.parse_args()
    logger = WormChainLogger()

    if args.command == "verify":
        is_ok, msg = logger.verify_integrity()
        if is_ok:
            print(f"✅ INTEGRITÄT OK: {msg}")
            sys.exit(0)
        else:
            print(f"🚨 ALARM! TAMPERING ERKANNT: {msg}")
            sys.exit(1)

    elif args.command == "status":
        registry.discover_and_register()
        print(f"Geladene Module ({len(registry.list_registered())}):")
        for mod in registry.list_registered():
            print(f" - {mod}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
