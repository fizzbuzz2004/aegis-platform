import importlib
import json
from pathlib import Path
from typing import Callable, Dict, Any, List

from agent.core.verifier import verifier

MODULES_PACKAGE = "agent.modules"
MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"

class ModuleRegistry:
    def __init__(self):
        self._runners: Dict[str, Callable[[Dict[str, Any]], None]] = {}
        self._manifests: Dict[str, Dict[str, Any]] = {}

    def discover_and_register(self) -> None:
        self._runners.clear()
        self._manifests.clear()

        if not MODULES_DIR.exists():
            print(f"[REGISTRY] Modul-Verzeichnis nicht gefunden: {MODULES_DIR}")
            return

        for item in MODULES_DIR.iterdir():
            if item.is_dir() and not item.name.startswith("__"):
                mod_name = item.name
                runner_file = item / "runner.py"
                signature_file = item / "runner.py.sig"
                manifest_file = item / "manifest.json"

                if runner_file.exists():
                    # ZERO-TRUST CHECK: Prüfe Ed25519 Signatur des Moduls
                    if not verifier.verify_file(runner_file, signature_file):
                        print(f"[ZERO-TRUST REJECTED] Modul '{mod_name}' verweigert! Signatur fehlt oder ungültig.")
                        continue

                    manifest_data = {}
                    if manifest_file.exists():
                        try:
                            with open(manifest_file, "r", encoding="utf-8") as mf:
                                manifest_data = json.load(mf)
                        except Exception as e:
                            print(f"[REGISTRY] Fehler beim Lesen von {manifest_file}: {e}")

                    module_path = f"{MODULES_PACKAGE}.{mod_name}.runner"
                    try:
                        mod = importlib.import_module(module_path)
                        if hasattr(mod, "run"):
                            self._runners[mod_name] = getattr(mod, "run")
                            self._manifests[mod_name] = manifest_data
                            print(f"[REGISTRY OK] Signiertes Modul sicher geladen: {mod_name}")
                    except Exception as e:
                        print(f"[REGISTRY] Fehler beim Importieren von '{mod_name}': {e}")

    def get_runner(self, name: str) -> Callable[[Dict[str, Any]], None]:
        return self._runners.get(name)

    def list_registered(self) -> List[str]:
        return list(self._runners.keys())

registry = ModuleRegistry()
