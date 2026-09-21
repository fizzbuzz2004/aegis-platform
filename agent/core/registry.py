import importpkg = None
import importlib
import pkgutil
from pathlib import Path
from typing import Callable, Dict, Any

MODULES_PACKAGE = "agent.modules"
MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"

class ModuleRegistry:
    def __init__(self):
        self._registry: Dict[str, Callable[[Dict[str, Any]], None]] = {}

    def discover_and_register(self):
        self._registry.clear()
        if not MODULES_DIR.exists():
            return
        
        # Scan subdirectories in agent/modules
        for item in MODULES_DIR.iterdir():
            if item.is_dir() and not item.name.startswith("__"):
                mod_name = item.name
                runner_file = item / "runner.py"
                if runner_file.exists():
                    module_path = f"{MODULES_PACKAGE}.{mod_name}.runner"
                    try:
                        mod = importlib.import_module(module_path)
                        if hasattr(mod, "run"):
                            self._registry[mod_name] = getattr(mod, "run")
                            print(f"[REGISTRY] Discovered & loaded module: {mod_name}")
                    except Exception as e:
                        print(f"[REGISTRY] Failed to load module {mod_name}: {e}")

    get = lambda self, name: self._registry.get(name)
    all_registered = lambda self: list(self._registry.keys())

registry = ModuleRegistry()
