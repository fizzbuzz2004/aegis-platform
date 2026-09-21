import requests
import json
from typing import Dict, Any, Optional, List

class ConfigPullClient:
    def __init__(self, server_url: str, api_token: str):
        self.server_url = server_url.rstrip("/")
        self.api_token = api_token
        self._last_known_config: Optional[Dict[str, Any]] = None
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "User-Agent": "AegisAgent/1.1",
            "Content-Type": "application/json"
        }

    def fetch_desired_state(self) -> Dict[str, bool]:
        """Fragt den Soll-Zustand ab. Liefert ein Dict der aktiven Module zurück."""
        endpoint = f"{self.server_url}/api/v1/sync"
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=5)
            if response.status_code == 200:
                self._last_known_config = response.json().get("modules", {})
                return self._last_known_config
            else:
                print(f"[CONFIG-PULL] Server-Fehler HTTP {response.status_code}")
        except Exception as e:
            print(f"[CONFIG-PULL] Netzwerk-Verbindungsfehler: {e}. Verwende Fallback.")
        return self._last_known_config or {}

    def push_results(self, module_name: str, findings: List[str]) -> bool:
        """Sendet die Audit-Ergebnisse sicher an das Systemhaus-Control-Plane."""
        endpoint = f"{self.server_url}/api/v1/results"
        payload = {
            "module_name": module_name,
            "findings": findings
        }
        try:
            response = requests.post(endpoint, headers=self.headers, json=payload, timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"[CONFIG-PUSH] Fehler beim Senden der Ergebnisse für {module_name}: {e}")
            return False
