import requests
from typing import Dict, Any, Optional

class ConfigPullClient:
    def __init__(self, server_url: str, api_token: str):
        self.server_url = server_url.rstrip("/")
        self.api_token = api_token
        self._last_known_config: Optional[Dict[str, Any]] = None

    def fetch_desired_state(self) -> Dict[str, bool]:
        """Fragt den Soll-Zustand ab. Liefert ein Dict der aktiven Module zurück."""
        endpoint = f"{self.server_url}/api/v1/sync"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "User-Agent": "AegisAgent/1.0"
        }

        try:
            response = requests.get(endpoint, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                self._last_known_config = data.get("modules", {})
                return self._last_known_config
            else:
                print(f"[CONFIG-PULL] Server-Fehler HTTP {response.status_code}")
        except Exception as e:
            print(f"[CONFIG-PULL] Netzwerk-Verbindungsfehler: {e}. Verwende Fallback.")

        # Fallback auf letzten bekannten Zustand, falls Server offline ist
        return self._last_known_config or {}
