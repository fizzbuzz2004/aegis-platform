import requests
import platform
import socket
from typing import Dict, Any, Optional, List

class ConfigPullClient:
    def __init__(self, server_url: str, api_token: str):
        self.server_url = server_url.rstrip("/")
        self.api_token = api_token
        self.hostname = socket.gethostname()
        self.os_info = f"{platform.system()} {platform.release()}"
        self._last_known_config: Optional[Dict[str, Any]] = None
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "User-Agent": f"AegisAgent/1.2 ({self.os_info})",
            "Content-Type": "application/json"
        }

    def fetch_desired_state(self) -> Dict[str, bool]:
        """Fragt den Soll-Zustand ab."""
        endpoint = f"{self.server_url}/api/v1/sync"
        params = {"hostname": self.hostname, "os": self.os_info}
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=10)
            if response.status_code == 200:
                self._last_known_config = response.json().get("modules", {})
                return self._last_known_config
            else:
                print(f"[CONFIG-PULL] Server-Fehler HTTP {response.status_code}")
        except Exception as e:
            print(f"[CONFIG-PULL] Verbindungsfehler: {e}. Nutze lokalen Cache.")
        return self._last_known_config or {}

    def push_results(self, module_name: str, findings: List[Dict[str, Any]]) -> bool:
        """Sendet strukturierte Audit-Ergebnisse an das Control Plane."""
        endpoint = f"{self.server_url}/api/v1/results"
        payload = {
            "hostname": self.hostname,
            "module_name": module_name,
            "findings": findings
        }
        try:
            response = requests.post(endpoint, headers=self.headers, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"[CONFIG-PUSH] Fehler beim Senden ({module_name}): {e}")
            return False
