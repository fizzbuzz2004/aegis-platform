import requests
import platform
import socket
import sqlite3
import json
import os
import sys
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
            "User-Agent": f"AegisAgent/2.0 ({self.os_info})",
            "Content-Type": "application/json"
        }
        
        # Lokale Offline-Queue für maximale Netzwerktoleranz
        if sys.platform == "win32":
            base_dir = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
            self.queue_db = os.path.join(base_dir, "Aegis", "queue.db")
        else:
            self.queue_db = "/var/log/aegis/queue.db"

        os.makedirs(os.path.dirname(os.path.abspath(self.queue_db)), exist_ok=True)
        self._init_queue_db()

    def _init_queue_db(self):
        with sqlite3.connect(self.queue_db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS offline_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_name TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def _enqueue(self, module_name: str, findings: List[Dict[str, Any]]):
        with sqlite3.connect(self.queue_db) as conn:
            conn.execute(
                "INSERT INTO offline_findings (module_name, findings_json) VALUES (?, ?)",
                (module_name, json.dumps(findings))
            )
            conn.commit()

    def flush_offline_queue(self) -> None:
        """Sendet ausstehende Offline-Ergebnisse nach Verbindungswiederherstellung."""
        with sqlite3.connect(self.queue_db) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            rows = cursor.execute("SELECT id, module_name, findings_json FROM offline_findings").fetchall()
            
            for row in rows:
                findings = json.loads(row["findings_json"])
                if self._transmit_payload(row["module_name"], findings):
                    conn.execute("DELETE FROM offline_findings WHERE id = ?", (row["id"],))
                    print(f"[OFFLINE-QUEUE] Nachgeliefertes Finding (ID: {row['id']}) erfolgreich übertragen.")
            conn.commit()

    def fetch_desired_state(self) -> Dict[str, bool]:
        endpoint = f"{self.server_url}/api/v1/sync"
        params = {"hostname": self.hostname, "os": self.os_info}
        try:
            # HTTPS mit Zertifikatsvalidierung
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=10, verify=True)
            if response.status_code == 200:
                self.flush_offline_queue()  # Versuche wartende Daten abzuarbeiten
                self._last_known_config = response.json().get("modules", {})
                return self._last_known_config
        except Exception as e:
            print(f"[CONFIG-PULL] Verbindungsfehler: {e}. Verwende gefallbackten Soll-Zustand.")
        return self._last_known_config or {}

    def _transmit_payload(self, module_name: str, findings: List[Dict[str, Any]]) -> bool:
        endpoint = f"{self.server_url}/api/v1/results"
        payload = {
            "hostname": self.hostname,
            "module_name": module_name,
            "findings": findings
        }
        try:
            response = requests.post(endpoint, headers=self.headers, json=payload, timeout=10, verify=True)
            return response.status_code == 200
        except Exception:
            return False

    def push_results(self, module_name: str, findings: List[Dict[str, Any]]) -> bool:
        success = self._transmit_payload(module_name, findings)
        if not success:
            print(f"[OFFLINE-BUFFER] Netzwerk offline. Speichere Ergebnisse lokal in Queue.")
            self._enqueue(module_name, findings)
        return success
