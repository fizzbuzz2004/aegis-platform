import os
import sys
import time
import hashlib
from datetime import datetime, timezone
from typing import Tuple

class WormChainLogger:
    def __init__(self, chain_file: str = None):
        if chain_file is None:
            if sys.platform == "win32":
                base_dir = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
                self.chain_file = os.path.join(base_dir, "Aegis", "aegis_chain.dat")
            else:
                self.chain_file = "/var/log/aegis/aegis_chain.dat"
        else:
            self.chain_file = chain_file

        os.makedirs(os.path.dirname(os.path.abspath(self.chain_file)), exist_ok=True)

    def _get_last_hash(self) -> str:
        if not os.path.exists(self.chain_file):
            return "0" * 64
        try:
            with open(self.chain_file, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f.readlines() if l.strip()]
                if not lines:
                    return "0" * 64
                return lines[-1].split("|")[0]
        except Exception:
            return "0" * 64

    def log(self, event: str) -> str:
        """Schreibt ein Event fälschungssicher mit SHA-256-Verkettung."""
        prev_hash = self._get_last_hash()
        utc_ts = datetime.now(timezone.utc).isoformat()
        
        payload = f"{prev_hash}:{utc_ts}:{event}"
        current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        
        entry = f"{current_hash}|{prev_hash}|{utc_ts}|{event}\n"
        with open(self.chain_file, "a", encoding="utf-8") as f:
            f.write(entry)
            
        print(f"[WORM-LOG] [{current_hash[:10]}] {event}")
        return current_hash

    def verify_integrity(self) -> Tuple[bool, str]:
        """Prüft die gesamte Chain lückenlos auf Manipulation."""
        if not os.path.exists(self.chain_file):
            return True, "Chain-Datei existiert noch nicht (sauberer Zustand)."

        with open(self.chain_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]

        expected_prev = "0" * 64
        for idx, line in enumerate(lines):
            parts = line.split("|")
            if len(parts) != 4:
                return False, f"Zeile {idx + 1}: Ungültiges Format."

            stored_hash, prev_hash, utc_ts, event = parts

            if prev_hash != expected_prev:
                return False, f"Zeile {idx + 1}: Kettenglied unterbrochen (PrevHash Mismatch)."

            payload = f"{prev_hash}:{utc_ts}:{event}"
            calculated_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            if calculated_hash != stored_hash:
                return False, f"Zeile {idx + 1}: Datenmanipulation erkannt! Hash weicht ab."

            expected_prev = stored_hash

        return True, f"Integrität bestätigt. {len(lines)} Blöcke verifiziert."
