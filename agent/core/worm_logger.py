import os
import time
import hashlib
from typing import Tuple

class WormChainLogger:
    def __init__(self, chain_file: str = "/tmp/aegis_chain.dat"):
        self.chain_file = chain_file
        os.makedirs(os.path.dirname(os.path.abspath(self.chain_file)), exist_ok=True)

    def _get_last_hash(self) -> str:
        if not os.path.exists(self.chain_file):
            return "0" * 64
        with open(self.chain_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
            if not lines:
                return "0" * 64
            return lines[-1].split("|")[0]

    def log(self, event: str) -> str:
        """Schreibt ein Event unveränderlich mit SHA-256-Verkettung."""
        prev_hash = self._get_last_hash()
        ts = int(time.time())
        # Format: PrevHash:Timestamp:Event
        payload = f"{prev_hash}:{ts}:{event}"
        current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        
        entry = f"{current_hash}|{prev_hash}|{ts}|{event}\n"
        with open(self.chain_file, "a", encoding="utf-8") as f:
            f.write(entry)
            
        print(f"[WORM-LOG] [{current_hash[:10]}] {event}")
        return current_hash

    def verify_integrity(self) -> Tuple[bool, str]:
        """Prüft die gesamte Chain lückenlos auf Manipulation."""
        if not os.path.exists(self.chain_file):
            return True, "Chain file does not exist yet (clean state)."

        with open(self.chain_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]

        expected_prev = "0" * 64
        for idx, line in enumerate(lines):
            parts = line.split("|")
            if len(parts) != 4:
                return False, f"Zeile {idx + 1}: Ungültiges Zeilenformat."

            stored_hash, prev_hash, ts, event = parts

            if prev_hash != expected_prev:
                return False, f"Zeile {idx + 1}: Kettenglied unterbrochen! (PrevHash Mismatch)"

            payload = f"{prev_hash}:{ts}:{event}"
            calculated_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            if calculated_hash != stored_hash:
                return False, f"Zeile {idx + 1}: Datenmanipulation erkannt! Hash stimmt nicht überein."

            expected_prev = stored_hash

        return True, f"Integrität bestätigt. {len(lines)} Blöcke geprüft."
