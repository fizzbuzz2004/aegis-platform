import os
import time
import hashlib

class WormChainLogger:
    def __init__(self, chain_file: str = "/tmp/aegis_chain.dat"):
        self.chain_file = chain_file
        os.makedirs(os.path.dirname(self.chain_file), exist_ok=True)

    def _get_last_hash(self) -> str:
        if not os.path.exists(self.chain_file):
            return "0" * 64
        with open(self.chain_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
            if not lines:
                return "0" * 64
            return lines[-1].split("|")[0]

    def log(self, event: str) -> str:
        prev_hash = self._get_last_hash()
        ts = int(time.time())
        current_hash = hashlib.sha256(f"{prev_hash}:{event}".encode("utf-8")).hexdigest()
        with open(self.chain_file, "a", encoding="utf-8") as f:
            f.write(f"{current_hash}|{prev_hash}|{ts}|{event}\n")
        print(f"[WORM-LOG] Recorded: {event[:40]}... (Hash: {current_hash[:12]}...)")
        return current_hash
