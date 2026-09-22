import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

PUBLIC_KEY_PATH = Path(__file__).resolve().parent.parent / "certs" / "public_key.pem"

class ModuleVerifier:
    def __init__(self, key_path: Path = PUBLIC_KEY_PATH):
        self.key_path = key_path

    def _load_public_key(self) -> ed25519.Ed25519PublicKey:
        if not self.key_path.exists():
            raise FileNotFoundError(f"[VERIFIER] Öffentlicher Schlüssel nicht gefunden: {self.key_path}")
        with open(self.key_path, "rb") as kf:
            key_bytes = kf.read()
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

    def verify_file(self, file_path: Path, signature_path: Path) -> bool:
        if not file_path.exists() or not signature_path.exists():
            return False
        try:
            public_key = self._load_public_key()
            with open(file_path, "rb") as ff:
                file_data = ff.read()
            with open(signature_path, "rb") as sf:
                signature = sf.read()
            
            public_key.verify(signature, file_data)
            return True
        except InvalidSignature:
            print(f"[SECURITY ALARM] Digitale Signatur ungültig für: {file_path}")
            return False
        except Exception as e:
            print(f"[VERIFIER] Fehler bei Verifikation von {file_path}: {e}")
            return False

verifier = ModuleVerifier()
