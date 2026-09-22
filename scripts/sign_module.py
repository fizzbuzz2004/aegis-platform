#!/usr/bin/env python3
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519

CERTS_DIR = Path(__file__).resolve().parent.parent / "agent" / "certs"
PRIVATE_KEY_PATH = CERTS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = CERTS_DIR / "public_key.pem"

def generate_keys_if_missing():
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    if not PRIVATE_KEY_PATH.exists():
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes_raw())
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes_raw())
        print(f"[KEYS] Neues Ed25519 Schlüsselpaar generiert in {CERTS_DIR}")

def sign_runner_file(runner_path: Path):
    if not runner_path.exists():
        print(f"[ERROR] Datei nicht gefunden: {runner_path}")
        sys.exit(1)

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())

    with open(runner_path, "rb") as f:
        file_data = f.read()

    signature = private_key.sign(file_data)
    signature_path = runner_path.parent / "runner.py.sig"

    with open(signature_path, "wb") as f:
        f.write(signature)

    print(f"✅ Modul erfolgreich signiert: {runner_path.parent.name}")
    print(f"   Signatur geschrieben: {signature_path}")

if __name__ == "__main__":
    generate_keys_if_missing()
    
    if len(sys.argv) > 1:
        target_path = Path(sys.argv[1])
    else:
        target_path = Path(__file__).resolve().parent.parent / "agent" / "modules" / "cis_hardening" / "runner.py"

    sign_runner_file(target_path)
