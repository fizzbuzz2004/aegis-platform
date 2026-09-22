1. Control Plane (Backend API)
fastapi: Haupt-Framework für die REST-API.

uvicorn[standard]: ASGI-Server zum Ausführen der FastAPI-Anwendung (uvicorn app.main:app --reload).

slowapi: Rate-Limiting für API-Endpunkte.

python-multipart: Erforderlich für OAuth2PasswordRequestForm beim Login.

sqlalchemy: ORM für Datenbankabfragen und Tabellendefinitionen.

psycopg2-binary: PostgreSQL-Treiber (benötigt durch deine DATABASE_URL in config.py).

pydantic-settings: Verwaltung von Umgebungsvariablen und BaseSettings.

python-jose[cryptography]: Erstellung und Validierung von JWT-Tokens.

passlib & bcrypt: Sicheres Hashing und Überprüfen von Passwörtern.

2. Aegis Agent (Client)
requests: HTTP-Client für den Pull-Mechanismus und das Senden von Ergebnissen (config_pull.py).

cryptography: Ed25519-Signaturprüfung für heruntergeladene Module (verifier.py).

System-Voraussetzungen & Tools
Neben den Python-Paketen werden folgende System-Tools benötigt:

Python 3.10+: Empfohlen für Type-Hinting und asynccontextmanager.

PostgreSQL 14+: Datenbank für die Control Plane.

OpenSSL / Keytool: Zur Generierung der Ed25519-Schlüsselpaare (public_key.pem & private_key.pem) für die Modul-Verifikation.

Schnellinstallation

# Virtuelle Umgebung erstellen und aktivieren
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Alle Abhängigkeiten installieren
pip install -r requirements.txt
