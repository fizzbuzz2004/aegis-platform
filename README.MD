Aegis Platform
Eine modulare Security- & Monitoring-Plattform bestehend aus einem leichten Go-Agenten für Edge-Logik mit Offline-Pufferung und einer Python/FastAPI Control-Plane zur zentralen Aggregation und Verwaltung.

🏗 Architektur & Tech-Stack

Komponente Technologie Beschreibung Agent (agent-go)Go (Golang)Multi-Platform Endpoint-Agent mit SQLite Offline-Queue und WORM-Audit-Log (aegis_chain.dat).Control-Plane (control-plane)Python / FastAPIZentrale REST-API zur Datenverarbeitung, Konfigurationsverwaltung und Schnittstellenbereitstellung.DeploymentDocker / ComposeContainerisierte Infrastruktur inklusive flexibler Secrets-Anbindung.

🚀 Quickstart
Voraussetzungen
Docker & Docker Compose

Go 1.21+ (für lokale Agenten-Entwicklung)

Python 3.11+ (für lokale Control-Plane-Entwicklung)

1. Repository klonen & Umweltvariablen einrichten

git clone https://github.com/lschwe04/aegis-platform.git
cd aegis-platform
cp .env.example .env

2. Secrets strukturieren
Erstelle das lokale secrets/-Verzeichnis für sensitive Laufzeitdaten:

mkdir -p secrets
echo "postgresql://aegis:password@db:5432/aegis_db" > secrets/db_url.txt
echo "super-secret-key-change-me" > secrets/secret_key.txt
echo "admin-secure-password" > secrets/admin_pw.txt

3. Stack via Docker Compose starten

docker compose -f docker-compose.prod.yml up -d --build

🛠 Entwicklung & Workflows
Agent kompilieren (scripts/build.sh)
Baut Binaries für Zielplattformen (z. B. Windows & Linux) nach ./dist/:

chmod +x scripts/build.sh
./scripts/build.sh

Control-Plane lokal ausführen

cd control-plane
python -m venv .venv
source .venv/bin/activate  # Unter Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload

Tests ausführen

# Go Agent Tests
cd agent-go && go test ./...

# Control-Plane Tests
cd control-plane && pytest

🔒 Sicherheit & Hinweise
Das secrets/-Verzeichnis sowie .env-Dateien werden nicht im Versionskontrollsystem erfasst (siehe .gitignore).

Lokale SQLite-Puffer (*.db) und Audit-Chains (aegis_chain.dat) sind rein laufzeitbezogen.

