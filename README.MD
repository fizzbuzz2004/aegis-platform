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

2. Lokalen VirtualBox-Teststack starten

Setze in `.env` mindestens ein eigenes `SECRET_KEY` und ein `ADMIN_INITIAL_PASSWORD` mit mindestens 12 Zeichen. Danach den mitgelieferten Control-Plane- und Postgres-Stack starten:

```sh
docker compose up -d --build
docker compose ps
```

Der lokale Stack ist in `docker-compose.yml` definiert. `docker-compose.prod.yml` ist für ein bereits gebautes `aegis-control-plane:latest` Image und eine externe Datenbank gedacht; er enthält keinen Postgres-Service und ist nicht der Quickstart für eine leere VirtualBox-Testumgebung.

Für den Wiederaufbau mit `scripts/rebuild_stack.sh` wird `.env` an der Repository-Wurzel oder in `control-plane/` verwendet. Wenn beide Dateien existieren und voneinander abweichen, muss der gewünschte Pfad explizit gewählt werden, damit nicht versehentlich ein anderer Bootstrap-Admin-Hash erzeugt wird:

```sh
sudo env AEGIS_ENV_FILE=control-plane/.env bash scripts/rebuild_stack.sh
```

Wenn der Admin bereits in der Datenbank vorhanden ist und sein Bootstrap-Passwort geändert wurde, kann der Hash kontrolliert auf das Passwort der ausgewählten Compose-Umgebung zurückgesetzt werden. Der Befehl zeigt weder Passwort noch Hash an:

```sh
sudo docker compose --env-file control-plane/.env exec -T control-plane python -c 'from app.core.config import settings; from app.core.database import SessionLocal; from app.core.security import get_password_hash; from app.models.orm import User; db = SessionLocal(); admin = db.query(User).filter(User.username == "admin").one(); admin.hashed_password = get_password_hash(settings.ADMIN_INITIAL_PASSWORD); admin.must_change_password = True; db.commit(); print("Bootstrap admin password reset from selected Compose environment"); db.close()'
```

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

## VirtualBox-Testnetz und Debugging

Die derzeit registrierten VirtualBox-VMs verwenden Bridged Networking. Ermittle die IPv4-Adresse der Ubuntu-Control-VM in der VM mit `ip -4 -o addr show scope global` und verwende die Adresse des bridged Interfaces, nicht `127.0.0.1` oder ungeprüft `192.168.56.10`. Die Ubuntu- und Windows-Agenten müssen TCP-Port 8000 auf dieser Adresse erreichen können; sie müssen einander nicht erreichen.

Von beiden Agent-VMs vor der Registrierung testen:

```sh
curl -f http://<CONTROL_VM_IP>:8000/docs
```

Falls UFW auf der Control-VM aktiv ist, Port 8000 dort freigeben:

```sh
sudo ufw allow 8000/tcp
```

Unter Windows PowerShell können beide x64-Agenten gebaut werden:

```powershell
.\scripts\build_virtualbox.ps1
```

Unter Linux/macOS:

```sh
cd agent-go
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../dist/aegis-agent-linux .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o ../dist/aegis-agent.exe .
```

Agent zuerst einmalig registrieren; danach wird `host_token` in `/etc/aegis/config.json` (Linux) bzw. `%ProgramData%\Aegis\config.json` (Windows) gespeichert:

```sh
sudo ./aegis-agent-linux -server http://<CONTROL_VM_IP>:8000 -register <enroll_code> -debug -once
sudo ./aegis-agent-linux -debug -once
```

```powershell
.\aegis-agent.exe -server http://<CONTROL_VM_IP>:8000 -register <enroll_code> -debug -once
.\aegis-agent.exe -debug -once
```

`-debug` protokolliert Endpunkte, HTTP-Status und Netzwerkfehler, niemals den Tokenwert. Unter Linux benötigt das Anlegen der Konfiguration Schreibrechte für `/etc/aegis`; Windows muss mit Rechten zum Schreiben in ProgramData laufen.

## Agent Auto-Update (Linux)

Der Control-Plane-Endpunkt `GET /api/v1/agents/update` liefert Release-Metadaten nur an Hosts mit gültigem `Authorization: Bearer <host_token>`. Für Updates muss auch die Agent-URL der Control Plane HTTPS verwenden; bei einer HTTP-URL laufen normale Sync-Zyklen weiter, aber Auto-Update bleibt deaktiviert. Veröffentliche das Linux-Binary auf einem HTTPS-fähigen Artefaktserver und setze `AGENT_UPDATE_VERSION`, `AGENT_UPDATE_URL`, `AGENT_UPDATE_SHA256` und `AGENT_UPDATE_OS_INFO` in der Control-Plane-Umgebung. `AGENT_UPDATE_OS_INFO` muss zum Binary passen, zum Beispiel `linux-amd64` oder `linux-arm64`. Alle vier Werte müssen gesetzt sein; ohne Konfiguration ist Auto-Update deaktiviert. Berechne den Digest für exakt die ausgelieferte Datei, zum Beispiel mit `sha256sum aegis-agent-linux-x64`.

Baue jedes Release mit derselben Version im Binary, zum Beispiel `AEGIS_AGENT_VERSION=1.2.3 ./scripts/build.sh`. Der Linux-Agent fragt nach einem erfolgreichen Reconcile-Zyklus nach Updates, lädt die Datei über HTTPS in sein Installationsverzeichnis, prüft SHA-256 und ersetzt das Binary atomar. Danach beendet er sich, damit `systemd` den aktualisierten Agenten neu startet. Der Dienst muss `Restart=always` oder `Restart=on-failure` verwenden und Schreibrechte auf das Binary-Verzeichnis haben. Die Prüfsumme schützt vor Übertragungsfehlern; der Metadaten-Endpunkt und Artefaktserver müssen zusätzlich über vertrauenswürdiges TLS erreichbar sein.

## Neue Agent-Probe

Lege eine Go-Datei in `agent-go/probes/` an und registriere einen `ProbeRunner` in `init()`. Beispiel: Die Probe `firewall_status` ist in `probes/firewall.go` umgesetzt und erscheint nach dem Build als Modulname. Für einen neuen Modulnamen wird kein Datenbankschema angepasst: `POST /api/v1/admin/toggle` legt einen unbekannten `TenantModule.module_name` als String an; der Agent führt ihn aus, wenn seine Probe mit exakt diesem Namen registriert ist.

```go
func init() {
	Register("mein_modul", func(ctx context.Context, pCtx ProbeContext) []Finding {
		return []Finding{{Status: "PASS", Code: "CHECK_OK", Severity: "INFO", Message: "Prüfung erfolgreich"}}
	})
}
```

## Tenant-Branding-Migration

Für bestehende Datenbanken vor dem aktualisierten Control-Plane-Start einmal `control-plane/migrations/001_tenant_branding.sql` gegen die Datenbank ausführen. Neue Datenbanken erhalten die Felder automatisch über SQLAlchemy `create_all`.

🔒 Sicherheit & Hinweise
Das secrets/-Verzeichnis sowie .env-Dateien werden nicht im Versionskontrollsystem erfasst (siehe .gitignore).

Lokale SQLite-Puffer (*.db) und Audit-Chains (aegis_chain.dat) sind rein laufzeitbezogen.

