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
mkdir -p certs
bash scripts/generate_mtls_certs.sh ./certs <CONTROL_VM_IP> ubuntu-agent
bash scripts/generate_mtls_certs.sh ./certs <CONTROL_VM_IP> windows-agent
docker compose up -d --build
docker compose ps
```

Die Generatoren fragen das Passwort des Root-CA-Schlüssels und das Client-PFX-Passwort ab. `certs/server/` enthält nur Control-Plane-Material; `certs/ca/ca.key` bleibt offline und wird niemals auf eine VM kopiert. Alternativ unter Windows mit OpenSSL ausführen: `scripts/generate_mtls_certs.ps1 -OutputDirectory .\certs -ServerName <CONTROL_VM_IP> -ClientName ubuntu-agent` (für jeden Agenten mit eigenem `ClientName` wiederholen). Siehe „VirtualBox-Testnetz und mTLS“ für die sichere Verteilung.

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
AEGIS_MTLS_ENABLED=false uvicorn app.main:app --reload

Das HTTP-Kommando ist ausschließlich für isolierte lokale Entwicklung. Der produktive Compose-Start läuft über `python -m app.main` mit mTLS; direkter Uvicorn-Start ohne TLS-Material ist nicht für Agent-Verkehr geeignet.

Tests ausführen

# Go Agent Tests
cd agent-go && go test ./...

# Control-Plane Tests
cd control-plane && pytest

## VirtualBox-Testnetz und mTLS

Die VirtualBox-VMs verwenden Bridged Networking. Ermittle die IPv4-Adresse der Ubuntu-Control-VM mit `ip -4 -o addr show scope global`; verwende diese Adresse als `ServerName` und Agent-URL. Die Generatoren erstellen eine verschlüsselte Root-CA, ein Serverzertifikat sowie ein eigenes Client-Zertifikat samt verschlüsseltem PFX je Agent. OpenSSL muss auf dem Generierungsrechner installiert sein.

Die Compose-Control-Plane verlangt Client-Zertifikate am TLS-Listener. Gemountet wird ausschließlich `certs/server/` mit `server.crt`, `server.key` und `ca.crt`; `certs/ca/ca.key` bleibt offline. Verteile pro VM nur den eigenen Ordner `certs/clients/<client-name>/` über einen authentisierten, verschlüsselten Kanal. Committe `certs/` nicht. Private Agent-Schlüssel erhalten restriktive ACLs/Rechte; die CA-Datei ist öffentlich und darf verteilt werden.

Linux-Agent vorbereiten und registrieren:

```sh
sudo install -d -m 700 /etc/aegis/pki
sudo install -m 644 certs/clients/ubuntu-agent/ca.crt /etc/aegis/pki/ca.crt
sudo install -m 644 certs/clients/ubuntu-agent/client.crt /etc/aegis/pki/client.crt
sudo install -m 600 certs/clients/ubuntu-agent/client.key /etc/aegis/pki/client.key
sudo ./aegis-agent-linux -server https://<CONTROL_VM_IP>:8000 -register <enroll_code> -once
```

Windows als Administrator ausführen. Das Deployment-Skript setzt eine restriktive ACL auf `%ProgramData%\Aegis\pki`, importiert die CA in den Windows-Vertrauensspeicher und verwendet das PFX für Download und Registrierung. Das PFX-Passwort wird als SecureString abgefragt:

```powershell
.\scripts\deploy_rmm_windows.ps1 `
	-EnrollmentCode <enroll_code> `
	-ServerUrl https://<CONTROL_VM_IP>:8000 `
	-RootCACertificate .\certs\clients\windows-agent\ca.crt `
	-ClientCertificate .\certs\clients\windows-agent\client.crt `
	-ClientPrivateKey .\certs\clients\windows-agent\client.key `
	-ClientPfx .\certs\clients\windows-agent\client.p12 `
	-ClientPfxPassword (Read-Host -AsSecureString "Client PFX password")
```

Prüfe die Verbindung vom Ubuntu-Agenten, bevor du den Agent startest:

```sh
curl --fail --cacert /etc/aegis/pki/ca.crt \
	--cert /etc/aegis/pki/client.crt --key /etc/aegis/pki/client.key \
	https://<CONTROL_VM_IP>:8000/docs
```

Die Client-Routen behalten zusätzlich die Bearer-Token-Autorisierung. TLS verifiziert die Client-Kette einmal pro Verbindung; HTTP-Keepalive vermeidet unnötige Handshakes. Die Anwendung speichert derzeit keine Zertifikat-Fingerprints pro Host und prüft keine CRL. Bei Schlüsselverlust die betroffene Client-Identität, bei CA-Verlust die gesamte CA kontrolliert rotieren.

Der TLS-Test mit `curl --cacert --cert --key` oben prüft zugleich Erreichbarkeit, Server-Identität und Client-Zertifikat. TCP-Port 8000 muss von beiden Agent-VMs zur Control-VM erreichbar sein; die Agent-VMs müssen einander nicht erreichen.

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

Linux-Agenten speichern `host_token` nach erfolgreicher Registrierung in `/etc/aegis/config.json`; Windows speichert die Konfiguration unter `%ProgramData%\Aegis\config.json`.

```sh
sudo ./aegis-agent-linux -server https://<CONTROL_VM_IP>:8000 -register <enroll_code> -debug -once
sudo ./aegis-agent-linux -debug -once
```

`-debug` protokolliert Endpunkte, HTTP-Status und Netzwerkfehler, niemals den Tokenwert. Unter Linux benötigt das Anlegen der Konfiguration Schreibrechte für `/etc/aegis`; Windows muss mit Rechten zum Schreiben in ProgramData laufen.

## Agent Auto-Update (Linux und Windows)

Der Control-Plane-Endpunkt `GET /api/v1/agents/update` liefert Release-Metadaten nur an Hosts mit gültigem `Authorization: Bearer <host_token>`. Für Updates muss auch die Agent-URL der Control Plane HTTPS verwenden; bei einer HTTP-URL laufen normale Sync-Zyklen weiter, aber Auto-Update bleibt deaktiviert. Veröffentliche das Linux-Binary auf einem HTTPS-fähigen Artefaktserver und setze `AGENT_UPDATE_VERSION`, `AGENT_UPDATE_URL`, `AGENT_UPDATE_SHA256` und `AGENT_UPDATE_OS_INFO` in der Control-Plane-Umgebung. `AGENT_UPDATE_OS_INFO` muss zum Binary passen, zum Beispiel `linux-amd64` oder `linux-arm64`. Alle vier Werte müssen gesetzt sein; ohne Konfiguration ist Auto-Update deaktiviert. Berechne den Digest für exakt die ausgelieferte Datei, zum Beispiel mit `sha256sum aegis-agent-linux-x64`.

Baue jedes Release mit derselben Version im Binary, zum Beispiel `AEGIS_AGENT_VERSION=1.2.3 ./scripts/build.sh`. Linux und Windows rufen den Metadaten-Endpunkt über mTLS auf, laden die Datei über HTTPS und prüfen SHA-256. Linux ersetzt das Binary atomar und beendet sich für den systemd-Neustart. Windows startet einen PowerShell-Helfer, der auf das Ende des Agenten wartet, das bisherige Binary als `.old` sichert, das geprüfte Staging-Binary aktiviert und den Agenten mit den ursprünglichen Argumenten neu startet. Der Installationsordner muss für den Agenten schreibbar und auf Dienstkonto/Administratoren beschränkt sein. Metadaten- und Artefaktserver müssen über vertrauenswürdiges TLS erreichbar sein.

## Neue Agent-Probe

Lege eine Go-Datei in `agent-go/probes/` an und registriere einen `ProbeRunner` in `init()`. Beispiel: Die Probe `firewall_status` ist in `probes/firewall.go` umgesetzt und erscheint nach dem Build als Modulname. Für einen neuen Modulnamen wird kein Datenbankschema angepasst: `POST /api/v1/admin/toggle` legt einen unbekannten `TenantModule.module_name` als String an; der Agent führt ihn aus, wenn seine Probe mit exakt diesem Namen registriert ist.

```go
func init() {
	Register("mein_modul", func(ctx context.Context, pCtx ProbeContext) []Finding {
		return []Finding{{Status: "PASS", Code: "CHECK_OK", Severity: "INFO", Message: "Prüfung erfolgreich"}}
	})
}
```

## Control-Plane-Migration

Für bestehende Datenbanken vor dem aktualisierten Control-Plane-Start die SQL-Migrationen in Reihenfolge ausführen:

1. `control-plane/migrations/001_tenant_branding.sql`
2. `control-plane/migrations/002_msp_psa_rbac.sql`

Neue Datenbanken erhalten das Schema automatisch über SQLAlchemy `create_all`.

MSP-Techniker (`TECHNICIAN`, einschließlich bestehender `ADMIN`-Konten) haben globalen Zugriff. Customer-Admins (`CUSTOMER_ADMIN`) müssen einem Mandanten zugeordnet sein; Dashboard- und PDF-Abfragen sind auf diesen Mandanten begrenzt. Globale Techniker können Customer-Admin-Konten über `POST /api/v1/admin/users` anlegen.

PSA-Ziele werden mandantenbezogen unter `POST /api/v1/admin/tenants/{tenant_id}/psa-webhooks` konfiguriert. Unterstützte Payload-Profile sind `generic`, `autotask`, `connectwise`, `ninjaone` und `halopsa`. Die Zugangsdaten werden nicht über die Auflistungs-API zurückgegeben. Ein Backup-Probe-Ticket wird bei mindestens 48 Stunden anhaltendem Fehler oder ausbleibendem Ergebnis automatisch erstellt; der Dienst prüft zusätzlich alle 15 Minuten auf veraltete Ergebnisse.

🔒 Sicherheit & Hinweise
Das secrets/-Verzeichnis sowie .env-Dateien werden nicht im Versionskontrollsystem erfasst (siehe .gitignore).

Lokale SQLite-Puffer (*.db) und Audit-Chains (aegis_chain.dat) sind rein laufzeitbezogen.

