#!/usr/bin/env bash
set -e

echo "=== 1. Starte PostgreSQL Database Container ==="
docker-compose up -d postgres
echo "Warte auf Datenbank-Bereitschaft..."
sleep 4

echo -e "\n=== 2. Starte Aegis Control Plane Server ==="
export DATABASE_URL="postgresql://aegis_admin:aegis_secure_password_2026@127.0.0.1:5432/aegis_db"
export SECRET_KEY="aegis_demo_secret_key"
cd control-plane
python3 -m uvicorn app.main:app --port 8000 > /dev/null 2>&1 &
SERVER_PID=$!
cd ..
sleep 3
trap "kill $SERVER_PID 2>/dev/null || true" EXIT

echo -e "\n=== 3. Signiere Agenten-Module mit Ed25519 Key ==="
PYTHONPATH=. python3 scripts/sign_module.py agent/modules/cis_hardening/runner.py
PYTHONPATH=. python3 scripts/sign_module.py agent/modules/backup_probe/runner.py

echo -e "\n=== 4. Admin Authentifizierung via OAuth2 / JWT ==="
TOKEN=$(curl -s -X POST "http://127.0.0.1:8000/api/v1/auth/login" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&password=admin123" | jq -r .access_token)

echo "JWT Token erhalten: ${TOKEN:0:20}..."

echo -e "\n=== 5. Agent Durchlauf 1 (Führt nur zugelassene, signierte Module aus) ==="
PYTHONPATH=. python3 agent/main.py --once

echo -e "\n=== 6. Admin aktiviert Remote 'backup_probe' via JWT-gesicherten Endpunkt ==="
curl -s -X POST "http://127.0.0.1:8000/api/v1/admin/toggle" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"tenant_id": 1, "module_name": "backup_probe", "enable": true}' | jq .

echo -e "\n=== 7. Agent Durchlauf 2 (Führt dynamisch nachgeladenes Modul aus) ==="
PYTHONPATH=. python3 agent/main.py --once

echo -e "\n=== 8. Systemhaus Dashboard Abfrage (PostgreSQL Audits) ==="
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8000/api/v1/admin/results/1" | jq .
