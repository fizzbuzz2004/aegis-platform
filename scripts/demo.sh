#!/usr/bin/env bash
set -e

rm -f control_plane.sqlite /tmp/aegis_chain.dat

echo "=== 1. Starte Control Plane ==="
cd control-plane
python3 -m uvicorn app.main:app --port 8000 > /dev/null 2>&1 &
SERVER_PID=$!
cd ..
sleep 2
trap "kill $SERVER_PID 2>/dev/null || true" EXIT

echo -e "\n=== 2. Agent führt Standard-Module (CIS) aus ==="
PYTHONPATH=. python3 agent/main.py --once

echo -e "\n=== 3. SYSTEMHAUS-AKTION: Aktiviere Backup-Probe per API (Remote) ==="
curl -s -X POST "http://127.0.0.1:8000/api/v1/admin/toggle" \
     -H "Content-Type: application/json" \
     -d '{"tenant_id": 1, "module_name": "backup_probe", "enable": true}' | jq .

echo -e "\n\n=== 4. Agent holt neue Konfig & prüft Backup-Status ==="
PYTHONPATH=. python3 agent/main.py --once

echo -e "\n=== 5. SYSTEMHAUS-DASHBOARD: Abfrage der zentralen Ergebnisse ==="
curl -s "http://127.0.0.1:8000/api/v1/admin/results/1" | jq .
