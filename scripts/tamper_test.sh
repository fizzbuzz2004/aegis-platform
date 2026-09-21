#!/usr/bin/env bash
set -e

# Alte Test-Logkette vor neuem Durchlauf aufräumen
rm -f /tmp/aegis_chain.dat

echo "=== 1. Starte Control Plane im Hintergrund ==="
python3 -m uvicorn control-plane.app.main:app --port 8000 &
SERVER_PID=$!
sleep 2

trap "kill $SERVER_PID 2>/dev/null || true" EXIT

echo "=== 2. Führe Agenten-Sync-Lauf aus ==="
PYTHONPATH=. python3 agent/cli/cli.py status
PYTHONPATH=. AEGIS_SYNC_INTERVAL=1 python3 -c "
from agent.core.worm_logger import WormChainLogger
from agent.modules.cis_hardening.runner import run
logger = WormChainLogger()
run({'logger': logger})
"

echo "=== 3. Prüfe WORM-Log-Chain (Soll: VALID) ==="
PYTHONPATH=. python3 agent/cli/cli.py verify

echo "=== 4. Manipuliere Log-Datei (Injektion gefälschter Daten) ==="
echo "badhash000|0000000000000000000000000000000000000000000000000000000000000000|12345|FORGED_ENTRY" >> /tmp/aegis_chain.dat

echo "=== 5. Prüfe WORM-Log-Chain erneut (Soll: ERKENNUNG / FEHLER) ==="
if PYTHONPATH=. python3 agent/cli/cli.py verify; then
    echo "❌ FEHLER: Tampering wurde NICHT erkannt!"
    exit 1
else
    echo "✅ ERFOLG: Tampering wurde zuverlässig abgefangen!"
fi
