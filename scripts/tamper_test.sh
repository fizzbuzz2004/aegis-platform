#!/usr/bin/env bash
set -e

rm -f /tmp/aegis_chain.dat control_plane.sqlite

echo "=== 1. Starte Control Plane im Hintergrund ==="
cd control-plane
python3 -m uvicorn app.main:app --port 8000 &
SERVER_PID=$!
cd ..
sleep 2

trap "kill $SERVER_PID 2>/dev/null || true" EXIT

echo "=== 2. Führe Agenten im RMM-Modus (--once) aus ==="
PYTHONPATH=. python3 agent/main.py --once

echo "=== 3. Prüfe WORM-Log-Chain (Soll: VALID) ==="
PYTHONPATH=. python3 agent/cli/cli.py verify

echo "=== 4. Manipuliere Log-Datei (Injektion gefälschter Daten) ==="
CHAIN_FILE="/var/log/aegis/aegis_chain.dat"
if [ ! -f "$CHAIN_FILE" ]; then
    CHAIN_FILE="/tmp/aegis_chain.dat"
fi
echo "badhash000|0000000000000000000000000000000000000000000000000000000000000000|2026-09-21T12:00:00Z|FORGED_ENTRY" >> "$CHAIN_FILE"

echo "=== 5. Prüfe WORM-Log-Chain erneut (Soll: ERKENNUNG) ==="
if PYTHONPATH=. python3 agent/cli/cli.py verify; then
    echo "❌ FEHLER: Tampering wurde NICHT erkannt!"
    exit 1
else
    echo "✅ ERFOLG: Tampering wurde zuverlässig abgefangen!"
fi
