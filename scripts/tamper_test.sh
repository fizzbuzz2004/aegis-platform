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

echo "=== 2. Führe Agenten-Sync-Lauf aus ==="
PYTHONPATH=. python3 agent/cli/cli.py status

# Nutzen des neuen RMM-Modus (--once) statt des manuellen Imports
PYTHONPATH=. python3 agent/main.py --once

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
