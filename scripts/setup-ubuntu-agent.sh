#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/setup-ubuntu-agent.sh <shared-bundle-folder>" >&2
  exit 1
fi

BUNDLE_ROOT="${1:-}"
if [[ -z "$BUNDLE_ROOT" ]]; then
  echo "Usage: sudo bash scripts/setup-ubuntu-agent.sh <shared-bundle-folder>" >&2
  exit 2
fi
BUNDLE_DIR="$BUNDLE_ROOT/ubuntu-agent"
ADDRESS_FILE="$BUNDLE_ROOT/control-plane-ip.txt"
if [[ ! -s "$ADDRESS_FILE" || ! -s "$BUNDLE_DIR/aegis-agent-linux" ]]; then
  echo "Control-plane bundle is missing. Run setup-control-plane.sh first." >&2
  exit 1
fi
for file in ca.crt client.crt client.key; do
  if [[ ! -s "$BUNDLE_DIR/$file" ]]; then
    echo "Missing agent certificate: $BUNDLE_DIR/$file" >&2
    exit 1
  fi
done
CONTROL_PLANE_IP="$(<"$ADDRESS_FILE")"
python3 -c 'import ipaddress, sys; ipaddress.IPv4Address(sys.argv[1])' "$CONTROL_PLANE_IP" \
  || { echo "Invalid control-plane IPv4 address in bundle." >&2; exit 1; }

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required on the Ubuntu agent VM." >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  apt-get update
  apt-get install -y curl
fi

systemctl stop aegis-agent.service 2>/dev/null || true
install -d -m 700 /etc/aegis/pki /var/log/aegis
install -m 644 "$BUNDLE_DIR/ca.crt" /etc/aegis/pki/ca.crt
install -m 644 "$BUNDLE_DIR/client.crt" /etc/aegis/pki/client.crt
install -m 600 "$BUNDLE_DIR/client.key" /etc/aegis/pki/client.key
install -m 755 "$BUNDLE_DIR/aegis-agent-linux" /usr/local/bin/aegis-agent

echo "Waiting for the control plane..."
ready=false
for attempt in $(seq 1 60); do
  if curl --silent --show-error --fail \
    --cacert /etc/aegis/pki/ca.crt \
    --cert /etc/aegis/pki/client.crt \
    --key /etc/aegis/pki/client.key \
    "https://$CONTROL_PLANE_IP:8000/docs" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [[ "$ready" != true ]]; then
  echo "Cannot reach https://$CONTROL_PLANE_IP:8000 with the shared test certificate." >&2
  echo "Check that the control plane is healthy and port 8000 is reachable, then retry." >&2
  exit 1
fi
/usr/local/bin/aegis-agent -server "https://$CONTROL_PLANE_IP:8000" \
  -register enroll_pilot_2026 -once -debug

cat > /etc/systemd/system/aegis-agent.service <<EOF
[Unit]
Description=Aegis VirtualBox test agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aegis-agent -server https://$CONTROL_PLANE_IP:8000 -debug
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now aegis-agent.service
echo
systemctl --no-pager --full status aegis-agent.service
echo "Follow agent activity with: sudo journalctl -u aegis-agent -f"
