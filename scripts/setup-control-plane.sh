#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/setup-control-plane.sh <control-plane-ip> <shared-folder>" >&2
  exit 1
fi

CONTROL_PLANE_IP="${1:-}"
SHARED_FOLDER="${2:-}"
if [[ -z "$CONTROL_PLANE_IP" || -z "$SHARED_FOLDER" ]]; then
  echo "Usage: sudo bash scripts/setup-control-plane.sh <control-plane-ip> <shared-folder>" >&2
  exit 2
fi
python3 -c 'import ipaddress, sys; ipaddress.IPv4Address(sys.argv[1])' "$CONTROL_PLANE_IP" \
  || { echo "Use the control-plane VM's bridged IPv4 address." >&2; exit 2; }
if [[ ! -d "$SHARED_FOLDER" || ! -w "$SHARED_FOLDER" ]]; then
  echo "Shared folder must already be mounted and writable: $SHARED_FOLDER" >&2
  exit 1
fi

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPOSITORY_ROOT"

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    echo "Automatic Docker installation supports Ubuntu only." >&2
    exit 1
  fi
  apt-get update
  apt-get install -y ca-certificates curl openssl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "$VERSION_CODENAME" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

if ! command -v openssl >/dev/null 2>&1; then
  apt-get update
  apt-get install -y openssl
fi
systemctl enable --now docker
docker info >/dev/null
docker compose version

CA_DIR="$REPOSITORY_ROOT/certs/ca"
SERVER_DIR="$REPOSITORY_ROOT/certs/server"
UBUNTU_CLIENT_DIR="$REPOSITORY_ROOT/certs/clients/ubuntu-agent"
WINDOWS_CLIENT_DIR="$REPOSITORY_ROOT/certs/clients/windows-agent"
CA_KEY="$CA_DIR/ca.key"
CA_CERT="$CA_DIR/ca.crt"
SERVER_NAME_FILE="$CA_DIR/control-plane-ip.txt"
SERVER_CERT="$SERVER_DIR/server.crt"
SERVER_KEY="$SERVER_DIR/server.key"
CA_CREATED=false

mkdir -p "$CA_DIR" "$SERVER_DIR" "$UBUNTU_CLIENT_DIR" "$WINDOWS_CLIENT_DIR"
if [[ -e "$CA_KEY" || -e "$CA_CERT" || -e "$SERVER_NAME_FILE" ]]; then
  if [[ ! -s "$CA_KEY" || ! -s "$CA_CERT" || ! -s "$SERVER_NAME_FILE" ]]; then
    echo "Partial test CA found under certs/ca. Restore it or remove that specific test CA before retrying." >&2
    exit 1
  fi
  EXISTING_IP="$(<"$SERVER_NAME_FILE")"
  if [[ "$EXISTING_IP" != "$CONTROL_PLANE_IP" ]]; then
    echo "Existing test certificates are for $EXISTING_IP, not $CONTROL_PLANE_IP." >&2
    echo "Use the original IP or deliberately create a fresh test CA." >&2
    exit 1
  fi
else
  openssl req -quiet -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -subj "/CN=Aegis VirtualBox Test CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$CA_KEY" -out "$CA_CERT"
  printf '%s\n' "$CONTROL_PLANE_IP" > "$SERVER_NAME_FILE"
  CA_CREATED=true
fi

generate_server_certificate() {
  local request extensions san
  request="$(mktemp "$SERVER_DIR/server.XXXXXX.csr")"
  extensions="$(mktemp "$SERVER_DIR/server.XXXXXX.ext")"
  san="IP:127.0.0.1,IP:$CONTROL_PLANE_IP"
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$SERVER_KEY"
  openssl req -quiet -new -key "$SERVER_KEY" -subj "/CN=$CONTROL_PLANE_IP" -out "$request"
  cat > "$extensions" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EOF
  openssl x509 -req -in "$request" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -days 825 -sha256 -extfile "$extensions" -out "$SERVER_CERT"
  rm -f "$request" "$extensions"
  install -m 644 "$CA_CERT" "$SERVER_DIR/ca.crt"
}

generate_client_certificate() {
  local name="$1" directory="$2" key request extensions certificate
  key="$directory/client.key"
  request="$directory/client.csr"
  extensions="$directory/client.ext"
  certificate="$directory/client.crt"
  openssl req -quiet -new -newkey rsa:2048 -nodes \
    -subj "/CN=$name" -keyout "$key" -out "$request"
  cat > "$extensions" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
  openssl x509 -req -in "$request" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -days 825 -sha256 -extfile "$extensions" -out "$certificate"
  rm -f "$request" "$extensions"
  install -m 644 "$CA_CERT" "$directory/ca.crt"
  chmod 600 "$key"
}

WINDOWS_CERT_REFRESHED=false
if [[ ! -s "$SERVER_CERT" || ! -s "$SERVER_KEY" || ! -s "$SERVER_DIR/ca.crt" ]]; then
  generate_server_certificate
fi
for client in "$UBUNTU_CLIENT_DIR" "$WINDOWS_CLIENT_DIR"; do
  if [[ "$CA_CREATED" == true || ! -s "$client/client.crt" || ! -s "$client/client.key" || ! -s "$client/ca.crt" ]]; then
    generate_client_certificate "$(basename "$client")" "$client"
    if [[ "$client" == "$WINDOWS_CLIENT_DIR" ]]; then
      WINDOWS_CERT_REFRESHED=true
    fi
  fi
done
if [[ ! -s "$WINDOWS_CLIENT_DIR/client.p12" || "$WINDOWS_CERT_REFRESHED" == true ]]; then
  openssl pkcs12 -export -in "$WINDOWS_CLIENT_DIR/client.crt" \
    -inkey "$WINDOWS_CLIENT_DIR/client.key" -certfile "$CA_CERT" \
    -name windows-agent -passout pass: -out "$WINDOWS_CLIENT_DIR/client.p12"
fi
chmod 600 "$CA_KEY" "$SERVER_KEY" \
  "$UBUNTU_CLIENT_DIR/client.key" "$WINDOWS_CLIENT_DIR/client.key"
chmod 644 "$CA_CERT" "$SERVER_CERT" "$SERVER_DIR/ca.crt" \
  "$UBUNTU_CLIENT_DIR/client.crt" "$UBUNTU_CLIENT_DIR/ca.crt" \
  "$WINDOWS_CLIENT_DIR/client.crt" "$WINDOWS_CLIENT_DIR/ca.crt"
openssl verify -purpose sslserver -verify_ip "$CONTROL_PLANE_IP" \
  -CAfile "$SERVER_DIR/ca.crt" "$SERVER_CERT"
openssl verify -purpose sslclient -CAfile "$CA_CERT" "$UBUNTU_CLIENT_DIR/client.crt"
openssl verify -purpose sslclient -CAfile "$CA_CERT" "$WINDOWS_CLIENT_DIR/client.crt"
for pair in "$SERVER_CERT:$SERVER_KEY" \
  "$UBUNTU_CLIENT_DIR/client.crt:$UBUNTU_CLIENT_DIR/client.key" \
  "$WINDOWS_CLIENT_DIR/client.crt:$WINDOWS_CLIENT_DIR/client.key"; do
  certificate="${pair%%:*}"
  key="${pair#*:}"
  certificate_public_key="$(openssl x509 -in "$certificate" -pubkey -noout | openssl sha256)"
  private_public_key="$(openssl pkey -in "$key" -pubout | openssl sha256)"
  if [[ "$certificate_public_key" != "$private_public_key" ]]; then
    echo "Certificate and private key do not match: $certificate" >&2
    exit 1
  fi
done
openssl pkcs12 -in "$WINDOWS_CLIENT_DIR/client.p12" -passin pass: -info -noout >/dev/null 2>&1

if [[ ! -f .env ]]; then
  cp .env.example .env
fi
if ! grep -q '^SECRET_KEY=.' .env; then
  if grep -q '^SECRET_KEY=' .env; then
    sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$(openssl rand -hex 32)/" .env
  else
    printf 'SECRET_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
  fi
fi
if ! grep -q '^ADMIN_INITIAL_PASSWORD=.' .env; then
  if grep -q '^ADMIN_INITIAL_PASSWORD=' .env; then
    sed -i 's/^ADMIN_INITIAL_PASSWORD=.*/ADMIN_INITIAL_PASSWORD=AegisLab2026!/' .env
  else
    printf 'ADMIN_INITIAL_PASSWORD=AegisLab2026!\n' >> .env
  fi
fi

BUNDLE_ROOT="$SHARED_FOLDER/aegis-vbox"
mkdir -p "$BUNDLE_ROOT/ubuntu-agent" "$BUNDLE_ROOT/windows-agent"
printf '%s\n' "$CONTROL_PLANE_IP" > "$BUNDLE_ROOT/control-plane-ip.txt"
for client in ubuntu-agent windows-agent; do
  source_dir="$REPOSITORY_ROOT/certs/clients/$client"
  bundle_dir="$BUNDLE_ROOT/$client"
  cp "$source_dir/ca.crt" "$bundle_dir/ca.crt"
  cp "$source_dir/client.crt" "$bundle_dir/client.crt"
  cp "$source_dir/client.key" "$bundle_dir/client.key"
done
cp "$WINDOWS_CLIENT_DIR/client.p12" "$BUNDLE_ROOT/windows-agent/client.p12"

mkdir -p "$REPOSITORY_ROOT/dist"
BUILD_DIR="$(mktemp -d "$REPOSITORY_ROOT/dist/.aegis-agent-build.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT
docker run --rm \
  -v "$REPOSITORY_ROOT:/src" \
  -v "$BUILD_DIR:/build" \
  -w /src/agent-go \
  golang:1.23-alpine \
  sh -ec 'GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /build/aegis-agent-linux .; GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /build/aegis-agent.exe .'
cp "$BUILD_DIR/aegis-agent-linux" "$BUNDLE_ROOT/ubuntu-agent/aegis-agent-linux"
cp "$BUILD_DIR/aegis-agent.exe" "$BUNDLE_ROOT/windows-agent/aegis-agent.exe"

docker compose up -d --build
healthy=false
for attempt in $(seq 1 90); do
  healthy=true
  for service in postgres control-plane; do
    container_id="$(docker compose ps -q "$service")"
    if [[ -z "$container_id" ]]; then
      healthy=false
      break
    fi
    state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
    if [[ "$state" != "healthy" ]]; then
      healthy=false
      break
    fi
  done
  [[ "$healthy" == true ]] && break
  sleep 2
done

if [[ "$healthy" != true ]]; then
  echo "Control-plane services did not become healthy. Recent logs:" >&2
  docker compose ps -a >&2 || true
  docker compose logs --tail 100 >&2 || true
  exit 1
fi

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 8000/tcp
fi

echo
docker compose ps
echo "Control plane: https://$CONTROL_PLANE_IP:8000"
echo "Dashboard:     https://$CONTROL_PLANE_IP:8000/api/v1/dashboard/ui"
echo "Shared bundles: $BUNDLE_ROOT"
echo "Dashboard login: admin"
echo "Dashboard password: $(sed -n 's/^ADMIN_INITIAL_PASSWORD=//p' .env | tail -n 1)"
echo "Keep certs/ca/ca.key on this VM; never copy it to an agent."
