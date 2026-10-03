#!/usr/bin/env bash
set -euo pipefail
umask 077

OUT_DIR="${1:-./certs}"
SERVER_NAME="${2:?Usage: $0 [output-dir] <server-dns-or-ip> <client-name>}"
CLIENT_NAME="${3:?Usage: $0 [output-dir] <server-dns-or-ip> <client-name>}"

[[ "$SERVER_NAME" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Invalid server DNS name or IPv4 address" >&2; exit 2; }
[[ "$CLIENT_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid client name" >&2; exit 2; }
command -v openssl >/dev/null || { echo "OpenSSL is required" >&2; exit 1; }

CA_DIR="$OUT_DIR/ca"
SERVER_DIR="$OUT_DIR/server"
CLIENT_DIR="$OUT_DIR/clients/$CLIENT_NAME"
mkdir -p "$CA_DIR" "$SERVER_DIR" "$CLIENT_DIR"
chmod 700 "$CA_DIR" "$SERVER_DIR" "$CLIENT_DIR"

if [[ ! -e "$CA_DIR/ca.crt" && ! -e "$CA_DIR/ca.key" ]]; then
  openssl genpkey -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:4096 -out "$CA_DIR/ca.key"
  openssl req -x509 -new -key "$CA_DIR/ca.key" -sha256 -days 3650 \
    -subj "/CN=Aegis Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$CA_DIR/ca.crt"
  chmod 600 "$CA_DIR/ca.key"
elif [[ ! -s "$CA_DIR/ca.crt" || ! -s "$CA_DIR/ca.key" ]]; then
  echo "CA certificate and encrypted private key must both exist" >&2
  exit 1
fi

cp "$CA_DIR/ca.crt" "$SERVER_DIR/ca.crt"
cp "$CA_DIR/ca.crt" "$CLIENT_DIR/ca.crt"

SAN="DNS:localhost,IP:127.0.0.1"
if [[ "$SERVER_NAME" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
  SAN="$SAN,IP:$SERVER_NAME"
else
  SAN="$SAN,DNS:$SERVER_NAME"
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$SERVER_DIR/server.key"
openssl req -new -key "$SERVER_DIR/server.key" -subj "/CN=$SERVER_NAME" -out "$SERVER_DIR/server.csr"
cat > "$SERVER_DIR/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF
openssl x509 -req -in "$SERVER_DIR/server.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
  -CAcreateserial -days 397 -sha256 -extfile "$SERVER_DIR/server.ext" -out "$SERVER_DIR/server.crt"
rm -f "$SERVER_DIR/server.csr" "$SERVER_DIR/server.ext"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$CLIENT_DIR/client.key"
openssl req -new -key "$CLIENT_DIR/client.key" -subj "/CN=$CLIENT_NAME" -out "$CLIENT_DIR/client.csr"
cat > "$CLIENT_DIR/client.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in "$CLIENT_DIR/client.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
  -CAcreateserial -days 397 -sha256 -extfile "$CLIENT_DIR/client.ext" -out "$CLIENT_DIR/client.crt"
openssl pkcs12 -export -in "$CLIENT_DIR/client.crt" -inkey "$CLIENT_DIR/client.key" \
  -certfile "$CA_DIR/ca.crt" -name "$CLIENT_NAME" -out "$CLIENT_DIR/client.p12"
rm -f "$CLIENT_DIR/client.csr" "$CLIENT_DIR/client.ext"
chmod 600 "$SERVER_DIR/server.key" "$CLIENT_DIR/client.key" "$CLIENT_DIR/client.p12"
chmod 644 "$CA_DIR/ca.crt" "$SERVER_DIR/server.crt" "$SERVER_DIR/ca.crt" "$CLIENT_DIR/client.crt" "$CLIENT_DIR/ca.crt"

printf 'Created TLS server material: %s\nCreated client identity: %s\nKeep %s/ca.key offline.\n' \
  "$SERVER_DIR" "$CLIENT_DIR" "$CA_DIR"
