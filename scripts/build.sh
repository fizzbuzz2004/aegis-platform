#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="dist"
AGENT_VERSION="${AEGIS_AGENT_VERSION:-dev}"
UPDATE_PUBLIC_KEY_B64="${AEGIS_UPDATE_SIGNING_PUBLIC_KEY_B64:-}"
LD_FLAGS="-s -w -X main.version=${AGENT_VERSION} -X github.com/aegis-platform/agent-go/core.updateSigningPublicKeyB64=${UPDATE_PUBLIC_KEY_B64}"
mkdir -p "${OUTPUT_DIR}"

echo "=== 1. Kompiliere Go Agent Cross-Platform Targets ==="
cd agent-go

# Windows x64
echo "Building Windows x64..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="${LD_FLAGS}" -o "../${OUTPUT_DIR}/aegis-agent-win-x64.exe" main.go

# Windows ARM64
echo "Building Windows ARM64..."
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="${LD_FLAGS}" -o "../${OUTPUT_DIR}/aegis-agent-win-arm64.exe" main.go

# Linux x64
echo "Building Linux x64..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="${LD_FLAGS}" -o "../${OUTPUT_DIR}/aegis-agent-linux-x64" main.go

# Linux ARM64
echo "Building Linux ARM64..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="${LD_FLAGS}" -o "../${OUTPUT_DIR}/aegis-agent-linux-arm64" main.go

cd ..
echo "✅ Alle Binaries erfolgreich gebaut in ./${OUTPUT_DIR}/"
