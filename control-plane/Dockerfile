# 1. Build-Phase
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Abhängigkeiten kopieren und herunterladen (für besseres Caching)
COPY go.mod go.sum ./
RUN go mod download

# Quellcode kopieren
COPY . .

# Statisch verlinktes Binary bauen
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/control-plane .

# 2. Laufzeit-Phase (minimales Image)
FROM alpine:3.19

# CA-Zertifikate für HTTPS-Requests installieren
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Gebautes Binary aus der Build-Phase kopieren
COPY --from=builder /app/control-plane /app/control-plane

EXPOSE 8080

ENTRYPOINT ["/app/control-plane"]
