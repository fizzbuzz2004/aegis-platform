#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$REPOSITORY_ROOT/.env" ]]; then
    ENV_FILE="$REPOSITORY_ROOT/.env"
elif [[ -f "$REPOSITORY_ROOT/control-plane/.env" ]]; then
    ENV_FILE="$REPOSITORY_ROOT/control-plane/.env"
else
    echo "No .env file found at repository root or control-plane/.env." >&2
    echo "Copy .env.example to one of those locations and set SECRET_KEY and ADMIN_INITIAL_PASSWORD." >&2
    exit 1
fi

dotenv_project_name="$(sed -n 's/^[[:space:]]*COMPOSE_PROJECT_NAME[[:space:]]*=[[:space:]]*//p' "$ENV_FILE" | tail -n 1 | tr -d '\r' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-${dotenv_project_name:-aegis-platform}}"
export COMPOSE_PROJECT_NAME

compose=(docker compose --env-file "$ENV_FILE" --project-directory "$REPOSITORY_ROOT" -p "$COMPOSE_PROJECT_NAME" -f "$REPOSITORY_ROOT/docker-compose.yml")

cd "$REPOSITORY_ROOT"
docker info >/dev/null
"${compose[@]}" config --quiet

echo "Stopping existing services for project $COMPOSE_PROJECT_NAME (database volume is preserved)..."
if ! "${compose[@]}" down --remove-orphans --timeout 30; then
    echo "Compose down reported stale state; removing only existing containers labeled for this project."
    mapfile -t project_containers < <(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
    if ((${#project_containers[@]})); then
        docker rm -f "${project_containers[@]}"
    fi
fi

echo "Rebuilding Control Plane image..."
"${compose[@]}" build --pull --no-cache control-plane

echo "Starting services..."
"${compose[@]}" up -d --force-recreate --remove-orphans

for attempt in $(seq 1 60); do
    all_healthy=true
    for service in postgres control-plane; do
        container_id="$("${compose[@]}" ps -q "$service")"
        if [[ -z "$container_id" ]]; then
            all_healthy=false
            break
        fi
        state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
        if [[ "$state" != "healthy" ]]; then
            all_healthy=false
            break
        fi
    done

    if [[ "$all_healthy" == true ]]; then
        "${compose[@]}" ps
        echo "All services are healthy."
        exit 0
    fi
    sleep 2
done

echo "Timed out waiting for healthy services." >&2
"${compose[@]}" ps >&2 || true
"${compose[@]}" logs --tail 100 >&2 || true
exit 1