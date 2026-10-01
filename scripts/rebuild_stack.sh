#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_ENV_FILE="$REPOSITORY_ROOT/.env"
CONTROL_PLANE_ENV_FILE="$REPOSITORY_ROOT/control-plane/.env"

if [[ -n "${AEGIS_ENV_FILE:-}" ]]; then
    if [[ "$AEGIS_ENV_FILE" = /* ]]; then
        ENV_FILE="$AEGIS_ENV_FILE"
    else
        ENV_FILE="$REPOSITORY_ROOT/$AEGIS_ENV_FILE"
    fi
    if [[ ! -f "$ENV_FILE" ]]; then
        echo "AEGIS_ENV_FILE does not exist: $ENV_FILE" >&2
        exit 1
    fi
elif [[ -f "$ROOT_ENV_FILE" && -f "$CONTROL_PLANE_ENV_FILE" ]]; then
    if cmp -s "$ROOT_ENV_FILE" "$CONTROL_PLANE_ENV_FILE"; then
        ENV_FILE="$ROOT_ENV_FILE"
    else
        echo "Both root .env and control-plane/.env exist and differ." >&2
        echo "Choose the intended file explicitly, e.g. AEGIS_ENV_FILE=control-plane/.env bash scripts/rebuild_stack.sh" >&2
        exit 1
    fi
elif [[ -f "$ROOT_ENV_FILE" ]]; then
    ENV_FILE="$ROOT_ENV_FILE"
elif [[ -f "$CONTROL_PLANE_ENV_FILE" ]]; then
    ENV_FILE="$CONTROL_PLANE_ENV_FILE"
else
    echo "No .env file found at repository root or control-plane/.env." >&2
    echo "Copy .env.example to one of those locations and set SECRET_KEY and ADMIN_INITIAL_PASSWORD." >&2
    exit 1
fi
echo "Using Compose environment file: ${ENV_FILE#"$REPOSITORY_ROOT"/}"

dotenv_project_name="$(sed -n 's/^[[:space:]]*COMPOSE_PROJECT_NAME[[:space:]]*=[[:space:]]*//p' "$ENV_FILE" | tail -n 1 | tr -d '\r' | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-${dotenv_project_name:-aegis-platform}}"
export COMPOSE_PROJECT_NAME

compose=(docker compose --env-file "$ENV_FILE" --project-directory "$REPOSITORY_ROOT" -p "$COMPOSE_PROJECT_NAME" -f "$REPOSITORY_ROOT/docker-compose.yml")
project_label="label=com.docker.compose.project=$COMPOSE_PROJECT_NAME"

cd "$REPOSITORY_ROOT"
docker info >/dev/null
"${compose[@]}" config --quiet

remove_project_runtime_state() {
    local container_id
    local network_id
    local remaining
    local project_containers=()
    local project_networks=()

    mapfile -t project_containers < <(docker ps -aq --filter "$project_label")
    for container_id in "${project_containers[@]}"; do
        if ! docker rm -f "$container_id" >/dev/null 2>&1 && docker inspect "$container_id" >/dev/null 2>&1; then
            echo "Could not remove project container $container_id" >&2
            return 1
        fi
    done

    mapfile -t project_networks < <(docker network ls -q --filter "$project_label")
    for network_id in "${project_networks[@]}"; do
        if ! docker network rm "$network_id" >/dev/null 2>&1 && docker network inspect "$network_id" >/dev/null 2>&1; then
            echo "Could not remove project network $network_id" >&2
            return 1
        fi
    done

    remaining="$(docker ps -aq --filter "$project_label")"
    if [[ -n "$remaining" ]]; then
        echo "Project containers remain after cleanup: $remaining" >&2
        return 1
    fi
}

echo "Stopping existing services for project $COMPOSE_PROJECT_NAME (database volume is preserved)..."
if ! "${compose[@]}" down --remove-orphans --timeout 30; then
    echo "Compose down reported stale state; reconciling objects labeled for this project."
fi
remove_project_runtime_state

echo "Rebuilding Control Plane image..."
"${compose[@]}" build --pull --no-cache control-plane

echo "Starting services..."
if ! "${compose[@]}" up -d --force-recreate --remove-orphans; then
    echo "Compose up failed; removing this project's stale containers/networks and retrying once." >&2
    remove_project_runtime_state
    if ! "${compose[@]}" up -d --force-recreate --remove-orphans; then
        echo "Compose up failed after project-scoped recovery; recent logs follow." >&2
        "${compose[@]}" ps -a >&2 || true
        "${compose[@]}" logs --tail 100 >&2 || true
        exit 1
    fi
fi

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