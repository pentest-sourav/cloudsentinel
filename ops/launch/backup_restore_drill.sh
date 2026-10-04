#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker-compose.prod.yml}"
OVERLAY_FILE="${OVERLAY_FILE:-deploy/docker-compose.launch.yml}"
PROJECT="${COMPOSE_PROJECT_NAME:-cloudsentinel-launch}"
POSTGRES_USER="${POSTGRES_USER:-cloudsentinel}"
POSTGRES_DB="${POSTGRES_DB:-cloudsentinel}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}"
ARTIFACT_DIR="${LAUNCH_ARTIFACT_DIR:-artifacts/launch-certification}"

mkdir -p "$ARTIFACT_DIR"
DUMP="$ARTIFACT_DIR/cloudsentinel-postgres-launch-drill.dump"

compose() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" -f "$OVERLAY_FILE" "$@"
}

echo "Creating isolated PostgreSQL backup..."
start=$SECONDS
CONTAINER_DUMP="/tmp/cloudsentinel-postgres-launch-drill.dump"
CONTAINER_RESTORE="/tmp/cloudsentinel-postgres-launch-restore.dump"
backup_error="$ARTIFACT_DIR/backup-error.txt"

echo "Checking PostgreSQL readiness..."
if ! compose exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" > "$ARTIFACT_DIR/pg-isready.txt" 2> "$backup_error"; then
  echo "PostgreSQL is not ready:"
  cat "$backup_error" >&2 || true
  cat "$ARTIFACT_DIR/pg-isready.txt" >&2 || true
  compose ps >&2 || true
  compose logs --no-color --tail=100 postgres >&2 || true
  exit 1
fi

echo "Running pg_dump inside the PostgreSQL container..."
if ! compose exec -T \
  -e PGPASSWORD="$POSTGRES_PASSWORD" \
  postgres \
  sh -c 'rm -f "$1" && pg_dump --format=custom --no-owner --no-acl -U "$2" -d "$3" -f "$1"' \
  sh "$CONTAINER_DUMP" "$POSTGRES_USER" "$POSTGRES_DB" > "$ARTIFACT_DIR/pg-dump.stdout" 2> "$backup_error"; then
  echo "PostgreSQL pg_dump failed:"
  cat "$backup_error" >&2 || true
  cat "$ARTIFACT_DIR/pg-dump.stdout" >&2 || true
  compose ps >&2 || true
  compose logs --no-color --tail=100 postgres >&2 || true
  exit 1
fi

if ! compose cp "postgres:$CONTAINER_DUMP" "$DUMP" > "$ARTIFACT_DIR/pg-cp.stdout" 2> "$backup_error"; then
  echo "Failed to copy PostgreSQL backup out of the container:"
  cat "$backup_error" >&2 || true
  cat "$ARTIFACT_DIR/pg-cp.stdout" >&2 || true
  exit 1
fi

compose exec -T postgres rm -f "$CONTAINER_DUMP" || true
backup_seconds=$((SECONDS - start))

if [ ! -s "$DUMP" ]; then
  echo "PostgreSQL backup archive is empty." >&2
  ls -lh "$DUMP" >&2 || true
  exit 1
fi

echo "Validating PostgreSQL backup archive..."
if ! pg_restore --list "$DUMP" > "$ARTIFACT_DIR/pg-restore-list.txt" 2> "$backup_error"; then
  echo "PostgreSQL backup archive validation failed:" >&2
  cat "$backup_error" >&2 || true
  exit 1
fi

echo "Restoring backup into an isolated database..."
if ! compose cp "$DUMP" "postgres:$CONTAINER_RESTORE" > "$ARTIFACT_DIR/pg-restore-cp.stdout" 2> "$backup_error"; then
  echo "Failed to copy PostgreSQL backup into the container:" >&2
  cat "$backup_error" >&2 || true
  cat "$ARTIFACT_DIR/pg-restore-cp.stdout" >&2 || true
  exit 1
fi

compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS cloudsentinel_restore_drill" -c "CREATE DATABASE cloudsentinel_restore_drill"

start=$SECONDS
if ! compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres pg_restore --no-owner --no-acl --dbname=cloudsentinel_restore_drill "$CONTAINER_RESTORE" > "$ARTIFACT_DIR/pg-restore.stdout" 2> "$backup_error"; then
  echo "PostgreSQL restore failed:" >&2
  cat "$backup_error" >&2 || true
  cat "$ARTIFACT_DIR/pg-restore.stdout" >&2 || true
  exit 1
fi
restore_seconds=$((SECONDS - start))

tenant_count="$(
  compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres psql -U "$POSTGRES_USER" -d cloudsentinel_restore_drill -tAc "SELECT count(*) FROM tenants"
)"

user_count="$(
  compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres psql -U "$POSTGRES_USER" -d cloudsentinel_restore_drill -tAc "SELECT count(*) FROM users"
)"

test "$tenant_count" -ge 1
test "$user_count" -ge 1

compose exec -T -e PGPASSWORD="$POSTGRES_PASSWORD" postgres psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE cloudsentinel_restore_drill"
compose exec -T postgres rm -f "$CONTAINER_RESTORE" || true

cat > "$ARTIFACT_DIR/backup-restore-evidence.txt" <<EOF
CloudSentinel PostgreSQL launch certification drill
backup_seconds=$backup_seconds
restore_seconds=$restore_seconds
restored_tenant_count=$tenant_count
restored_user_count=$user_count
status=PASS
EOF

echo "backup/restore drill: PASS"
echo "  backup_seconds=$backup_seconds"
echo "  restore_seconds=$restore_seconds"
echo "  restored_tenant_count=$tenant_count"
echo "  restored_user_count=$user_count"
