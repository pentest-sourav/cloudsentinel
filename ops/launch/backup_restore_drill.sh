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
backup_error="$ARTIFACT_DIR/backup-error.txt"
if ! compose exec -T \
  -e PGPASSWORD="$POSTGRES_PASSWORD" \
  postgres \
  pg_dump \
  --format=custom \
  --no-owner \
  --no-acl \
  --file=- \
  -U "$POSTGRES_USER" \
  -d "$POSTGRES_DB" > "$DUMP" 2> "$backup_error"; then
  echo "PostgreSQL backup failed. Container diagnostics:"
  cat "$backup_error" >&2 || true
  compose ps >&2 || true
  compose logs --no-color --tail=100 postgres >&2 || true
  exit 1
fi
backup_seconds=$((SECONDS - start))

test -s "$DUMP"
if ! compose exec -T postgres pg_restore --list - < "$DUMP" >/dev/null 2> "$backup_error"; then
  echo "PostgreSQL backup archive validation failed:" >&2
  cat "$backup_error" >&2 || true
  exit 1
fi

echo "Restoring backup into an isolated database..."
compose exec -T   -e PGPASSWORD="$POSTGRES_PASSWORD"   postgres   psql   -U "$POSTGRES_USER"   -d postgres   -v ON_ERROR_STOP=1   -c "DROP DATABASE IF EXISTS cloudsentinel_restore_drill"   -c "CREATE DATABASE cloudsentinel_restore_drill"

start=$SECONDS
compose exec -T   -e PGPASSWORD="$POSTGRES_PASSWORD"   postgres   pg_restore   --no-owner   --no-acl   --dbname=cloudsentinel_restore_drill   - < "$DUMP"
restore_seconds=$((SECONDS - start))

tenant_count="$(
  compose exec -T     -e PGPASSWORD="$POSTGRES_PASSWORD"     postgres     psql     -U "$POSTGRES_USER"     -d cloudsentinel_restore_drill     -tAc "SELECT count(*) FROM tenants"
)"

user_count="$(
  compose exec -T     -e PGPASSWORD="$POSTGRES_PASSWORD"     postgres     psql     -U "$POSTGRES_USER"     -d cloudsentinel_restore_drill     -tAc "SELECT count(*) FROM users"
)"

test "$tenant_count" -ge 1
test "$user_count" -ge 1

compose exec -T   -e PGPASSWORD="$POSTGRES_PASSWORD"   postgres   psql   -U "$POSTGRES_USER"   -d postgres   -v ON_ERROR_STOP=1   -c "DROP DATABASE cloudsentinel_restore_drill"

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
