#!/usr/bin/env python3
"""Production PostgreSQL backup and restore verification utility.

Commands:
  backup  Create an atomic compressed custom-format pg_dump and manifest.
  verify  Verify a backup checksum and pg_restore archive readability.
  restore Restore a verified backup into an explicitly supplied database URL.

The dump/restore binaries can be pinned with PG_DUMP_BIN and PG_RESTORE_BIN.
BACKUP_EXPECTED_POSTGRES_MAJOR can be set to fail fast when the configured
client major version does not match the PostgreSQL server major version.
Optional S3 replication is enabled with BACKUP_S3_BUCKET. Credentials are
resolved by the AWS SDK default credential chain; no credentials are stored
by this utility.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path


def database_url() -> str:
    value = os.environ.get("DATABASE_URL")
    if not value:
        raise RuntimeError("DATABASE_URL must be set")
    return value


def libpq_url(value: str) -> str:
    """Convert SQLAlchemy's psycopg URL into a libpq-compatible URL."""
    if value.startswith("postgresql+psycopg://"):
        return "postgresql://" + value.removeprefix("postgresql+psycopg://")
    return value


def require_binary(name: str, env_name: str | None = None) -> str:
    configured = os.environ.get(env_name, "").strip() if env_name else ""
    candidate = configured or name
    path = shutil.which(candidate)
    if not path:
        raise RuntimeError(
            f"Required executable not found: {candidate}. "
            f"Set {env_name} to the pinned binary path."
            if env_name
            else f"Required executable not found: {candidate}"
        )
    return path


def postgres_binary(name: str, env_name: str) -> str:
    return require_binary(name, env_name)


def binary_major_version(binary: str) -> str:
    result = subprocess.run(
        [binary, "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    tokens = result.stdout.strip().split()
    if len(tokens) < 3:
        raise RuntimeError(f"Unable to determine PostgreSQL client version: {result.stdout!r}")
    return tokens[2].split(".", 1)[0]


def validate_expected_major(binary: str) -> None:
    expected = os.environ.get("BACKUP_EXPECTED_POSTGRES_MAJOR", "").strip()
    if not expected:
        return
    actual = binary_major_version(binary)
    if actual != expected:
        raise RuntimeError(
            f"PostgreSQL client major mismatch: expected {expected}, got {actual} "
            f"from {binary}"
        )


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_for(backup: Path, sha256: str) -> dict[str, object]:
    return {
        "format": "postgresql-custom",
        "created_at": datetime.now(UTC).isoformat(),
        "filename": backup.name,
        "size_bytes": backup.stat().st_size,
        "sha256": sha256,
    }


def write_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def s3_client():
    import boto3

    return boto3.client("s3")


def upload_to_s3(backup: Path, manifest_path: Path) -> None:
    bucket = os.environ.get("BACKUP_S3_BUCKET")
    if not bucket:
        return

    prefix = os.environ.get("BACKUP_S3_PREFIX", "cloudsentinel/postgres")
    prefix = prefix.strip("/")
    client = s3_client()

    extra_args = {"ServerSideEncryption": "AES256"}
    kms_key = os.environ.get("BACKUP_S3_KMS_KEY_ID")
    if kms_key:
        extra_args = {
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": kms_key,
        }

    for path in (backup, manifest_path):
        key = f"{prefix}/{path.name}"
        client.upload_file(
            str(path),
            bucket,
            key,
            ExtraArgs=extra_args,
        )


def prune_local(directory: Path, retention_days: int) -> None:
    if retention_days <= 0:
        return

    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    for path in directory.glob("cloudsentinel-postgres-*.dump"):
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        if modified < cutoff:
            manifest = path.with_suffix(".json")
            path.unlink(missing_ok=True)
            manifest.unlink(missing_ok=True)


def backup(output_dir: Path) -> Path:
    pg_dump = postgres_binary("pg_dump", "PG_DUMP_BIN")
    validate_expected_major(pg_dump)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"cloudsentinel-postgres-{timestamp}.dump"
    manifest_path = path.with_suffix(".json")
    temp_path = output_dir / f".{path.name}.tmp"

    temp_path.unlink(missing_ok=True)
    try:
        run(
            [
                pg_dump,
                "--format=custom",
                "--no-owner",
                "--no-acl",
                "--file",
                str(temp_path),
                libpq_url(database_url()),
            ]
        )
        if not temp_path.is_file() or temp_path.stat().st_size == 0:
            raise RuntimeError("pg_dump completed without producing a non-empty archive")
        os.replace(temp_path, path)

        sha256 = checksum(path)
        write_manifest(path=manifest_path, manifest=manifest_for(path, sha256))
        upload_to_s3(path, manifest_path)

        retention = int(os.environ.get("BACKUP_LOCAL_RETENTION_DAYS", "14"))
        prune_local(output_dir, retention)
        print(path)
        return path
    finally:
        temp_path.unlink(missing_ok=True)


def load_manifest(backup_path: Path) -> dict[str, object]:
    manifest_path = backup_path.with_suffix(".json")
    if not manifest_path.exists():
        raise RuntimeError(f"Backup manifest not found: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def verify(backup_path: Path) -> None:
    pg_restore = postgres_binary("pg_restore", "PG_RESTORE_BIN")
    validate_expected_major(pg_restore)
    if not backup_path.is_file():
        raise RuntimeError(f"Backup does not exist: {backup_path}")
    if backup_path.stat().st_size == 0:
        raise RuntimeError(f"Backup is empty: {backup_path}")

    manifest = load_manifest(backup_path)
    if manifest.get("format") != "postgresql-custom":
        raise RuntimeError("Unsupported backup manifest format")
    expected = manifest.get("sha256")
    actual = checksum(backup_path)
    if expected != actual:
        raise RuntimeError(f"Checksum mismatch: expected {expected}, got {actual}")

    run([pg_restore, "--list", str(backup_path)])
    print(f"verified: {backup_path}")


def restore(backup_path: Path, target_url: str) -> None:
    pg_restore = postgres_binary("pg_restore", "PG_RESTORE_BIN")
    validate_expected_major(pg_restore)
    verify(backup_path)

    if not target_url:
        raise RuntimeError("A target database URL is required")

    if libpq_url(database_url()) == libpq_url(target_url):
        raise RuntimeError(
            "Refusing to restore over DATABASE_URL; use an isolated target database"
        )

    run(
        [
            pg_restore,
            "--clean",
            "--if-exists",
            "--exit-on-error",
            "--no-owner",
            "--no-acl",
            "--dbname",
            libpq_url(target_url),
            str(backup_path),
        ]
    )
    print(f"restored: {backup_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CloudSentinel PostgreSQL backup utility")
    sub = parser.add_subparsers(dest="command", required=True)

    backup_parser = sub.add_parser("backup")
    backup_parser.add_argument(
        "--output-dir",
        default=os.environ.get("BACKUP_OUTPUT_DIR", "./backups/postgres"),
        type=Path,
    )

    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("backup", type=Path)

    restore_parser = sub.add_parser("restore")
    restore_parser.add_argument("backup", type=Path)
    restore_parser.add_argument(
        "--target-database-url",
        default=os.environ.get("RESTORE_DATABASE_URL", ""),
    )
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        if args.command == "backup":
            backup(args.output_dir)
        elif args.command == "verify":
            verify(args.backup)
        elif args.command == "restore":
            restore(args.backup, args.target_database_url)
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"backup utility command failed with exit code {exc.returncode}", file=sys.stderr)
        return 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"backup utility error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
