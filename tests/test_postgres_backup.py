import pytest
from pathlib import Path
from unittest.mock import patch

from ops.backup import postgres_backup


def test_manifest_contains_integrity_metadata(tmp_path: Path):
    backup = tmp_path / "cloudsentinel-postgres-test.dump"
    backup.write_bytes(b"backup-data")

    manifest = postgres_backup.manifest_for(
        backup,
        postgres_backup.checksum(backup),
    )

    assert manifest["format"] == "postgresql-custom"
    assert manifest["filename"] == backup.name
    assert manifest["size_bytes"] == len(b"backup-data")
    assert len(manifest["sha256"]) == 64


def test_verify_rejects_checksum_mismatch(tmp_path: Path):
    backup = tmp_path / "cloudsentinel-postgres-test.dump"
    backup.write_bytes(b"backup-data")
    postgres_backup.write_manifest(
        backup.with_suffix(".json"),
        {
            "format": "postgresql-custom",
            "filename": backup.name,
            "size_bytes": backup.stat().st_size,
            "sha256": "0" * 64,
        },
    )

    with patch.object(postgres_backup, "require_binary"):
        try:
            postgres_backup.verify(backup)
        except RuntimeError as exc:
            assert "Checksum mismatch" in str(exc)
        else:
            raise AssertionError("verify() accepted an invalid checksum")


def test_prune_local_removes_expired_backup_and_manifest(tmp_path: Path):
    backup = tmp_path / "cloudsentinel-postgres-old.dump"
    manifest = backup.with_suffix(".json")
    backup.write_bytes(b"old")
    manifest.write_text("{}")
    
    import os
    import time

    old_time = time.time() - 3 * 86400
    os.utime(backup, (old_time, old_time))
    os.utime(manifest, (old_time, old_time))

    postgres_backup.prune_local(tmp_path, retention_days=1)

    assert not backup.exists()
    assert not manifest.exists()


def test_restore_refuses_live_database_target(tmp_path, monkeypatch):
    backup = tmp_path / "cloudsentinel-postgres-test.dump"
    backup.write_bytes(b"backup-data")
    postgres_backup.write_manifest(
        backup.with_suffix(".json"),
        postgres_backup.manifest_for(
            backup,
            postgres_backup.checksum(backup),
        ),
    )

    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://user:pass@db:5432/app",
    )
    monkeypatch.setattr(
        postgres_backup,
        "require_binary",
        lambda name: name,
    )
    monkeypatch.setattr(
        postgres_backup,
        "run",
        lambda command: None,
    )

    with pytest.raises(RuntimeError, match="Refusing to restore"):
        postgres_backup.restore(
            backup,
            "postgresql://user:pass@db:5432/app",
        )


def test_restore_uses_exit_on_error_for_isolated_target(tmp_path, monkeypatch):
    backup = tmp_path / "cloudsentinel-postgres-test.dump"
    backup.write_bytes(b"backup-data")
    postgres_backup.write_manifest(
        backup.with_suffix(".json"),
        postgres_backup.manifest_for(
            backup,
            postgres_backup.checksum(backup),
        ),
    )

    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://user:pass@db:5432/app",
    )
    monkeypatch.setattr(
        postgres_backup,
        "require_binary",
        lambda name: name,
    )
    commands = []
    monkeypatch.setattr(
        postgres_backup,
        "run",
        lambda command: commands.append(command),
    )

    postgres_backup.restore(
        backup,
        "postgresql://user:pass@restore-db:5432/app",
    )

    restore_command = commands[-1]
    assert "--exit-on-error" in restore_command


def test_backup_uses_pinned_dump_binary_and_atomic_output(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@db:5432/app")
    monkeypatch.setenv("PG_DUMP_BIN", "/usr/local/bin/pg_dump-17")
    commands = []

    monkeypatch.setattr(
        postgres_backup,
        "require_binary",
        lambda name, env_name=None: "/usr/local/bin/pg_dump-17",
    )
    monkeypatch.setattr(postgres_backup, "validate_expected_major", lambda binary: None)

    def fake_run(command):
        commands.append(command)
        output = Path(command[command.index("--file") + 1])
        output.write_bytes(b"valid-backup")

    monkeypatch.setattr(postgres_backup, "run", fake_run)

    result = postgres_backup.backup(tmp_path)

    assert result.exists()
    assert result.read_bytes() == b"valid-backup"
    assert not list(tmp_path.glob("*.tmp"))
    assert commands[0][0] == "/usr/local/bin/pg_dump-17"
    assert commands[0][commands[0].index("--file") + 1].endswith(".dump.tmp") is False


def test_backup_removes_partial_archive_when_dump_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@db:5432/app")
    monkeypatch.setattr(
        postgres_backup,
        "require_binary",
        lambda name, env_name=None: "/usr/local/bin/pg_dump-17",
    )
    monkeypatch.setattr(postgres_backup, "validate_expected_major", lambda binary: None)

    def failing_run(command):
        output = Path(command[command.index("--file") + 1])
        output.write_bytes(b"partial")
        raise subprocess.CalledProcessError(1, command)

    import subprocess
    monkeypatch.setattr(postgres_backup, "run", failing_run)

    with pytest.raises(subprocess.CalledProcessError):
        postgres_backup.backup(tmp_path)

    assert not list(tmp_path.glob("cloudsentinel-postgres-*.dump"))
    assert not list(tmp_path.glob("*.tmp"))


def test_verify_rejects_empty_backup(tmp_path, monkeypatch):
    backup = tmp_path / "cloudsentinel-postgres-empty.dump"
    backup.write_bytes(b"")
    postgres_backup.write_manifest(
        backup.with_suffix(".json"),
        {
            "format": "postgresql-custom",
            "filename": backup.name,
            "size_bytes": 0,
            "sha256": postgres_backup.checksum(backup),
        },
    )
    monkeypatch.setattr(
        postgres_backup,
        "require_binary",
        lambda name, env_name=None: "/usr/local/bin/pg_restore-17",
    )

    with pytest.raises(RuntimeError, match="Backup is empty"):
        postgres_backup.verify(backup)
