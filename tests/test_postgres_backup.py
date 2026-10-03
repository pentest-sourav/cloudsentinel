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
