from datetime import datetime, timezone

from engine.findings.model import Severity
from engine.rules.aws.kms.scheduled_deletion import (
    build_kms_scheduled_deletion_finding,
    check_kms_scheduled_deletion,
)


def test_enabled_key_is_compliant():
    assert check_kms_scheduled_deletion(
        "key-1",
        "Enabled",
        None,
    ) is None


def test_pending_deletion_key_fails():
    deletion_date = datetime(
        2026,
        10,
        1,
        tzinfo=timezone.utc,
    )

    result = check_kms_scheduled_deletion(
        "key-1",
        "PendingDeletion",
        deletion_date,
    )

    assert result is not None

    finding = build_kms_scheduled_deletion_finding(result)

    assert finding.rule_id == "CS-AWS-KMS-002"
    assert finding.severity == Severity.HIGH
    assert finding.evidence["key_state"] == "PendingDeletion"


def test_pending_deletion_without_date_is_unknown():
    assert check_kms_scheduled_deletion(
        "key-1",
        "PendingDeletion",
        None,
    ) is None
