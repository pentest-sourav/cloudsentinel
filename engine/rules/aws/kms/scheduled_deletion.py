from dataclasses import dataclass
from datetime import datetime

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class KMSScheduledDeletionResult:
    key_id: str
    deletion_date: datetime


def check_kms_scheduled_deletion(
    key_id: str,
    key_state: str | None,
    deletion_date: datetime | None,
) -> KMSScheduledDeletionResult | None:
    if not key_id:
        return None

    if key_state != "PendingDeletion":
        return None

    if deletion_date is None:
        return None

    return KMSScheduledDeletionResult(
        key_id=key_id,
        deletion_date=deletion_date,
    )


def build_kms_scheduled_deletion_finding(
    result: KMSScheduledDeletionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-KMS-002",
        title="KMS Key Is Scheduled For Deletion",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="kms_key",
        resource_id=result.key_id,
        description=(
            f"The KMS key {result.key_id} is scheduled for deletion. "
            "Applications that still depend on the key may lose the "
            "ability to decrypt protected data after the deletion "
            "takes effect."
        ),
        evidence={
            "key_id": result.key_id,
            "key_state": "PendingDeletion",
            "deletion_date": result.deletion_date.isoformat(),
        },
        remediation=(
            "Verify that the key is no longer required. If deletion "
            "was accidental, cancel the scheduled deletion and review "
            "dependent resources before making another lifecycle change."
        ),
    )
