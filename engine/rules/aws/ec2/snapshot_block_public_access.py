from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SnapshotBlockPublicAccessResult:
    state: str | None
    managed_by: str | None


def check_snapshot_block_public_access(
    state: str | None,
    managed_by: str | None,
) -> SnapshotBlockPublicAccessResult | None:
    normalized_state = str(
        state or ""
    ).strip().lower()

    if normalized_state == "block-all-sharing":
        return None

    return SnapshotBlockPublicAccessResult(
        state=state,
        managed_by=managed_by,
    )


def build_snapshot_block_public_access_finding(
    result: SnapshotBlockPublicAccessResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-182",
        title=(
            "EBS Snapshot Block Public Access Is Not Fully Enabled"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ec2_snapshot_block_public_access",
        resource_id="regional-snapshot-block-public-access",
        description=(
            "EBS Snapshot Block Public Access is not configured "
            "in block-all-sharing mode for the current AWS Region."
        ),
        evidence={
            "state": result.state,
            "managed_by": result.managed_by,
        },
        remediation=(
            "Enable EBS Snapshot Block Public Access with the state "
            "set to block-all-sharing for the affected AWS Region."
        ),
        compliance=[
            "AWS Security Hub EC2.182",
        ],
    )
