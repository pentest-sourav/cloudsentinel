from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PublicSnapshotResult:
    """
    Result of evaluating an EBS snapshot for public access.
    """

    snapshot_id: str
    volume_id: str | None
    state: str


def check_public_snapshot(
    snapshot_id: str,
    volume_id: str | None,
    state: str | None,
    public: bool,
) -> PublicSnapshotResult | None:
    """
    Detect an EBS snapshot that is publicly accessible.

    Only completed snapshots are evaluated because an
    in-progress snapshot is not yet in a usable state.

    The rule evaluates normalized scanner data only and
    does not perform AWS API calls or remediation.
    """

    if not snapshot_id:
        return None

    if state != "completed":
        return None

    if not public:
        return None

    return PublicSnapshotResult(
        snapshot_id=snapshot_id,
        volume_id=volume_id,
        state=state,
    )


def build_public_snapshot_finding(
    result: PublicSnapshotResult,
) -> Finding:
    """
    Convert a publicly accessible EBS snapshot result
    into a CloudSentinel security finding.
    """

    return Finding(
        rule_id="CS-AWS-EC2-005",
        title="EBS Snapshot Is Publicly Accessible",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ebs_snapshot",
        resource_id=result.snapshot_id,
        description=(
            f"The EBS snapshot {result.snapshot_id} is publicly "
            "accessible and is in the completed state. A public "
            "snapshot can expose its underlying stored data to "
            "unauthorized AWS accounts."
        ),
        evidence={
            "snapshot_id": result.snapshot_id,
            "volume_id": result.volume_id,
            "state": result.state,
            "public": True,
            "access_scope": "public",
        },
        remediation=(
            "Make the EBS snapshot private and review its sharing "
            "permissions. Remove unintended public access, verify "
            "that no sensitive data was exposed, and review related "
            "snapshots for the same exposure."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
