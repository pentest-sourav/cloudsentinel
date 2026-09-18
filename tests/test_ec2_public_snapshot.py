from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.public_snapshot import (
    PublicSnapshotResult,
    build_public_snapshot_finding,
    check_public_snapshot,
)


def test_public_completed_snapshot_creates_finding():
    result = check_public_snapshot(
        snapshot_id="snap-123",
        volume_id="vol-123",
        state="completed",
        public=True,
    )

    assert result is not None
    assert isinstance(result, PublicSnapshotResult)
    assert result.snapshot_id == "snap-123"
    assert result.volume_id == "vol-123"
    assert result.state == "completed"


def test_private_completed_snapshot_is_ignored():
    result = check_public_snapshot(
        snapshot_id="snap-123",
        volume_id="vol-123",
        state="completed",
        public=False,
    )

    assert result is None


def test_in_progress_public_snapshot_is_ignored():
    result = check_public_snapshot(
        snapshot_id="snap-123",
        volume_id="vol-123",
        state="pending",
        public=True,
    )

    assert result is None


def test_snapshot_with_empty_id_is_ignored():
    result = check_public_snapshot(
        snapshot_id="",
        volume_id="vol-123",
        state="completed",
        public=True,
    )

    assert result is None


def test_snapshot_with_none_volume_id_is_still_detected():
    result = check_public_snapshot(
        snapshot_id="snap-789",
        volume_id=None,
        state="completed",
        public=True,
    )

    assert result is not None
    assert result.snapshot_id == "snap-789"
    assert result.volume_id is None
    assert result.state == "completed"


def test_public_snapshot_result_is_immutable():
    result = PublicSnapshotResult(
        snapshot_id="snap-immutable",
        volume_id="vol-immutable",
        state="completed",
    )

    try:
        result.state = "pending"
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "PublicSnapshotResult must be immutable"
        )


def test_public_snapshot_finding_metadata():
    result = check_public_snapshot(
        snapshot_id="snap-456",
        volume_id="vol-456",
        state="completed",
        public=True,
    )

    assert result is not None

    finding = build_public_snapshot_finding(result)

    assert isinstance(finding, Finding)

    assert finding.rule_id == "CS-AWS-EC2-005"
    assert finding.title == "EBS Snapshot Is Publicly Accessible"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "ebs_snapshot"
    assert finding.resource_id == "snap-456"

    assert "publicly accessible" in finding.description.lower()
    assert "snap-456" in finding.description
    assert "completed" in finding.description

    assert finding.evidence["snapshot_id"] == "snap-456"
    assert finding.evidence["volume_id"] == "vol-456"
    assert finding.evidence["state"] == "completed"
    assert finding.evidence["public"] is True
    assert finding.evidence["access_scope"] == "public"

    assert finding.remediation
    assert "private" in finding.remediation.lower()

    assert finding.compliance == [
        "CIS AWS Foundations",
    ]
