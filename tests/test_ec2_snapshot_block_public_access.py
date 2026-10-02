from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.snapshot_block_public_access import (
    SnapshotBlockPublicAccessResult,
    build_snapshot_block_public_access_finding,
    check_snapshot_block_public_access,
)


def test_block_all_sharing_is_compliant():
    result = check_snapshot_block_public_access(
        state="block-all-sharing",
        managed_by="account",
    )

    assert result is None


def test_block_new_sharing_is_non_compliant():
    result = check_snapshot_block_public_access(
        state="block-new-sharing",
        managed_by="account",
    )

    assert result is not None
    assert isinstance(
        result,
        SnapshotBlockPublicAccessResult,
    )
    assert result.state == "block-new-sharing"
    assert result.managed_by == "account"


def test_unblocked_is_non_compliant():
    result = check_snapshot_block_public_access(
        state="unblocked",
        managed_by="account",
    )

    assert result is not None
    assert result.state == "unblocked"


def test_missing_state_is_non_compliant():
    result = check_snapshot_block_public_access(
        state=None,
        managed_by=None,
    )

    assert result is not None
    assert result.state is None
    assert result.managed_by is None


def test_state_comparison_is_case_insensitive():
    result = check_snapshot_block_public_access(
        state="BLOCK-ALL-SHARING",
        managed_by="account",
    )

    assert result is None


def test_snapshot_block_public_access_result_is_immutable():
    result = SnapshotBlockPublicAccessResult(
        state="unblocked",
        managed_by="account",
    )

    try:
        result.state = "block-all-sharing"
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "SnapshotBlockPublicAccessResult must be immutable"
        )


def test_snapshot_block_public_access_finding_metadata():
    result = check_snapshot_block_public_access(
        state="block-new-sharing",
        managed_by="declarative-policy",
    )

    assert result is not None

    finding = build_snapshot_block_public_access_finding(
        result
    )

    assert isinstance(finding, Finding)
    assert finding.rule_id == "CS-AWS-EC2-182"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert (
        finding.resource_type
        == "ec2_snapshot_block_public_access"
    )
    assert (
        finding.resource_id
        == "regional-snapshot-block-public-access"
    )
    assert finding.evidence["state"] == "block-new-sharing"
    assert finding.evidence["managed_by"] == "declarative-policy"
    assert finding.compliance == [
        "AWS Security Hub EC2.182",
    ]
    assert finding.remediation
