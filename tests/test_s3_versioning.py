from engine.findings.model import Severity
from engine.rules.aws.s3.versioning import (
    build_s3_versioning_finding,
    check_s3_versioning,
)


def test_versioning_enabled_has_no_finding():
    versioning_status = {
        "Status": "Enabled",
        "MFADelete": "Disabled",
    }

    result = check_s3_versioning(
        bucket_name="versioned-bucket",
        versioning_status=versioning_status,
    )

    assert result.versioning_enabled is True
    assert result.status == "Enabled"
    assert result.mfa_delete == "Disabled"

    finding = build_s3_versioning_finding(result)

    assert finding is None


def test_versioning_disabled_generates_medium_finding():
    versioning_status = {
        "Status": None,
        "MFADelete": None,
    }

    result = check_s3_versioning(
        bucket_name="unversioned-bucket",
        versioning_status=versioning_status,
    )

    assert result.versioning_enabled is False
    assert result.status is None
    assert result.mfa_delete is None

    finding = build_s3_versioning_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-005"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "unversioned-bucket"
    assert finding.evidence["versioning_enabled"] is False


def test_versioning_suspended_generates_medium_finding():
    versioning_status = {
        "Status": "Suspended",
        "MFADelete": "Disabled",
    }

    result = check_s3_versioning(
        bucket_name="suspended-bucket",
        versioning_status=versioning_status,
    )

    assert result.versioning_enabled is False
    assert result.status == "Suspended"

    finding = build_s3_versioning_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-005"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "suspended-bucket"


def test_missing_versioning_status_generates_medium_finding():
    versioning_status = {}

    result = check_s3_versioning(
        bucket_name="missing-status-bucket",
        versioning_status=versioning_status,
    )

    assert result.versioning_enabled is False
    assert result.status is None
    assert result.mfa_delete is None

    finding = build_s3_versioning_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-005"
    assert finding.severity == Severity.MEDIUM
