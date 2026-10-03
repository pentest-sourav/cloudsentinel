from engine.findings.model import Severity
from engine.rules.aws.s3.lifecycle import (
    build_s3_lifecycle_finding,
    check_s3_lifecycle,
)


def test_versioned_bucket_without_lifecycle_fails():
    result = check_s3_lifecycle(
        bucket_name="bucket-a",
        versioning_status={"Status": "Enabled"},
        lifecycle_configuration={},
    )

    finding = build_s3_lifecycle_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-010"
    assert finding.severity == Severity.MEDIUM


def test_unversioned_bucket_does_not_require_lifecycle():
    result = check_s3_lifecycle(
        bucket_name="bucket-a",
        versioning_status={"Status": "Suspended"},
        lifecycle_configuration={},
    )

    assert build_s3_lifecycle_finding(result) is None


def test_versioned_bucket_with_lifecycle_passes():
    result = check_s3_lifecycle(
        bucket_name="bucket-a",
        versioning_status={"Status": "Enabled"},
        lifecycle_configuration={
            "Rules": [{"Status": "Enabled", "Prefix": ""}]
        },
    )

    assert result.lifecycle_configured is True
    assert build_s3_lifecycle_finding(result) is None
