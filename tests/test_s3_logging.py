from engine.findings.model import Severity

from engine.rules.aws.s3.logging import (
    build_s3_logging_finding,
    check_s3_logging,
)


def test_s3_logging_disabled_generates_finding():
    result = check_s3_logging(
        bucket_name="test-bucket",
        logging_configuration={},
    )

    assert result.logging_enabled is False

    finding = build_s3_logging_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-S3-006"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "test-bucket"
    assert finding.evidence["logging_enabled"] is False


def test_s3_logging_enabled_has_no_finding():
    configuration = {
        "TargetBucket": "logging-bucket",
        "TargetPrefix": "s3-access/",
    }

    result = check_s3_logging(
        bucket_name="secure-bucket",
        logging_configuration=configuration,
    )

    assert result.logging_enabled is True

    finding = build_s3_logging_finding(result)

    assert finding is None
