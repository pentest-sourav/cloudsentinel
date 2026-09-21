from engine.findings.model import Severity
from engine.rules.aws.iam.root_access_key import (
    build_root_access_key_finding,
    check_root_access_key,
)


def test_detects_root_access_key():
    result = check_root_access_key(
        access_keys_present=True,
    )

    assert result.access_keys_present is True

    finding = build_root_access_key_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-IAM-021"


def test_does_not_detect_when_root_has_no_access_key():
    result = check_root_access_key(
        access_keys_present=False,
    )

    assert result.access_keys_present is False

    finding = build_root_access_key_finding(result)

    assert finding is None


def test_finding_has_expected_metadata():
    result = check_root_access_key(
        access_keys_present=True,
    )

    finding = build_root_access_key_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-IAM-021"
    assert finding.title == "AWS Root Account Access Key Exists"
    assert finding.severity == Severity.CRITICAL
    assert finding.provider == "aws"
    assert finding.resource_type == "aws_account"
    assert finding.resource_id == "root"


def test_finding_contains_expected_evidence():
    result = check_root_access_key(
        access_keys_present=True,
    )

    finding = build_root_access_key_finding(result)

    assert finding is not None

    assert finding.evidence == {
        "access_keys_present": True,
    }


def test_finding_contains_compliance():
    result = check_root_access_key(
        access_keys_present=True,
    )

    finding = build_root_access_key_finding(result)

    assert finding is not None

    assert finding.compliance == [
        "CIS AWS Foundations",
    ]
