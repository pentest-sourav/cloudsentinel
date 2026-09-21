from engine.findings.model import Severity
from engine.rules.aws.iam.user_attached_policy import (
    build_user_attached_policy_finding,
    check_user_attached_policy,
)


def test_detects_managed_policy_attached_to_user():
    result = check_user_attached_policy(
        username="alice",
        managed_policy_count=1,
        managed_policy_names=["ReadOnlyAccess"],
        inline_policy_count=0,
        inline_policy_names=[],
    )

    assert result.has_attached_policies is True

    finding = build_user_attached_policy_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-IAM-022"


def test_detects_inline_policy_attached_to_user():
    result = check_user_attached_policy(
        username="alice",
        managed_policy_count=0,
        managed_policy_names=[],
        inline_policy_count=1,
        inline_policy_names=["DeveloperPolicy"],
    )

    assert result.has_attached_policies is True

    finding = build_user_attached_policy_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-IAM-022"


def test_does_not_detect_user_without_attached_policies():
    result = check_user_attached_policy(
        username="alice",
        managed_policy_count=0,
        managed_policy_names=[],
        inline_policy_count=0,
        inline_policy_names=[],
    )

    assert result.has_attached_policies is False

    finding = build_user_attached_policy_finding(result)

    assert finding is None


def test_finding_has_expected_metadata():
    result = check_user_attached_policy(
        username="alice",
        managed_policy_count=1,
        managed_policy_names=["ReadOnlyAccess"],
        inline_policy_count=1,
        inline_policy_names=["DeveloperPolicy"],
    )

    finding = build_user_attached_policy_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-IAM-022"
    assert finding.title == "IAM User Has Policies Attached Directly"
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"
    assert finding.resource_type == "aws_iam_user"
    assert finding.resource_id == "alice"


def test_finding_contains_policy_evidence():
    result = check_user_attached_policy(
        username="alice",
        managed_policy_count=1,
        managed_policy_names=["ReadOnlyAccess"],
        inline_policy_count=2,
        inline_policy_names=[
            "DeveloperPolicy",
            "BillingPolicy",
        ],
    )

    finding = build_user_attached_policy_finding(result)

    assert finding is not None

    assert finding.evidence == {
        "managed_policy_count": 1,
        "managed_policy_names": ["ReadOnlyAccess"],
        "inline_policy_count": 2,
        "inline_policy_names": [
            "DeveloperPolicy",
            "BillingPolicy",
        ],
    }


def test_finding_contains_compliance():
    result = check_user_attached_policy(
        username="alice",
        managed_policy_count=1,
        managed_policy_names=["ReadOnlyAccess"],
        inline_policy_count=0,
        inline_policy_names=[],
    )

    finding = build_user_attached_policy_finding(result)

    assert finding is not None

    assert finding.compliance == [
        "CIS AWS Foundations",
    ]
