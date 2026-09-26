from engine.findings.model import Severity
from engine.rules.aws.amplify.controls import (
    build_amplify_app_tags_finding,
    build_amplify_branch_tags_finding,
    check_amplify_app_tags,
    check_amplify_branch_tags,
)


APP_ARN = (
    "arn:aws:amplify:ap-south-1:123456789012:"
    "apps/d123456789"
)

BRANCH_ARN = (
    "arn:aws:amplify:ap-south-1:123456789012:"
    "branches/d123456789/main"
)


def test_amplify_app_tags_passes_when_tagged():
    assert (
        check_amplify_app_tags(
            "frontend",
            APP_ARN,
            True,
            True,
        )
        is None
    )


def test_amplify_app_tags_skips_when_tag_data_unavailable():
    assert (
        check_amplify_app_tags(
            "frontend",
            APP_ARN,
            False,
            False,
        )
        is None
    )


def test_amplify_app_tags_fails_when_untagged():
    result = check_amplify_app_tags(
        "frontend",
        APP_ARN,
        True,
        False,
    )

    assert result is not None
    assert result.reason == "missing_non_system_tags"
    assert result.resource_type == "amplify_app"

    finding = build_amplify_app_tags_finding(result)

    assert finding.rule_id == "CS-AWS-AMPLIFY-001"
    assert finding.severity == Severity.LOW
    assert finding.resource_type == "amplify_app"
    assert finding.resource_id == APP_ARN
    assert "AWS Security Hub Amplify.1" in finding.compliance


def test_amplify_branch_tags_passes_when_tagged():
    assert (
        check_amplify_branch_tags(
            "main",
            BRANCH_ARN,
            True,
            True,
        )
        is None
    )


def test_amplify_branch_tags_skips_when_tag_data_unavailable():
    assert (
        check_amplify_branch_tags(
            "main",
            BRANCH_ARN,
            False,
            False,
        )
        is None
    )


def test_amplify_branch_tags_fails_when_untagged():
    result = check_amplify_branch_tags(
        "main",
        BRANCH_ARN,
        True,
        False,
    )

    assert result is not None
    assert result.reason == "missing_non_system_tags"
    assert result.resource_type == "amplify_branch"

    finding = build_amplify_branch_tags_finding(result)

    assert finding.rule_id == "CS-AWS-AMPLIFY-002"
    assert finding.severity == Severity.LOW
    assert finding.resource_type == "amplify_branch"
    assert finding.resource_id == BRANCH_ARN
    assert "AWS Security Hub Amplify.2" in finding.compliance
