from engine.findings.model import Severity
from engine.rules.aws.cloudformation.controls import (
    build_cloudformation_service_role_finding,
    build_cloudformation_stack_tags_finding,
    build_cloudformation_termination_protection_finding,
    check_cloudformation_service_role,
    check_cloudformation_stack_tags,
    check_cloudformation_termination_protection,
)


STACK_NAME = "prod"
STACK_ID = "arn:aws:cloudformation:ap-south-1:123:stack/prod/id"


def test_stack_tags_pass_with_non_system_tag():
    assert check_cloudformation_stack_tags(
        STACK_NAME,
        STACK_ID,
        True,
        True,
    ) is None


def test_stack_tags_skip_when_tag_data_unavailable():
    assert check_cloudformation_stack_tags(
        STACK_NAME,
        STACK_ID,
        False,
        False,
    ) is None


def test_stack_tags_fail_without_non_system_tags():
    result = check_cloudformation_stack_tags(
        STACK_NAME,
        STACK_ID,
        True,
        False,
    )

    assert result is not None

    finding = build_cloudformation_stack_tags_finding(result)

    assert finding.rule_id == "CS-AWS-CLOUDFORMATION-002"
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"


def test_termination_protection_passes_when_enabled():
    assert check_cloudformation_termination_protection(
        STACK_NAME,
        STACK_ID,
        True,
    ) is None


def test_termination_protection_skips_when_unknown():
    assert check_cloudformation_termination_protection(
        STACK_NAME,
        STACK_ID,
        None,
    ) is None


def test_termination_protection_fails_when_disabled():
    result = check_cloudformation_termination_protection(
        STACK_NAME,
        STACK_ID,
        False,
    )

    assert result is not None

    finding = (
        build_cloudformation_termination_protection_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-CLOUDFORMATION-003"
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence[
        "termination_protection_enabled"
    ] is False


def test_service_role_passes_when_present():
    assert check_cloudformation_service_role(
        STACK_NAME,
        STACK_ID,
        "arn:aws:iam::123:role/cfn",
    ) is None


def test_service_role_fails_when_missing():
    result = check_cloudformation_service_role(
        STACK_NAME,
        STACK_ID,
        None,
    )

    assert result is not None

    finding = build_cloudformation_service_role_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CLOUDFORMATION-004"
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["role_arn"] is None
