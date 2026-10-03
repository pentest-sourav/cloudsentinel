from engine.rules.aws.route53.protection import (
    check_route53_health_check_tagging,
)
from engine.rules.aws.secretsmanager.tagging import (
    check_secretsmanager_tagging,
)
from engine.rules.aws.sqs.tagging import check_sqs_tagging
from engine.rules.aws.ssm.protection import check_document_tags
from engine.rules.aws.stepfunctions.tagging import (
    check_stepfunctions_tagging,
)


def test_route53_required_tag_keys_are_exact_and_case_sensitive():
    assert check_route53_health_check_tagging(
        "hc-1", "route53_health_check",
        [{"Key": "Environment", "Value": "prod"}],
        ["Environment"],
    ) is None
    assert check_route53_health_check_tagging(
        "hc-1", "route53_health_check",
        [{"Key": "environment", "Value": "prod"}],
        ["Environment"],
    ) is not None


def test_secretsmanager_required_tag_keys_are_exact():
    assert check_secretsmanager_tagging(
        "secret-1", "arn:secret",
        [{"Key": "Owner", "Value": "sec"}],
        ["Owner"],
    ) is None
    assert check_secretsmanager_tagging(
        "secret-1", "arn:secret",
        [{"Key": "owner", "Value": "sec"}],
        ["Owner"],
    ) is not None


def test_sqs_required_tag_keys_are_exact():
    compliant = check_sqs_tagging(
        "arn:queue",
        [{"Key": "Environment", "Value": "prod"}],
        ["Environment"],
    )
    non_compliant = check_sqs_tagging(
        "arn:queue",
        [{"Key": "environment", "Value": "prod"}],
        ["Environment"],
    )
    assert compliant.required_tag_keys == ["Environment"]
    assert non_compliant.required_tag_keys == ["Environment"]


def test_sqs_finding_respects_required_tag_keys():
    from engine.rules.aws.sqs.tagging import (
        build_sqs_tagging_finding,
    )

    result = check_sqs_tagging(
        "arn:queue",
        [{"Key": "environment", "Value": "prod"}],
        ["Environment"],
    )
    assert build_sqs_tagging_finding(result) is not None


def test_ssm_required_tag_keys_are_exact():
    assert check_document_tags(
        "doc-1", "doc", "123",
        {"Owner": "team"}, True, ["Owner"]
    ) is None
    assert check_document_tags(
        "doc-1", "doc", "123",
        {"owner": "team"}, True, ["Owner"]
    ) is not None


def test_stepfunctions_required_tag_keys_are_exact():
    assert check_stepfunctions_tagging(
        "arn:activity",
        [{"key": "Environment", "value": "prod"}],
        ["Environment"],
    ).required_tag_keys == ["Environment"]
    assert check_stepfunctions_tagging(
        "arn:activity",
        [{"key": "environment", "value": "prod"}],
        ["Environment"],
    ).required_tag_keys == ["Environment"]


def test_empty_required_keys_preserve_baseline_behavior():
    assert check_sqs_tagging(
        "arn:queue",
        [],
        [],
    ).tagged is False
    assert check_secretsmanager_tagging(
        "secret-1", "arn:secret", [], []
    ) is not None
