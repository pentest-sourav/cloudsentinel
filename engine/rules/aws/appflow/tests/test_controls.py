from engine.findings.model import Severity
from engine.rules.aws.appflow.controls import (
    build_appflow_flow_tags_finding,
    check_appflow_flow_tags,
)


BASE = {
    "flow_name": "salesforce_to_s3",
    "flow_arn": (
        "arn:aws:appflow:ap-south-1:"
        "123456789012:flow/salesforce_to_s3"
    ),
}


def test_flow_tags_pass_when_non_system_tag_exists():
    assert check_appflow_flow_tags(
        **BASE,
        tag_data_available=True,
        has_non_system_tags=True,
    ) is None


def test_flow_tags_fail_when_no_non_system_tags_exist():
    result = check_appflow_flow_tags(
        **BASE,
        tag_data_available=True,
        has_non_system_tags=False,
    )

    assert result is not None
    assert result.reason == "missing_non_system_tags"
    assert result.evidence["has_non_system_tags"] is False


def test_flow_tags_skip_when_tag_data_unavailable():
    assert check_appflow_flow_tags(
        **BASE,
        tag_data_available=False,
        has_non_system_tags=False,
    ) is None


def test_invalid_flow_is_skipped():
    assert check_appflow_flow_tags(
        flow_name="",
        flow_arn=BASE["flow_arn"],
        tag_data_available=True,
        has_non_system_tags=False,
    ) is None


def test_finding_contains_expected_metadata():
    result = check_appflow_flow_tags(
        **BASE,
        tag_data_available=True,
        has_non_system_tags=False,
    )

    finding = build_appflow_flow_tags_finding(result)

    assert finding.rule_id == "CS-AWS-APPFLOW-001"
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"
    assert finding.resource_type == "appflow_flow"
    assert finding.resource_id == BASE["flow_arn"]
    assert finding.compliance == [
        "AWS Security Hub AppFlow.1"
    ]
