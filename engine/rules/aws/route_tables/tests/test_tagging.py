from engine.findings.model import Severity
from engine.rules.aws.route_tables.tagging import (
    build_route_table_tagging_finding,
    check_route_table_tagging,
)


def test_untagged_route_table_is_detected():
    result = check_route_table_tagging(
        route_table_id="rtb-123",
        vpc_id="vpc-123",
        tags=[],
    )

    assert result is not None
    assert result.route_table_id == "rtb-123"


def test_route_table_with_user_tag_is_allowed():
    result = check_route_table_tagging(
        route_table_id="rtb-123",
        vpc_id="vpc-123",
        tags=[
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ],
    )

    assert result is None


def test_aws_system_tags_do_not_count():
    result = check_route_table_tagging(
        route_table_id="rtb-123",
        vpc_id="vpc-123",
        tags=[
            {
                "Key": "aws:cloudformation:stack-id",
                "Value": "stack",
            }
        ],
    )

    assert result is not None


def test_route_table_tagging_finding():
    result = check_route_table_tagging(
        route_table_id="rtb-123",
        vpc_id="vpc-123",
        tags=[],
    )

    finding = build_route_table_tagging_finding(result)

    assert finding.rule_id == "CS-AWS-RT-002"
    assert finding.severity == Severity.LOW
    assert finding.resource_type == "route_table"
    assert finding.resource_id == "rtb-123"
