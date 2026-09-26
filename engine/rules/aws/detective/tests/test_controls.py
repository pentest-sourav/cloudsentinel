from engine.findings.model import Severity

from engine.rules.aws.detective.controls import (
    build_detective_graph_tags_finding,
    check_detective_graph_tags,
)


def test_detective_tags_pass():
    result = check_detective_graph_tags(
        "graph",
        "arn:aws:detective:region:account:graph:123",
        "AWS::Detective::Graph",
        True,
        True,
    )

    assert result is None


def test_detective_tags_fail():
    result = check_detective_graph_tags(
        "graph",
        "arn:aws:detective:region:account:graph:123",
        "AWS::Detective::Graph",
        True,
        False,
    )

    assert result is not None
    assert result.control_id == "Detective.1"
    assert result.reason == "missing_non_system_tags"

    finding = build_detective_graph_tags_finding(result)

    assert finding.rule_id == "CS-AWS-DETECTIVE-001"
    assert finding.severity == Severity.LOW


def test_detective_tags_skip_when_tag_data_unavailable():
    result = check_detective_graph_tags(
        "graph",
        "arn:graph",
        "AWS::Detective::Graph",
        False,
        False,
    )

    assert result is None
