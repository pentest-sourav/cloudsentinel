from engine.rules.registry.guardduty_handlers import (
    GUARDDUTY_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.guardduty_registry import (
    GUARDDUTY_RULES,
)


def test_guardduty_registry_contains_current_controls():
    assert [
        rule.rule_id
        for rule in GUARDDUTY_RULES.list_rules()
    ] == [
        "CS-AWS-GD-001",
        "CS-AWS-GD-005",
        "CS-AWS-GD-006",
        "CS-AWS-GD-007",
        "CS-AWS-GD-008",
        "CS-AWS-GD-009",
        "CS-AWS-GD-010",
        "CS-AWS-GD-011",
        "CS-AWS-GD-012",
        "CS-AWS-GD-013",
    ]


def test_guardduty_registry_has_handler_for_every_source():
    for rule in GUARDDUTY_RULES.list_rules():
        assert (
            rule.data_source
            in GUARDDUTY_DATA_SOURCE_HANDLERS
        )


from engine.findings.model import Severity
from engine.rules.aws.guardduty.protection import (
    GuardDutyControlResult,
    build_finding,
    check_ec2_runtime_monitoring,
    check_ecs_runtime_monitoring,
)


def test_guardduty_compliance_control_ids_are_not_zero_padded():
    result = GuardDutyControlResult(
        resource_id="detector-1",
        control_name="GuardDuty S3 Protection",
        expected_configuration="S3_DATA_EVENTS=ENABLED",
        actual_configuration="S3_DATA_EVENTS=DISABLED_OR_MISSING",
    )

    finding = build_finding(
        result,
        rule_id="CS-AWS-GD-010",
        title="GuardDuty S3 Protection should be enabled",
        severity=Severity.HIGH,
    )

    assert finding.compliance == ["AWS Security Hub GuardDuty.10"]


def test_guardduty_ec2_runtime_requires_runtime_monitoring_and_agent_management():
    features = {
        "RUNTIME_MONITORING": {
            "Status": "DISABLED",
            "AdditionalConfiguration": [
                {"Name": "EC2_AGENT_MANAGEMENT", "Status": "ENABLED"},
            ],
        },
    }

    result = check_ec2_runtime_monitoring("detector-1", features)

    assert result is not None


def test_guardduty_ecs_runtime_requires_runtime_monitoring_and_agent_management():
    features = {
        "RUNTIME_MONITORING": {
            "Status": "DISABLED",
            "AdditionalConfiguration": [
                {"Name": "ECS_FARGATE_AGENT_MANAGEMENT", "Status": "ENABLED"},
            ],
        },
    }

    result = check_ecs_runtime_monitoring("detector-1", features)

    assert result is not None
