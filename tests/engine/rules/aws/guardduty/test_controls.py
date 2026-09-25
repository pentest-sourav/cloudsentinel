from engine.findings.model import Severity

from engine.rules.aws.guardduty.common import (
    additional_configuration_enabled,
    feature_enabled,
)
from engine.rules.aws.guardduty.protection import (
    build_gd001,
    build_gd002,
    build_gd003,
    build_gd004,
    build_gd005,
    build_gd006,
    build_gd007,
    build_gd008,
    build_gd009,
    build_gd010,
    check_detector_enabled,
    check_ec2_runtime_monitoring,
    check_ecs_runtime_monitoring,
    check_eks_runtime_monitoring,
    check_feature,
)


def test_feature_enabled():
    assert feature_enabled(
        {
            "S3_DATA_EVENTS": {
                "Status": "ENABLED"
            }
        },
        "S3_DATA_EVENTS",
    )

    assert not feature_enabled(
        {
            "S3_DATA_EVENTS": {
                "Status": "DISABLED"
            }
        },
        "S3_DATA_EVENTS",
    )


def test_additional_configuration_enabled():
    features = {
        "RUNTIME_MONITORING": {
            "Status": "ENABLED",
            "AdditionalConfiguration": [
                {
                    "Name": "ECS_FARGATE_AGENT_MANAGEMENT",
                    "Status": "ENABLED",
                }
            ],
        }
    }

    assert additional_configuration_enabled(
        features,
        "RUNTIME_MONITORING",
        "ECS_FARGATE_AGENT_MANAGEMENT",
    )


def test_detector_enabled_passes():
    assert check_detector_enabled(
        "detector-a",
        "ENABLED",
    ) is None


def test_detector_enabled_fails():
    result = check_detector_enabled(
        "guardduty",
        "DISABLED",
    )

    finding = build_gd001(result)

    assert finding.rule_id == "CS-AWS-GD-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "guardduty"


def test_feature_control_passes():
    assert check_feature(
        "detector-a",
        {
            "S3_DATA_EVENTS": {
                "Status": "ENABLED"
            }
        },
        "S3_DATA_EVENTS",
        "S3 Protection",
    ) is None


def test_feature_control_fails():
    result = check_feature(
        "detector-a",
        {},
        "S3_DATA_EVENTS",
        "S3 Protection",
    )

    finding = build_gd007(result)

    assert finding.rule_id == "CS-AWS-GD-010"
    assert finding.severity == Severity.HIGH


def test_eks_runtime_requires_feature_and_agent_management():
    result = check_eks_runtime_monitoring(
        "detector-a",
        {
            "EKS_RUNTIME_MONITORING": {
                "Status": "ENABLED",
                "AdditionalConfiguration": [],
            }
        },
    )

    finding = build_gd004(result)

    assert finding.rule_id == "CS-AWS-GD-007"


def test_eks_runtime_requires_feature():
    result = check_eks_runtime_monitoring(
        "detector-a",
        {},
    )

    finding = build_gd004(result)

    assert finding.rule_id == "CS-AWS-GD-007"


def test_eks_runtime_passes():
    assert check_eks_runtime_monitoring(
        "detector-a",
        {
            "EKS_RUNTIME_MONITORING": {
                "Status": "ENABLED",
                "AdditionalConfiguration": [
                    {
                        "Name": "EKS_ADDON_MANAGEMENT",
                        "Status": "ENABLED",
                    }
                ],
            }
        },
    ) is None


def test_ecs_runtime_requires_agent_management():
    result = check_ecs_runtime_monitoring(
        "detector-a",
        {
            "RUNTIME_MONITORING": {
                "Status": "ENABLED",
                "AdditionalConfiguration": [],
            }
        },
    )

    finding = build_gd009(result)

    assert finding.rule_id == "CS-AWS-GD-012"
    assert finding.severity == Severity.MEDIUM


def test_ec2_runtime_requires_agent_management():
    result = check_ec2_runtime_monitoring(
        "detector-a",
        {
            "RUNTIME_MONITORING": {
                "Status": "ENABLED",
                "AdditionalConfiguration": [],
            }
        },
    )

    finding = build_gd010(result)

    assert finding.rule_id == "CS-AWS-GD-013"
    assert finding.severity == Severity.MEDIUM


def test_all_feature_builders_have_expected_rule_ids():
    checks = [
        (
            "CS-AWS-GD-005",
            build_gd002,
            "EKS_AUDIT_LOGS",
        ),
        (
            "CS-AWS-GD-006",
            build_gd003,
            "LAMBDA_NETWORK_LOGS",
        ),
        (
            "CS-AWS-GD-008",
            build_gd005,
            "EBS_MALWARE_PROTECTION",
        ),
        (
            "CS-AWS-GD-009",
            build_gd006,
            "RDS_LOGIN_EVENTS",
        ),
        (
            "CS-AWS-GD-011",
            build_gd008,
            "RUNTIME_MONITORING",
        ),
    ]

    for rule_id, builder, feature_name in checks:
        result = check_feature(
            "detector-a",
            {},
            feature_name,
            feature_name,
        )

        finding = builder(result)

        assert finding.rule_id == rule_id
