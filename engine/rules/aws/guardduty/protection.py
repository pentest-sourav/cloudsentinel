from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity

from engine.rules.aws.guardduty.common import (
    additional_configuration_enabled,
    feature_enabled,
)


@dataclass(frozen=True)
class GuardDutyControlResult:
    resource_id: str
    control_name: str
    expected_configuration: str
    actual_configuration: str


def check_detector_enabled(
    resource_id: str,
    status: str | None,
) -> GuardDutyControlResult | None:
    if status == "ENABLED":
        return None

    return GuardDutyControlResult(
        resource_id=resource_id,
        control_name="GuardDuty enabled",
        expected_configuration="ENABLED",
        actual_configuration=str(status),
    )


def check_feature(
    resource_id: str,
    features: dict[str, dict[str, Any]],
    feature_name: str,
    control_name: str,
) -> GuardDutyControlResult | None:
    if feature_enabled(
        features,
        feature_name,
    ):
        return None

    return GuardDutyControlResult(
        resource_id=resource_id,
        control_name=control_name,
        expected_configuration=(
            f"{feature_name}=ENABLED"
        ),
        actual_configuration=(
            f"{feature_name}=DISABLED_OR_MISSING"
        ),
    )


def check_eks_runtime_monitoring(
    resource_id: str,
    features: dict[str, dict[str, Any]],
) -> GuardDutyControlResult | None:
    if (
        feature_enabled(
            features,
            "EKS_RUNTIME_MONITORING",
        )
        and additional_configuration_enabled(
            features,
            "EKS_RUNTIME_MONITORING",
            "EKS_ADDON_MANAGEMENT",
        )
    ):
        return None

    return GuardDutyControlResult(
        resource_id=resource_id,
        control_name=(
            "GuardDuty EKS Runtime Monitoring"
        ),
        expected_configuration=(
            "EKS_RUNTIME_MONITORING=ENABLED; "
            "EKS_ADDON_MANAGEMENT=ENABLED"
        ),
        actual_configuration=(
            "EKS_RUNTIME_MONITORING="
            f"{'ENABLED' if feature_enabled(features, 'EKS_RUNTIME_MONITORING') else 'DISABLED_OR_MISSING'}; "
            "EKS_ADDON_MANAGEMENT="
            f"{'ENABLED' if additional_configuration_enabled(features, 'EKS_RUNTIME_MONITORING', 'EKS_ADDON_MANAGEMENT') else 'DISABLED_OR_MISSING'}"
        ),
    )


def check_ecs_runtime_monitoring(
    resource_id: str,
    features: dict[str, dict[str, Any]],
) -> GuardDutyControlResult | None:
    if additional_configuration_enabled(
        features,
        "RUNTIME_MONITORING",
        "ECS_FARGATE_AGENT_MANAGEMENT",
    ):
        return None

    return GuardDutyControlResult(
        resource_id=resource_id,
        control_name=(
            "GuardDuty ECS Runtime Monitoring"
        ),
        expected_configuration=(
            "RUNTIME_MONITORING="
            "ENABLED; "
            "ECS_FARGATE_AGENT_MANAGEMENT=ENABLED"
        ),
        actual_configuration=(
            "ECS_FARGATE_AGENT_MANAGEMENT="
            "DISABLED_OR_MISSING"
        ),
    )


def check_ec2_runtime_monitoring(
    resource_id: str,
    features: dict[str, dict[str, Any]],
) -> GuardDutyControlResult | None:
    if additional_configuration_enabled(
        features,
        "RUNTIME_MONITORING",
        "EC2_AGENT_MANAGEMENT",
    ):
        return None

    return GuardDutyControlResult(
        resource_id=resource_id,
        control_name=(
            "GuardDuty EC2 Runtime Monitoring"
        ),
        expected_configuration=(
            "RUNTIME_MONITORING="
            "ENABLED; "
            "EC2_AGENT_MANAGEMENT=ENABLED"
        ),
        actual_configuration=(
            "EC2_AGENT_MANAGEMENT="
            "DISABLED_OR_MISSING"
        ),
    )


def build_finding(
    result: GuardDutyControlResult,
    *,
    rule_id: str,
    title: str,
    severity: Severity,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        provider="aws",
        resource_type="guardduty_detector",
        resource_id=result.resource_id,
        description=(
            f"{result.control_name} is not enabled "
            "as required."
        ),
        evidence={
            "detector_id": result.resource_id,
            "expected_configuration": (
                result.expected_configuration
            ),
            "actual_configuration": (
                result.actual_configuration
            ),
        },
        remediation=(
            "Enable the required GuardDuty detector "
            "feature in the AWS GuardDuty console "
            "or through the GuardDuty API."
        ),
        compliance=[
            f"AWS Security Hub "
            f"{rule_id.replace('CS-AWS-GD-', 'GuardDuty.')}"
        ],
    )


def build_gd001(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-001",
        title="GuardDuty should be enabled",
        severity=Severity.HIGH,
    )


def build_gd002(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-005",
        title=(
            "GuardDuty EKS Audit Log Monitoring "
            "should be enabled"
        ),
        severity=Severity.HIGH,
    )


def build_gd003(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-006",
        title=(
            "GuardDuty Lambda Protection "
            "should be enabled"
        ),
        severity=Severity.HIGH,
    )


def build_gd004(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-007",
        title=(
            "GuardDuty EKS Runtime Monitoring "
            "should be enabled"
        ),
        severity=Severity.HIGH,
    )


def build_gd005(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-008",
        title=(
            "GuardDuty Malware Protection for EC2 "
            "should be enabled"
        ),
        severity=Severity.HIGH,
    )


def build_gd006(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-009",
        title=(
            "GuardDuty RDS Protection "
            "should be enabled"
        ),
        severity=Severity.HIGH,
    )


def build_gd007(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-010",
        title=(
            "GuardDuty S3 Protection "
            "should be enabled"
        ),
        severity=Severity.HIGH,
    )


def build_gd008(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-011",
        title=(
            "GuardDuty Runtime Monitoring "
            "should be enabled"
        ),
        severity=Severity.HIGH,
    )


def build_gd009(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-012",
        title=(
            "GuardDuty ECS Runtime Monitoring "
            "should be enabled"
        ),
        severity=Severity.MEDIUM,
    )


def build_gd010(result):
    return build_finding(
        result,
        rule_id="CS-AWS-GD-013",
        title=(
            "GuardDuty EC2 Runtime Monitoring "
            "should be enabled"
        ),
        severity=Severity.MEDIUM,
    )
