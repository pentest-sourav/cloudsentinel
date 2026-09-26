from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AutoScalingResult:
    group_name: str
    group_arn: str | None
    reason: str
    evidence: dict[str, object]


def _finding(
    result: AutoScalingResult,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
    compliance: list[str],
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        provider="aws",
        resource_type="autoscaling_group",
        resource_id=(
            result.group_arn
            or result.group_name
        ),
        description=description,
        evidence={
            **result.evidence,
            "configuration_issue": result.reason,
        },
        remediation=remediation,
        compliance=compliance,
    )


def check_autoscaling_elb_health_checks(
    group_name: str,
    group_arn: str | None,
    has_load_balancer: bool,
    health_check_type: str | None,
) -> AutoScalingResult | None:
    if not group_name or not has_load_balancer:
        return None

    if health_check_type is None:
        return None

    if health_check_type.upper() == "ELB":
        return None

    return AutoScalingResult(
        group_name=group_name,
        group_arn=group_arn,
        reason="elb_health_check_not_enabled",
        evidence={
            "has_load_balancer": has_load_balancer,
            "health_check_type": health_check_type,
        },
    )


def build_autoscaling_elb_health_checks_finding(
    result: AutoScalingResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-AUTOSCALING-001",
        "Auto Scaling Group Does Not Use ELB Health Checks",
        Severity.LOW,
        (
            f"Auto Scaling group {result.group_name} is "
            "associated with a load balancer but does not "
            "use ELB health checks."
        ),
        (
            "Configure the Auto Scaling group to use ELB "
            "health checks when it is associated with an "
            "Elastic Load Balancing resource."
        ),
        [
            "AWS Security Hub AutoScaling.1",
            "AWS Config autoscaling-group-elb-healthcheck-required",
        ],
    )


def check_autoscaling_multiple_az(
    group_name: str,
    group_arn: str | None,
    availability_zone_count: int,
) -> AutoScalingResult | None:
    if not group_name:
        return None

    if availability_zone_count >= 2:
        return None

    return AutoScalingResult(
        group_name=group_name,
        group_arn=group_arn,
        reason="less_than_two_availability_zones",
        evidence={
            "availability_zone_count": (
                availability_zone_count
            ),
        },
    )


def build_autoscaling_multiple_az_finding(
    result: AutoScalingResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-AUTOSCALING-002",
        "Auto Scaling Group Does Not Span Multiple Availability Zones",
        Severity.MEDIUM,
        (
            f"Auto Scaling group {result.group_name} "
            "does not span at least two Availability Zones."
        ),
        (
            "Configure the Auto Scaling group across at least "
            "two Availability Zones to improve resilience."
        ),
        [
            "AWS Security Hub AutoScaling.2",
            "AWS Config autoscaling-multiple-az",
        ],
    )


def check_autoscaling_imdsv2(
    group_name: str,
    group_arn: str | None,
    launch_configuration_name: str | None,
    launch_configuration_data_available: bool,
    metadata_http_tokens: str | None,
) -> AutoScalingResult | None:
    if (
        not group_name
        or not launch_configuration_name
        or not launch_configuration_data_available
    ):
        return None

    if metadata_http_tokens is None:
        return None

    if metadata_http_tokens.lower() == "required":
        return None

    return AutoScalingResult(
        group_name=group_name,
        group_arn=group_arn,
        reason="imdsv2_not_required",
        evidence={
            "launch_configuration_name": (
                launch_configuration_name
            ),
            "metadata_http_tokens": (
                metadata_http_tokens
            ),
        },
    )


def build_autoscaling_imdsv2_finding(
    result: AutoScalingResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-AUTOSCALING-003",
        "Auto Scaling Launch Configuration Does Not Require IMDSv2",
        Severity.HIGH,
        (
            f"Auto Scaling group {result.group_name} uses "
            "a launch configuration that does not require "
            "Instance Metadata Service Version 2."
        ),
        (
            "Replace the launch configuration with a new "
            "configuration that requires IMDSv2. Launch "
            "configurations cannot be modified after creation."
        ),
        [
            "AWS Security Hub AutoScaling.3",
            "AWS Config autoscaling-launchconfig-requires-imdsv2",
        ],
    )


def check_autoscaling_public_ip(
    group_name: str,
    group_arn: str | None,
    launch_configuration_name: str | None,
    launch_configuration_data_available: bool,
    associate_public_ip_address: bool | None,
) -> AutoScalingResult | None:
    if (
        not group_name
        or not launch_configuration_name
        or not launch_configuration_data_available
    ):
        return None

    if associate_public_ip_address is None:
        return None

    if not associate_public_ip_address:
        return None

    return AutoScalingResult(
        group_name=group_name,
        group_arn=group_arn,
        reason="launch_configuration_assigns_public_ip",
        evidence={
            "launch_configuration_name": (
                launch_configuration_name
            ),
            "associate_public_ip_address": True,
        },
    )


def build_autoscaling_public_ip_finding(
    result: AutoScalingResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-AUTOSCALING-005",
        "Auto Scaling Launch Configuration Assigns Public IP Addresses",
        Severity.HIGH,
        (
            f"Auto Scaling group {result.group_name} "
            "uses a launch configuration that assigns "
            "public IP addresses to launched instances."
        ),
        (
            "Create a new launch configuration without public "
            "IP assignment and update the Auto Scaling group "
            "to use the new configuration."
        ),
        [
            "AWS Security Hub AutoScaling.5",
            "AWS Config autoscaling-launch-config-public-ip-disabled",
        ],
    )


def check_autoscaling_multiple_instance_types(
    group_name: str,
    group_arn: str | None,
    instance_types: list[str],
    instance_type_count: int,
    instance_type_data_available: bool,
    uses_attribute_based_instance_types: bool,
) -> AutoScalingResult | None:
    if (
        not group_name
        or not instance_type_data_available
        or uses_attribute_based_instance_types
    ):
        return None

    if instance_type_count >= 2:
        return None

    return AutoScalingResult(
        group_name=group_name,
        group_arn=group_arn,
        reason="only_one_explicit_instance_type",
        evidence={
            "instance_types": instance_types,
            "instance_type_count": instance_type_count,
        },
    )


def build_autoscaling_multiple_instance_types_finding(
    result: AutoScalingResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-AUTOSCALING-006",
        "Auto Scaling Group Does Not Use Multiple Instance Types",
        Severity.MEDIUM,
        (
            f"Auto Scaling group {result.group_name} "
            "does not define multiple explicit instance types."
        ),
        (
            "Configure the Auto Scaling group with multiple "
            "explicit instance types so it can use alternative "
            "capacity pools when capacity is constrained."
        ),
        [
            "AWS Security Hub AutoScaling.6",
            "AWS Config autoscaling-multiple-instance-types",
        ],
    )


def check_autoscaling_launch_template(
    group_name: str,
    group_arn: str | None,
    has_launch_template: bool,
) -> AutoScalingResult | None:
    if not group_name:
        return None

    if has_launch_template:
        return None

    return AutoScalingResult(
        group_name=group_name,
        group_arn=group_arn,
        reason="launch_template_not_configured",
        evidence={
            "has_launch_template": False,
        },
    )


def build_autoscaling_launch_template_finding(
    result: AutoScalingResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-AUTOSCALING-009",
        "Auto Scaling Group Does Not Use an EC2 Launch Template",
        Severity.MEDIUM,
        (
            f"Auto Scaling group {result.group_name} "
            "is not configured with an EC2 launch template."
        ),
        (
            "Replace the launch configuration with an EC2 "
            "launch template and configure the Auto Scaling "
            "group to use the launch template."
        ),
        [
            "AWS Security Hub AutoScaling.9",
            "AWS Config autoscaling-launch-template",
        ],
    )


def check_autoscaling_tags(
    group_name: str,
    group_arn: str | None,
    has_non_system_tags: bool,
) -> AutoScalingResult | None:
    if not group_name:
        return None

    if has_non_system_tags:
        return None

    return AutoScalingResult(
        group_name=group_name,
        group_arn=group_arn,
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def build_autoscaling_tags_finding(
    result: AutoScalingResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-AUTOSCALING-010",
        "Auto Scaling Group Is Not Tagged",
        Severity.LOW,
        (
            f"Auto Scaling group {result.group_name} "
            "does not have any non-system tags."
        ),
        (
            "Add the required organizational tags to the "
            "Auto Scaling group. CloudSentinel evaluates "
            "baseline presence of at least one non-system tag."
        ),
        [
            "AWS Security Hub AutoScaling.10",
            "AWS Resource Tagging Standard",
        ],
    )
