from typing import Any, Callable

from scanner.aws.collectors.ec2 import EC2DataCollector
from scanner.aws.collectors.security_group_rules import (
    SecurityGroupRuleCollector,
)


def collect_ec2_security_group_rules(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    """
    Collect raw AWS EC2 security groups and convert them into
    RuleExecutor-compatible security-group rule records.
    """

    security_groups = collector.collect_security_groups()

    rule_collector = SecurityGroupRuleCollector()

    return rule_collector.collect(security_groups)


def collect_ec2_instances(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    """
    Collect EC2 instances in normalized form.

    Security analysis is performed by the rule engine.
    """

    return collector.collect_instances()


def collect_ec2_ebs_volumes(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    """
    Collect EBS volumes attached to EC2 instances
    in normalized form.
    """

    return collector.collect_ebs_volumes()


EC2_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[EC2DataCollector], Any],
] = {
    "ec2_security_group_rules": (
        collect_ec2_security_group_rules
    ),
    "ec2_instances": (
        collect_ec2_instances
    ),
    "ec2_ebs_volumes": (
        collect_ec2_ebs_volumes
    ),
}
