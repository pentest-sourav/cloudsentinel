from typing import Any

from scanner.aws.collectors.ec2 import EC2DataCollector
from scanner.aws.collectors.security_group_rules import (
    SecurityGroupRuleCollector,
)


def collect_ec2_security_group_rules(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    security_groups = collector.collect_security_groups()

    rule_collector = SecurityGroupRuleCollector()

    return rule_collector.collect(security_groups)


def collect_ec2_instances(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_instances()


def collect_ec2_ebs_volumes(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_ebs_volumes()


def collect_ec2_snapshots(
    collector: EC2DataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_snapshots()


EC2_DATA_SOURCE_HANDLERS = {
    "ec2_security_group_rules": collect_ec2_security_group_rules,
    "ec2_instances": collect_ec2_instances,
    "ec2_ebs_volumes": collect_ec2_ebs_volumes,
    "ec2_snapshots": collect_ec2_snapshots,
}
