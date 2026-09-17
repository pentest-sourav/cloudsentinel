from unittest.mock import MagicMock

from engine.rules.executor import RuleExecutor
from engine.rules.registry.ec2_handlers import (
    EC2_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.ec2_registry import EC2_RULES
from scanner.aws.collectors.ec2 import EC2DataCollector


def test_ec2_security_group_rule_executes_through_registry():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-001",
            "SecurityGroups": [
                {"GroupId": "sg-001"},
            ],
        }
    ]

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-001",
            "GroupName": "public-ssh",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                }
            ],
        }
    ]

    collector = EC2DataCollector(service)

    executor = RuleExecutor(
        handlers=EC2_DATA_SOURCE_HANDLERS,
    )

    findings = executor.execute_registry(
        registry=EC2_RULES,
        collector=collector,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-EC2-001"
    assert finding.title == "SSH Port Exposed to the Internet"
    assert finding.severity.value == "high"
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_security_group"
    assert finding.resource_id == "sg-001"

    assert finding.evidence["source"] == "0.0.0.0/0"
    assert finding.evidence["from_port"] == 22
    assert finding.evidence["to_port"] == 22
    assert finding.evidence["management_service"] == "SSH"
