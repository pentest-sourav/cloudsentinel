from unittest.mock import MagicMock

from scanner.aws.collectors.ec2 import EC2DataCollector


def test_security_groups_are_discovered_without_ec2_instances():
    """
    Security-group discovery must work even when the AWS
    account/region has zero EC2 instances.
    """

    service = MagicMock()

    # No EC2 instances exist.
    service.describe_instances.return_value = []

    # But security groups exist in the region.
    service.describe_all_security_groups.return_value = [
        {
            "GroupId": "sg-standalone-001",
            "GroupName": "default",
            "VpcId": "vpc-001",
            "IpPermissions": [],
        }
    ]

    collector = EC2DataCollector(service)

    groups = collector.collect_security_groups()

    assert groups == [
        {
            "GroupId": "sg-standalone-001",
            "GroupName": "default",
            "VpcId": "vpc-001",
            "IpPermissions": [],
        }
    ]

    # Critical regression checks:
    service.describe_all_security_groups.assert_called_once_with()
    service.describe_instances.assert_not_called()
    service.describe_security_groups.assert_not_called()


def test_security_group_discovery_is_cached():
    """
    Multiple calls to collect_security_groups() must not
    trigger repeated AWS API calls.
    """

    service = MagicMock()

    service.describe_all_security_groups.return_value = [
        {
            "GroupId": "sg-cache-001",
            "GroupName": "cached",
        }
    ]

    collector = EC2DataCollector(service)

    first_result = collector.collect_security_groups()
    second_result = collector.collect_security_groups()

    assert first_result == second_result

    service.describe_all_security_groups.assert_called_once_with()
