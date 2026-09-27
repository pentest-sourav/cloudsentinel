from unittest.mock import MagicMock

from scanner.aws.collectors.security_groups import (
    SecurityGroupDataCollector,
)


def test_collect_security_group_inventory_counts_eni_attachments():
    service = MagicMock()

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-used",
            "GroupName": "web",
            "Description": "web",
            "VpcId": "vpc-1",
            "IpPermissions": [],
            "IpPermissionsEgress": [],
        },
        {
            "GroupId": "sg-unused",
            "GroupName": "unused",
            "Description": "unused",
            "VpcId": "vpc-1",
            "IpPermissions": [],
            "IpPermissionsEgress": [],
        },
    ]

    service.describe_network_interfaces.return_value = [
        {
            "NetworkInterfaceId": "eni-1",
            "Groups": [
                {"GroupId": "sg-used", "GroupName": "web"},
            ],
        },
        {
            "NetworkInterfaceId": "eni-2",
            "Groups": [
                {"GroupId": "sg-used", "GroupName": "web"},
            ],
        },
    ]

    collector = SecurityGroupDataCollector(service)

    result = collector.collect_security_group_inventory()

    assert result == [
        {
            "group_id": "sg-used",
            "group_name": "web",
            "is_default": False,
            "attached_eni_count": 2,
        },
        {
            "group_id": "sg-unused",
            "group_name": "unused",
            "is_default": False,
            "attached_eni_count": 0,
        },
    ]


def test_collect_security_group_inventory_deduplicates_groups_per_eni():
    service = MagicMock()

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-1",
            "GroupName": "web",
            "IpPermissions": [],
        },
    ]

    service.describe_network_interfaces.return_value = [
        {
            "NetworkInterfaceId": "eni-1",
            "Groups": [
                {"GroupId": "sg-1"},
                {"GroupId": "sg-1"},
            ],
        },
    ]

    collector = SecurityGroupDataCollector(service)

    result = collector.collect_security_group_inventory()

    assert result[0]["attached_eni_count"] == 1
