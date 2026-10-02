from unittest.mock import Mock

from scanner.aws.collectors.ec2_tagging import (
    EC2TaggingDataCollector,
)


def test_instance_tagging_normalizes_resources():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-123",
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        }
    ]

    collector = EC2TaggingDataCollector(service)

    result = collector.collect_instances()

    assert result == [
        {
            "resource_id": "i-123",
            "resource_type": "ec2_instance",
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        }
    ]


def test_missing_tags_are_normalized_to_empty_list():
    service = Mock()

    service.describe_all_volumes.return_value = [
        {
            "VolumeId": "vol-123",
        }
    ]

    collector = EC2TaggingDataCollector(service)

    result = collector.collect_volumes()

    assert result == [
        {
            "resource_id": "vol-123",
            "resource_type": "ebs_volume",
            "tags": [],
        }
    ]


def test_mocked_unconfigured_service_response_is_ignored():
    service = Mock()

    collector = EC2TaggingDataCollector(service)

    result = collector.collect_network_interfaces()

    assert result == []
