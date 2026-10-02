from unittest.mock import Mock

from scanner.aws.services.ec2 import EC2Service


def test_describe_tagging_resources_collects_paginated_results():
    service = EC2Service.__new__(EC2Service)

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Volumes": [
                {
                    "VolumeId": "vol-123",
                    "Tags": [],
                }
            ]
        },
        {
            "Volumes": [
                {
                    "VolumeId": "vol-456",
                    "Tags": [
                        {
                            "Key": "Environment",
                            "Value": "prod",
                        }
                    ],
                }
            ]
        },
    ]

    service.ec2_client = Mock()
    service.ec2_client.get_paginator.return_value = paginator

    result = service.describe_all_volumes()

    assert result == [
        {
            "VolumeId": "vol-123",
            "Tags": [],
        },
        {
            "VolumeId": "vol-456",
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        },
    ]

    service.ec2_client.get_paginator.assert_called_once_with(
        "describe_volumes"
    )


def test_describe_instances_flattens_reservations():
    service = EC2Service.__new__(EC2Service)

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-123",
                            "Tags": [],
                        }
                    ]
                }
            ]
        }
    ]

    service.ec2_client = Mock()
    service.ec2_client.get_paginator.return_value = paginator

    result = service.describe_instances()

    assert result == [
        {
            "InstanceId": "i-123",
            "Tags": [],
        }
    ]
