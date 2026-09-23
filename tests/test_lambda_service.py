from unittest.mock import MagicMock, patch

from scanner.aws.services.lambda_service import LambdaService


def test_list_event_source_mappings():
    session = MagicMock()
    lambda_client = MagicMock()

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "EventSourceMappings": [
                {
                    "UUID": "mapping-1",
                    "EventSourceArn": (
                        "arn:aws:sqs:eu-north-1:"
                        "123456789012:queue"
                    ),
                }
            ]
        }
    ]

    lambda_client.get_paginator.return_value = paginator

    with patch(
        "scanner.aws.services.lambda_service.create_aws_client",
        return_value=lambda_client,
    ):
        service = LambdaService(session)

    mappings = service.list_event_source_mappings(
        "test-function"
    )

    assert mappings == [
        {
            "UUID": "mapping-1",
            "EventSourceArn": (
                "arn:aws:sqs:eu-north-1:"
                "123456789012:queue"
            ),
        }
    ]

    lambda_client.get_paginator.assert_called_once_with(
        "list_event_source_mappings"
    )


def test_get_subnet_availability_zones():
    session = MagicMock()
    lambda_client = MagicMock()
    ec2_client = MagicMock()

    ec2_client.describe_subnets.return_value = {
        "Subnets": [
            {
                "SubnetId": "subnet-a",
                "AvailabilityZone": "eu-north-1a",
            },
            {
                "SubnetId": "subnet-b",
                "AvailabilityZone": "eu-north-1b",
            },
        ]
    }

    with patch(
        "scanner.aws.services.lambda_service.create_aws_client",
        side_effect=[lambda_client, ec2_client],
    ):
        service = LambdaService(session)

        result = service.get_subnet_availability_zones(
            [
                "subnet-a",
                "subnet-b",
            ]
        )

    assert result == {
        "subnet-a": "eu-north-1a",
        "subnet-b": "eu-north-1b",
    }

    ec2_client.describe_subnets.assert_called_once_with(
        SubnetIds=[
            "subnet-a",
            "subnet-b",
        ]
    )


def test_get_subnet_availability_zones_empty_input():
    session = MagicMock()
    lambda_client = MagicMock()

    with patch(
        "scanner.aws.services.lambda_service.create_aws_client",
        return_value=lambda_client,
    ):
        service = LambdaService(session)

        result = service.get_subnet_availability_zones([])

    assert result == {}
