from unittest.mock import Mock

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.services.route_tables import RouteTableService
from scanner.aws.session import AWS_RETRY_CONFIG


def test_route_table_service_uses_centralized_retry_config():
    fake_session = Mock(spec=boto3.Session)
    fake_ec2 = Mock()
    fake_session.client.return_value = fake_ec2

    RouteTableService(fake_session)

    fake_session.client.assert_called_once_with(
        "ec2",
        config=AWS_RETRY_CONFIG,
    )


def test_describe_route_tables_collects_all_pages():
    fake_session = Mock(spec=boto3.Session)
    fake_ec2 = Mock()
    paginator = Mock()

    fake_session.client.return_value = fake_ec2
    fake_ec2.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {
            "RouteTables": [
                {"RouteTableId": "rtb-001"},
            ]
        },
        {
            "RouteTables": [
                {"RouteTableId": "rtb-002"},
            ]
        },
    ]

    service = RouteTableService(fake_session)

    result = service.describe_route_tables()

    assert result == [
        {"RouteTableId": "rtb-001"},
        {"RouteTableId": "rtb-002"},
    ]

    fake_ec2.get_paginator.assert_called_once_with(
        "describe_route_tables"
    )
    paginator.paginate.assert_called_once_with()


def test_describe_route_tables_handles_client_error():
    fake_session = Mock(spec=boto3.Session)
    fake_ec2 = Mock()
    paginator = Mock()

    fake_session.client.return_value = fake_ec2
    fake_ec2.get_paginator.return_value = paginator

    paginator.paginate.side_effect = ClientError(
        {
            "Error": {
                "Code": "UnauthorizedOperation",
                "Message": "not authorized",
            }
        },
        "DescribeRouteTables",
    )

    service = RouteTableService(fake_session)

    try:
        service.describe_route_tables()
        assert False
    except RuntimeError as exc:
        assert "UnauthorizedOperation" in str(exc)
        assert "not authorized" in str(exc)


def test_describe_route_tables_handles_botocore_error():
    fake_session = Mock(spec=boto3.Session)
    fake_ec2 = Mock()
    paginator = Mock()

    fake_session.client.return_value = fake_ec2
    fake_ec2.get_paginator.return_value = paginator

    paginator.paginate.side_effect = BotoCoreError()

    service = RouteTableService(fake_session)

    try:
        service.describe_route_tables()
        assert False
    except RuntimeError as exc:
        assert str(exc) == (
            "AWS SDK error during Route Table discovery: "
            "An unspecified error occurred"
        )
