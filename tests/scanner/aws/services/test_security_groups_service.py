from unittest.mock import MagicMock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.services.security_groups import SecurityGroupService


def test_describe_security_groups_uses_paginator():
    session = MagicMock()
    client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = client
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"SecurityGroups": [{"GroupId": "sg-1"}]},
        {"SecurityGroups": [{"GroupId": "sg-2"}]},
    ]

    service = SecurityGroupService(session)

    assert service.describe_security_groups() == [
        {"GroupId": "sg-1"},
        {"GroupId": "sg-2"},
    ]


def test_describe_network_interfaces_uses_paginator():
    session = MagicMock()
    client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = client
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1"}]},
    ]

    service = SecurityGroupService(session)

    assert service.describe_network_interfaces() == [
        {"NetworkInterfaceId": "eni-1"},
    ]


def test_security_group_client_error_is_wrapped():
    session = MagicMock()
    client = MagicMock()

    session.client.return_value = client

    client.get_paginator.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "denied",
            }
        },
        "DescribeSecurityGroups",
    )

    service = SecurityGroupService(session)

    with pytest.raises(RuntimeError, match="AccessDenied"):
        service.describe_security_groups()


def test_network_interface_client_error_is_wrapped():
    session = MagicMock()
    client = MagicMock()

    session.client.return_value = client

    client.get_paginator.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "denied",
            }
        },
        "DescribeNetworkInterfaces",
    )

    service = SecurityGroupService(session)

    with pytest.raises(RuntimeError, match="AccessDenied"):
        service.describe_network_interfaces()


def test_security_group_boto_error_is_wrapped():
    session = MagicMock()
    client = MagicMock()

    session.client.return_value = client

    client.get_paginator.side_effect = BotoCoreError()

    service = SecurityGroupService(session)

    with pytest.raises(RuntimeError, match="AWS SDK error"):
        service.describe_security_groups()


def test_network_interface_boto_error_is_wrapped():
    session = MagicMock()
    client = MagicMock()

    session.client.return_value = client

    client.get_paginator.side_effect = BotoCoreError()

    service = SecurityGroupService(session)

    with pytest.raises(RuntimeError, match="AWS SDK error"):
        service.describe_network_interfaces()
