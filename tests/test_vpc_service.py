from unittest.mock import MagicMock

from scanner.aws.services.vpc import VPCService


def test_describe_default_security_groups():
    session = MagicMock()
    client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = client
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-default",
                    "GroupName": "default",
                    "VpcId": "vpc-123",
                }
            ]
        }
    ]

    service = VPCService(session)

    result = service.describe_default_security_groups()

    assert result == [
        {
            "GroupId": "sg-default",
            "GroupName": "default",
            "VpcId": "vpc-123",
        }
    ]

    client.get_paginator.assert_called_once_with(
        "describe_security_groups"
    )


def test_describe_flow_logs():
    session = MagicMock()
    client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = client
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {
            "FlowLogs": [
                {
                    "FlowLogId": "fl-123",
                    "ResourceId": "vpc-123",
                    "FlowLogStatus": "ACTIVE",
                }
            ]
        }
    ]

    service = VPCService(session)

    result = service.describe_flow_logs()

    assert result == [
        {
            "FlowLogId": "fl-123",
            "ResourceId": "vpc-123",
            "FlowLogStatus": "ACTIVE",
        }
    ]

    client.get_paginator.assert_called_once_with(
        "describe_flow_logs"
    )


def test_describe_network_acls():
    session = MagicMock()
    client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = client
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {
            "NetworkAcls": [
                {
                    "NetworkAclId": "acl-123",
                    "VpcId": "vpc-123",
                    "IsDefault": False,
                    "Entries": [
                        {
                            "RuleNumber": 100,
                            "Egress": False,
                            "RuleAction": "allow",
                            "Protocol": "-1",
                            "CidrBlock": "0.0.0.0/0",
                        }
                    ],
                }
            ]
        }
    ]

    service = VPCService(session)

    result = service.describe_network_acls()

    assert result == [
        {
            "NetworkAclId": "acl-123",
            "VpcId": "vpc-123",
            "IsDefault": False,
            "Entries": [
                {
                    "RuleNumber": 100,
                    "Egress": False,
                    "RuleAction": "allow",
                    "Protocol": "-1",
                    "CidrBlock": "0.0.0.0/0",
                }
            ],
        }
    ]

    client.get_paginator.assert_called_once_with(
        "describe_network_acls"
    )
