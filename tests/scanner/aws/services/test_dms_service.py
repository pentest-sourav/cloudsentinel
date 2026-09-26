from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.dms import DMSService


def _error():
    return ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "DescribeReplicationInstances",
    )


def _service(client):
    session = Mock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.dms.create_aws_client",
            lambda *_: client,
        )
        return DMSService(session)


def _paginator_client(items):
    client = Mock()
    paginator = Mock()
    paginator.paginate.return_value = items
    client.get_paginator.return_value = paginator
    return client, paginator


def test_describe_replication_instances():
    client, paginator = _paginator_client(
        [
            {
                "ReplicationInstances": [
                    {
                        "ReplicationInstanceArn": "arn:ri"
                    }
                ]
            }
        ]
    )

    service = _service(client)

    assert service.describe_replication_instances() == [
        {
            "ReplicationInstanceArn": "arn:ri"
        }
    ]

    client.get_paginator.assert_called_once_with(
        "describe_replication_instances"
    )


def test_describe_certificates():
    client, _ = _paginator_client(
        [
            {
                "Certificates": [
                    {
                        "CertificateArn": "arn:cert"
                    }
                ]
            }
        ]
    )

    assert _service(
        client
    ).describe_certificates() == [
        {
            "CertificateArn": "arn:cert"
        }
    ]


def test_describe_event_subscriptions():
    client, _ = _paginator_client(
        [
            {
                "EventSubscriptions": [
                    {
                        "EventSubscriptionArn": "arn:event"
                    }
                ]
            }
        ]
    )

    assert _service(
        client
    ).describe_event_subscriptions() == [
        {
            "EventSubscriptionArn": "arn:event"
        }
    ]


def test_describe_replication_subnet_groups():
    client, _ = _paginator_client(
        [
            {
                "ReplicationSubnetGroups": [
                    {
                        "ReplicationSubnetGroupArn": "arn:subnet"
                    }
                ]
            }
        ]
    )

    assert _service(
        client
    ).describe_replication_subnet_groups() == [
        {
            "ReplicationSubnetGroupArn": "arn:subnet"
        }
    ]


def test_describe_replication_tasks():
    client, _ = _paginator_client(
        [
            {
                "ReplicationTasks": [
                    {
                        "ReplicationTaskArn": "arn:task"
                    }
                ]
            }
        ]
    )

    assert _service(
        client
    ).describe_replication_tasks() == [
        {
            "ReplicationTaskArn": "arn:task"
        }
    ]


def test_describe_endpoints():
    client, _ = _paginator_client(
        [
            {
                "Endpoints": [
                    {
                        "EndpointArn": "arn:endpoint"
                    }
                ]
            }
        ]
    )

    assert _service(
        client
    ).describe_endpoints() == [
        {
            "EndpointArn": "arn:endpoint"
        }
    ]


def test_list_tags_for_resource():
    client = Mock()

    client.list_tags_for_resource.return_value = {
        "TagList": [
            {
                "Key": "Environment",
                "Value": "prod",
            },
            {
                "Key": "Owner",
                "Value": "security",
            },
        ]
    }

    service = _service(client)

    assert service.list_tags_for_resource(
        "arn:resource"
    ) == {
        "Environment": "prod",
        "Owner": "security",
    }


def test_empty_tag_arn_returns_empty():
    client = Mock()

    service = _service(client)

    assert service.list_tags_for_resource("") == {}

    client.list_tags_for_resource.assert_not_called()


def test_api_error_is_normalized():
    client = Mock()

    client.get_paginator.side_effect = _error()

    service = _service(client)

    with pytest.raises(
        RuntimeError,
        match="AWS DMS describe_replication_instances failed",
    ):
        service.describe_replication_instances()
