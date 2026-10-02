from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.securityhub import (
    SecurityHubService,
)


def make_service():
    session = Mock()
    client = Mock()
    session.client.return_value = client

    service = SecurityHubService(session)

    return service, session, client


def test_init_creates_securityhub_client():
    service, session, client = make_service()

    assert service.securityhub_client is client
    session.client.assert_called_once()


def test_describe_hub_returns_configuration():
    service, _, client = make_service()

    client.describe_hub.return_value = {
        "HubArn": "arn:aws:securityhub:region:account:hub/default",
        "SubscribedAt": "2026-01-01T00:00:00Z",
        "AutoEnableControls": True,
        "ControlFindingGenerator": "SECURITY_CONTROL",
    }

    result = service.describe_hub()

    assert result["HubArn"].endswith(
        "hub/default"
    )
    assert result["AutoEnableControls"] is True


def test_describe_hub_returns_none_when_not_enabled():
    service, _, client = make_service()

    client.describe_hub.side_effect = ClientError(
        {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "not found",
            }
        },
        "DescribeHub",
    )

    assert service.describe_hub() is None


def test_get_enabled_standards_paginates():
    service, _, client = make_service()

    client.get_enabled_standards.side_effect = [
        {
            "StandardsSubscriptions": [
                {
                    "StandardsArn": "standard-a",
                    "StandardsStatus": "READY",
                }
            ],
            "NextToken": "page-2",
        },
        {
            "StandardsSubscriptions": [
                {
                    "StandardsArn": "standard-b",
                    "StandardsStatus": "INCOMPLETE",
                }
            ]
        },
    ]

    result = service.get_enabled_standards()

    assert [item["StandardsArn"] for item in result] == [
        "standard-a",
        "standard-b",
    ]

    assert client.get_enabled_standards.call_count == 2
    assert client.get_enabled_standards.call_args_list[1].kwargs[
        "NextToken"
    ] == "page-2"


def test_sdk_error_is_wrapped():
    service, _, client = make_service()

    client.get_enabled_standards.side_effect = Exception(
        "boom"
    )

    with pytest.raises(
        RuntimeError,
        match="Unexpected error during Security Hub",
    ):
        service.get_enabled_standards()
