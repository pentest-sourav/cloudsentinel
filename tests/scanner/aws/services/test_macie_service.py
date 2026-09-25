from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
)

from scanner.aws.services.macie import MacieService


def make_service():
    session = Mock()
    client = Mock()

    with patch(
        "scanner.aws.services.macie.create_aws_client",
        return_value=client,
    ):
        service = MacieService(session)

    return service, client


def test_get_macie_session_returns_configuration():
    service, client = make_service()

    client.get_macie_session.return_value = {
        "status": "ENABLED",
        "serviceRole": (
            "arn:aws:iam::123456789012:"
            "role/aws-service-role/macie.amazonaws.com/"
            "AWSServiceRoleForAmazonMacie"
        ),
    }

    result = service.get_macie_session()

    client.get_macie_session.assert_called_once_with()

    assert result["status"] == "ENABLED"
    assert "serviceRole" in result


def test_get_administrator_account_returns_configuration():
    service, client = make_service()

    client.get_administrator_account.return_value = {
        "administrator": {
            "accountId": "999999999999",
            "relationshipStatus": "Enabled",
        }
    }

    result = service.get_administrator_account()

    client.get_administrator_account.assert_called_once_with()

    assert result["administrator"]["accountId"] == (
        "999999999999"
    )
    assert result["administrator"][
        "relationshipStatus"
    ] == "Enabled"


def test_get_administrator_account_returns_none_when_not_member():
    service, client = make_service()

    client.get_administrator_account.side_effect = (
        ClientError(
            {
                "Error": {
                    "Code": "ResourceNotFoundException",
                    "Message": "Administrator not found",
                }
            },
            "GetAdministratorAccount",
        )
    )

    assert (
        service.get_administrator_account()
        is None
    )


def test_get_automated_discovery_configuration_returns_configuration():
    service, client = make_service()

    client.get_automated_discovery_configuration.return_value = {
        "status": "ENABLED",
        "autoEnableOrganizationMembers": "ALL",
        "classificationScopeId": "scope-123",
        "sensitivityInspectionTemplateId": "template-123",
    }

    result = (
        service.get_automated_discovery_configuration()
    )

    client.get_automated_discovery_configuration.assert_called_once_with()

    assert result["status"] == "ENABLED"
    assert result[
        "autoEnableOrganizationMembers"
    ] == "ALL"


def test_get_macie_session_wraps_client_error():
    service, client = make_service()

    client.get_macie_session.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        "GetMacieSession",
    )

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: Access denied",
    ):
        service.get_macie_session()


def test_get_macie_session_wraps_sdk_error():
    service, client = make_service()

    client.get_macie_session.side_effect = (
        BotoCoreError()
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error",
    ):
        service.get_macie_session()


def test_get_automated_discovery_wraps_client_error():
    service, client = make_service()

    client.get_automated_discovery_configuration.side_effect = (
        ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Access denied",
                }
            },
            "GetAutomatedDiscoveryConfiguration",
        )
    )

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: Access denied",
    ):
        service.get_automated_discovery_configuration()
