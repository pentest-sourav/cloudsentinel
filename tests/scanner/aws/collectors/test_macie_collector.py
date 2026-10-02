from unittest.mock import Mock

from scanner.aws.collectors.macie import (
    MacieDataCollector,
)


def test_collect_account_configuration_for_standalone_account():
    service = Mock()

    service.get_macie_session.return_value = {
        "status": "ENABLED",
        "accountId": "123456789012",
    }

    service.get_administrator_account.return_value = None

    service.get_automated_discovery_configuration.return_value = {
        "status": "ENABLED",
        "autoEnableOrganizationMembers": "NONE",
        "classificationScopeId": "scope-123",
        "sensitivityInspectionTemplateId": "template-123",
    }

    collector = MacieDataCollector(service)

    result = collector.collect_account_configuration()

    assert result == [
        {
            "resource_id": "123456789012",
            "account_id": "123456789012",
            "macie_status": "ENABLED",
            "administrator_account_id": None,
            "relationship_status": None,
            "is_member_account": False,
            "automated_discovery_status": "ENABLED",
            "auto_enable_organization_members": "NONE",
            "classification_scope_id": "scope-123",
            "sensitivity_inspection_template_id": (
                "template-123"
            ),
        }
    ]

    service.get_macie_session.assert_called_once_with()
    service.get_administrator_account.assert_called_once_with()
    service.get_automated_discovery_configuration.assert_called_once_with()


def test_collect_account_configuration_for_member_skips_admin_config():
    service = Mock()

    service.get_macie_session.return_value = {
        "status": "ENABLED",
        "accountId": "123456789012",
    }

    service.get_administrator_account.return_value = {
        "administrator": {
            "accountId": "999999999999",
            "relationshipStatus": "Enabled",
        }
    }

    collector = MacieDataCollector(service)

    result = collector.collect_account_configuration()

    assert result == [
        {
            "resource_id": "123456789012",
            "account_id": "123456789012",
            "macie_status": "ENABLED",
            "administrator_account_id": (
                "999999999999"
            ),
            "relationship_status": "Enabled",
            "is_member_account": True,
            "automated_discovery_status": None,
            "auto_enable_organization_members": None,
            "classification_scope_id": None,
            "sensitivity_inspection_template_id": None,
        }
    ]

    service.get_macie_session.assert_called_once_with()
    service.get_administrator_account.assert_called_once_with()
    service.get_automated_discovery_configuration.assert_not_called()


def test_collect_account_configuration_uses_session_without_account_id():
    service = Mock()

    service.get_macie_session.return_value = {
        "status": "PAUSED",
    }

    service.get_administrator_account.return_value = None

    service.get_automated_discovery_configuration.return_value = {
        "status": "DISABLED",
    }

    collector = MacieDataCollector(service)

    result = collector.collect_account_configuration()

    assert result[0]["resource_id"] == "aws-account"
    assert result[0]["macie_status"] == "PAUSED"
