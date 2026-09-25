from unittest.mock import Mock

from scanner.aws.scanners.ses import SESScanner


def test_ses_scanner_executes_registered_rules():
    service = Mock()

    service.list_contact_lists.return_value = [
        {"ContactListName": "marketing"},
    ]

    service.get_contact_list.return_value = {
        "ContactListName": "marketing",
        "Tags": [],
    }

    service.list_configuration_sets.return_value = [
        "primary",
    ]

    service.get_configuration_set.return_value = {
        "ConfigurationSetName": "primary",
        "Tags": [],
        "DeliveryOptions": {
            "TlsPolicy": "OPTIONAL",
        },
    }

    scanner = SESScanner(service)

    findings = scanner.scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CS-AWS-SES-001",
        "CS-AWS-SES-002",
        "CS-AWS-SES-003",
    }
