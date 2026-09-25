from unittest.mock import Mock

from scanner.aws.scanners.opensearch import OpenSearchScanner


DOMAIN_ARN = (
    "arn:aws:es:ap-south-1:"
    "123456789012:domain/cloudsentinel"
)


def test_opensearch_scanner_executes_opensearch_rules():
    service = Mock()

    service.list_domain_names.return_value = [
        "cloudsentinel",
    ]

    service.describe_domain.return_value = {
        "DomainName": "cloudsentinel",
        "ARN": DOMAIN_ARN,
        "EncryptionAtRestOptions": {
            "Enabled": True,
        },
        "NodeToNodeEncryptionOptions": {
            "Enabled": True,
        },
        "VPCOptions": {
            "VPCId": "vpc-123",
        },
        "LogPublishingOptions": {
            "ES_APPLICATION_LOGS": {
                "Enabled": True,
            },
            "AUDIT_LOGS": {
                "Enabled": True,
            },
        },
        "ServiceSoftwareOptions": {
            "UpdateAvailable": False,
        },
        "DomainEndpointOptions": {
            "EnforceHTTPS": True,
            "TLSSecurityPolicy": (
                "Policy-Min-TLS-1-2-PFS-2023-10"
            ),
        },
        "AdvancedSecurityOptions": {
            "Enabled": True,
        },
        "ClusterConfig": {
            "InstanceCount": 3,
            "ZoneAwarenessEnabled": True,
            "DedicatedMasterEnabled": True,
            "DedicatedMasterCount": 3,
        },
    }

    service.list_tags.return_value = [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]

    scanner = OpenSearchScanner(service)

    findings = scanner.scan()

    assert findings == []
