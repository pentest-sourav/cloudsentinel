from unittest.mock import Mock


DOMAIN_ARN = (
    "arn:aws:es:ap-south-1:"
    "123456789012:domain/cloudsentinel"
)


def make_domain(
    name="cloudsentinel",
    arn=DOMAIN_ARN,
):
    return {
        "DomainName": name,
        "ARN": arn,
        "DomainId": "domain-id",
        "DomainProcessingStatus": "Active",
        "EncryptionAtRestOptions": {
            "Enabled": True,
            "KmsKeyId": "key-id",
        },
        "NodeToNodeEncryptionOptions": {
            "Enabled": True,
        },
        "VPCOptions": {
            "VPCId": "vpc-123",
            "SubnetIds": [
                "subnet-123",
                "subnet-456",
            ],
        },
        "LogPublishingOptions": {
            "ES_APPLICATION_LOGS": {
                "Enabled": True,
                "CloudWatchLogsLogGroupArn": "arn:error",
            },
            "AUDIT_LOGS": {
                "Enabled": True,
                "CloudWatchLogsLogGroupArn": "arn:audit",
            },
        },
        "ServiceSoftwareOptions": {
            "CurrentVersion": "R2025",
            "NewVersion": "R2025",
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


def test_collect_domains_normalizes_domain():
    from scanner.aws.collectors.opensearch import (
        OpenSearchDataCollector,
    )

    service = Mock()

    service.list_domain_names.return_value = [
        "cloudsentinel",
    ]
    service.describe_domain.return_value = make_domain()
    service.list_tags.return_value = [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]

    collector = OpenSearchDataCollector(service)

    result = collector.collect_domains()

    assert result == [
        {
            "domain_name": "cloudsentinel",
            "domain_arn": DOMAIN_ARN,
            "domain_id": "domain-id",
            "domain_processing_status": "Active",
            "encryption_at_rest_options": {
                "Enabled": True,
                "KmsKeyId": "key-id",
            },
            "node_to_node_encryption_options": {
                "Enabled": True,
            },
            "vpc_options": {
                "VPCId": "vpc-123",
                "SubnetIds": [
                    "subnet-123",
                    "subnet-456",
                ],
            },
            "log_publishing_options": {
                "ES_APPLICATION_LOGS": {
                    "Enabled": True,
                    "CloudWatchLogsLogGroupArn": "arn:error",
                },
                "AUDIT_LOGS": {
                    "Enabled": True,
                    "CloudWatchLogsLogGroupArn": "arn:audit",
                },
            },
            "service_software_options": {
                "CurrentVersion": "R2025",
                "NewVersion": "R2025",
                "UpdateAvailable": False,
            },
            "domain_endpoint_options": {
                "EnforceHTTPS": True,
                "TLSSecurityPolicy": (
                    "Policy-Min-TLS-1-2-PFS-2023-10"
                ),
            },
            "advanced_security_options": {
                "Enabled": True,
            },
            "cluster_config": {
                "InstanceCount": 3,
                "ZoneAwarenessEnabled": True,
                "DedicatedMasterEnabled": True,
                "DedicatedMasterCount": 3,
            },
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        }
    ]


def test_collect_domains_skips_domain_without_arn():
    from scanner.aws.collectors.opensearch import (
        OpenSearchDataCollector,
    )

    service = Mock()

    service.list_domain_names.return_value = [
        "invalid",
    ]
    service.describe_domain.return_value = {
        "DomainName": "invalid",
    }

    collector = OpenSearchDataCollector(service)

    assert collector.collect_domains() == []

    service.list_tags.assert_not_called()


def test_collect_domains_caches_discovery():
    from scanner.aws.collectors.opensearch import (
        OpenSearchDataCollector,
    )

    service = Mock()

    service.list_domain_names.return_value = [
        "cloudsentinel",
    ]
    service.describe_domain.return_value = make_domain()
    service.list_tags.return_value = []

    collector = OpenSearchDataCollector(service)

    collector.collect_domains()
    collector.collect_domains()

    service.list_domain_names.assert_called_once_with()
    service.describe_domain.assert_called_once_with(
        "cloudsentinel"
    )
    service.list_tags.assert_called_once_with(
        DOMAIN_ARN
    )


def test_collect_domains_handles_missing_optional_sections():
    from scanner.aws.collectors.opensearch import (
        OpenSearchDataCollector,
    )

    service = Mock()

    service.list_domain_names.return_value = [
        "cloudsentinel",
    ]
    service.describe_domain.return_value = {
        "ARN": DOMAIN_ARN,
    }
    service.list_tags.return_value = []

    collector = OpenSearchDataCollector(service)

    result = collector.collect_domains()

    assert result == [
        {
            "domain_name": "cloudsentinel",
            "domain_arn": DOMAIN_ARN,
            "domain_id": None,
            "domain_processing_status": None,
            "encryption_at_rest_options": {},
            "node_to_node_encryption_options": {},
            "vpc_options": {},
            "log_publishing_options": {},
            "service_software_options": {},
            "domain_endpoint_options": {},
            "advanced_security_options": {},
            "cluster_config": {},
            "tags": [],
        }
    ]
