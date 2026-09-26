from unittest.mock import Mock

from scanner.aws.scanners.msk import MSKScanner


def test_msk_scanner_executes_all_registered_rules():
    service = Mock()

    service.list_clusters.return_value = [
        {
            "ClusterArn": "arn:cluster:1",
        },
    ]

    service.describe_cluster.return_value = {
        "ClusterArn": "arn:cluster:1",
        "ClusterName": "insecure-msk",
        "ClusterType": "PROVISIONED",
        "State": "ACTIVE",
        "ClientAuthentication": {
            "Unauthenticated": {
                "Enabled": True,
            },
        },
        "EncryptionInfo": {
            "EncryptionInTransit": {
                "InCluster": False,
            },
        },
        "EnhancedMonitoring": "DEFAULT",
        "Provisioned": {
            "BrokerNodeGroupInfo": {
                "ConnectivityInfo": {
                    "PublicAccess": {
                        "Type": "SERVICE_PROVIDED_EIPS",
                    },
                },
            },
        },
    }

    service.list_connectors.return_value = [
        {
            "connectorArn": "arn:connector:1",
            "connectorName": "insecure-connector",
            "connectorState": "RUNNING",
            "kafkaClusterEncryptionInTransit": {
                "encryptionType": "PLAINTEXT",
            },
            "logDelivery": {
                "workerLogDelivery": {
                    "cloudWatchLogs": {
                        "enabled": False,
                    },
                    "firehose": {
                        "enabled": False,
                    },
                    "s3": {
                        "enabled": False,
                    },
                },
            },
        },
    ]

    findings = MSKScanner(service).scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CS-AWS-MSK-001",
        "CS-AWS-MSK-002",
        "CS-AWS-MSK-003",
        "CS-AWS-MSK-004",
        "CS-AWS-MSK-005",
        "CS-AWS-MSK-006",
    }
