from unittest.mock import Mock

from scanner.aws.scanners.documentdb import DocumentDBScanner


def test_documentdb_scanner_returns_no_findings_for_empty_account():
    service = Mock()
    service.describe_db_clusters.return_value = []
    service.describe_db_cluster_snapshots.return_value = []

    scanner = DocumentDBScanner(service)

    assert scanner.scan() == []


def test_documentdb_scanner_detects_cluster_and_snapshot_findings():
    service = Mock()

    service.describe_db_clusters.return_value = [
        {
            "DBClusterIdentifier": "cluster-1",
            "DBClusterArn": (
                "arn:aws:rds:ap-south-1:123456789012:"
                "cluster:cluster-1"
            ),
            "StorageEncrypted": False,
            "BackupRetentionPeriod": 3,
            "DeletionProtection": False,
            "EnabledCloudwatchLogsExports": [],
            "DBClusterParameterGroup": [
                {
                    "DBClusterParameterGroupName": "custom-docdb",
                    "ParameterApplyStatus": "in-sync",
                }
            ],
        }
    ]

    service.describe_db_cluster_parameters.return_value = [
        {
            "ParameterName": "tls",
            "ParameterValue": "disabled",
        }
    ]

    service.describe_db_cluster_snapshots.return_value = [
        {
            "DBClusterSnapshotIdentifier": "snapshot-1",
            "DBClusterIdentifier": "cluster-1",
            "StorageEncrypted": True,
            "SnapshotType": "manual",
        }
    ]

    service.describe_db_cluster_snapshot_attributes.return_value = {
        "DBClusterSnapshotAttributesResult": {
            "DBClusterSnapshotAttributes": [
                {
                    "AttributeName": "restore",
                    "AttributeValues": ["all"],
                }
            ]
        }
    }

    scanner = DocumentDBScanner(service)
    findings = scanner.scan()

    rule_ids = {finding.rule_id for finding in findings}

    assert "CS-AWS-DOCUMENTDB-001" in rule_ids
    assert "CS-AWS-DOCUMENTDB-002" in rule_ids
    assert "CS-AWS-DOCUMENTDB-003" in rule_ids
    assert "CS-AWS-DOCUMENTDB-004" in rule_ids
    assert "CS-AWS-DOCUMENTDB-005" in rule_ids
    assert "CS-AWS-DOCUMENTDB-006" in rule_ids
