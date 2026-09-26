from unittest.mock import Mock

from scanner.aws.scanners.neptune import NeptuneScanner


def test_neptune_scanner_executes_registered_rules():
    service = Mock()

    service.describe_db_clusters.return_value = [
        {
            "DBClusterIdentifier": "cluster-1",
            "StorageEncrypted": False,
            "EnabledCloudwatchLogsExports": [],
            "DeletionProtection": False,
            "BackupRetentionPeriod": 1,
            "IAMDatabaseAuthenticationEnabled": False,
        }
    ]

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "instance-1",
            "DBClusterIdentifier": "cluster-1",
            "AvailabilityZone": "ap-south-1a",
        }
    ]

    service.describe_db_cluster_snapshots.return_value = []

    scanner = NeptuneScanner(service)

    findings = scanner.scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert "CS-AWS-NEPTUNE-001" in rule_ids
    assert "CS-AWS-NEPTUNE-002" in rule_ids
    assert "CS-AWS-NEPTUNE-004" in rule_ids
    assert "CS-AWS-NEPTUNE-005" in rule_ids
    assert "CS-AWS-NEPTUNE-007" in rule_ids
    assert "CS-AWS-NEPTUNE-009" in rule_ids

    assert "CS-AWS-NEPTUNE-003" not in rule_ids
    assert "CS-AWS-NEPTUNE-006" not in rule_ids
