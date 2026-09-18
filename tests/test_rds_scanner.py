from unittest.mock import MagicMock

from scanner.aws.scanners.rds import RDSScanner


def test_rds_scanner_detects_public_rds():
    service = MagicMock()

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "cloudsentinel-db",
            "Engine": "postgres",
            "EngineVersion": "16.3",
            "PubliclyAccessible": True,
            "StorageEncrypted": True,
            "BackupRetentionPeriod": 7,
            "MultiAZ": True,
            "DeletionProtection": True,
        }
    ]

    scanner = RDSScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-RDS-001"
    assert finding.resource_id == "cloudsentinel-db"
    assert finding.severity.value == "high"
    assert finding.evidence["publicly_accessible"] is True


def test_rds_scanner_returns_no_findings_for_private_rds():
    service = MagicMock()

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "cloudsentinel-db",
            "PubliclyAccessible": False,
            "StorageEncrypted": True,
            "BackupRetentionPeriod": 7,
            "MultiAZ": True,
            "DeletionProtection": True,
        }
    ]

    scanner = RDSScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_rds_scanner_handles_empty_account():
    service = MagicMock()

    service.describe_db_instances.return_value = []

    scanner = RDSScanner(service)

    findings = scanner.scan()

    assert findings == []

def test_rds_scanner_detects_unencrypted_rds():
    service = MagicMock()

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "cloudsentinel-db",
            "Engine": "postgres",
            "EngineVersion": "16.3",
            "PubliclyAccessible": False,
            "StorageEncrypted": False,
            "BackupRetentionPeriod": 7,
            "MultiAZ": True,
            "DeletionProtection": True,
        }
    ]

    scanner = RDSScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-RDS-002"
    assert finding.resource_id == "cloudsentinel-db"
    assert finding.severity.value == "high"
    assert finding.evidence["storage_encrypted"] is False
