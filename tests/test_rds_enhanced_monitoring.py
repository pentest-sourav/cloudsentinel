from engine.findings.model import Severity
from engine.rules.aws.rds.enhanced_monitoring import (
    build_rds_enhanced_monitoring_finding,
    check_rds_enhanced_monitoring,
)


def test_detects_disabled_enhanced_monitoring():
    result = check_rds_enhanced_monitoring(
        db_instance_id="cloudsentinel-db",
        monitoring_interval=0,
    )

    assert result is not None
    assert result.db_instance_id == "cloudsentinel-db"
    assert result.monitoring_interval == 0


def test_accepts_enabled_enhanced_monitoring():
    for interval in (1, 5, 10, 15, 30, 60):
        result = check_rds_enhanced_monitoring(
            db_instance_id="cloudsentinel-db",
            monitoring_interval=interval,
        )

        assert result is None


def test_missing_monitoring_interval_is_unknown():
    result = check_rds_enhanced_monitoring(
        db_instance_id="cloudsentinel-db",
        monitoring_interval=None,
    )

    assert result is None


def test_missing_db_instance_id_is_ignored():
    result = check_rds_enhanced_monitoring(
        db_instance_id="",
        monitoring_interval=0,
    )

    assert result is None


def test_enhanced_monitoring_finding():
    result = check_rds_enhanced_monitoring(
        db_instance_id="cloudsentinel-db",
        monitoring_interval=0,
    )

    assert result is not None

    finding = build_rds_enhanced_monitoring_finding(result)

    assert finding.rule_id == "CS-AWS-RDS-009"
    assert finding.severity == Severity.LOW
    assert finding.resource_type == "rds_instance"
    assert finding.resource_id == "cloudsentinel-db"
    assert finding.evidence["monitoring_interval"] == 0
    assert finding.compliance == [
        "AWS Security Hub CSPM RDS.6"
    ]
