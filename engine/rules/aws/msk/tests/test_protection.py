from engine.findings.model import Severity
from engine.rules.aws.msk.protection import (
    build_msk_connector_encryption_finding,
    build_msk_connector_logging_finding,
    build_msk_enhanced_monitoring_finding,
    build_msk_in_cluster_encryption_finding,
    build_msk_public_access_finding,
    build_msk_unauthenticated_access_finding,
    check_msk_connector_encryption,
    check_msk_connector_logging,
    check_msk_enhanced_monitoring,
    check_msk_in_cluster_encryption,
    check_msk_public_access,
    check_msk_unauthenticated_access,
)


def test_msk_in_cluster_encryption():
    assert check_msk_in_cluster_encryption(
        "arn:cluster",
        True,
    ) is None

    result = check_msk_in_cluster_encryption(
        "arn:cluster",
        False,
    )

    assert result is not None
    assert result.resource_type == "msk_cluster"

    finding = build_msk_in_cluster_encryption_finding(result)

    assert finding.rule_id == "CS-AWS-MSK-001"
    assert finding.severity == Severity.MEDIUM


def test_msk_enhanced_monitoring():
    assert check_msk_enhanced_monitoring(
        "arn:cluster",
        "PROVISIONED",
        "PER_TOPIC_PER_BROKER",
    ) is None

    assert check_msk_enhanced_monitoring(
        "arn:cluster",
        "SERVERLESS",
        None,
    ) is None

    result = check_msk_enhanced_monitoring(
        "arn:cluster",
        "PROVISIONED",
        "DEFAULT",
    )

    assert result is not None

    finding = build_msk_enhanced_monitoring_finding(result)

    assert finding.rule_id == "CS-AWS-MSK-002"
    assert finding.severity == Severity.LOW


def test_msk_connector_encryption():
    assert check_msk_connector_encryption(
        "arn:connector",
        "TLS",
    ) is None

    result = check_msk_connector_encryption(
        "arn:connector",
        "PLAINTEXT",
    )

    assert result is not None

    finding = build_msk_connector_encryption_finding(result)

    assert finding.rule_id == "CS-AWS-MSK-003"
    assert finding.severity == Severity.MEDIUM


def test_msk_public_access():
    assert check_msk_public_access(
        "arn:cluster",
        "PROVISIONED",
        "DISABLED",
    ) is None

    assert check_msk_public_access(
        "arn:cluster",
        "SERVERLESS",
        None,
    ) is None

    result = check_msk_public_access(
        "arn:cluster",
        "PROVISIONED",
        "SERVICE_PROVIDED_EIPS",
    )

    assert result is not None

    finding = build_msk_public_access_finding(result)

    assert finding.rule_id == "CS-AWS-MSK-004"
    assert finding.severity == Severity.CRITICAL


def test_msk_connector_logging():
    assert check_msk_connector_logging(
        "arn:connector",
        True,
    ) is None

    result = check_msk_connector_logging(
        "arn:connector",
        False,
    )

    assert result is not None

    finding = build_msk_connector_logging_finding(result)

    assert finding.rule_id == "CS-AWS-MSK-005"
    assert finding.severity == Severity.MEDIUM


def test_msk_unauthenticated_access():
    assert check_msk_unauthenticated_access(
        "arn:cluster",
        False,
    ) is None

    assert check_msk_unauthenticated_access(
        "arn:cluster",
        None,
    ) is None

    result = check_msk_unauthenticated_access(
        "arn:cluster",
        True,
    )

    assert result is not None

    finding = build_msk_unauthenticated_access_finding(result)

    assert finding.rule_id == "CS-AWS-MSK-006"
    assert finding.severity == Severity.MEDIUM
