from engine.findings.model import Severity
from engine.rules.aws.emr.protection import (
    build_emr_at_rest_encryption_finding,
    build_emr_block_public_access_finding,
    build_emr_in_transit_encryption_finding,
    build_emr_primary_node_public_ip_finding,
    check_emr_at_rest_encryption,
    check_emr_block_public_access,
    check_emr_in_transit_encryption,
    check_emr_primary_node_public_ip,
)


def test_emr_primary_node_public_ip_finding():
    result = check_emr_primary_node_public_ip(
        "j-1",
        True,
    )

    assert result is not None

    finding = build_emr_primary_node_public_ip_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-EMR-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_id == "j-1"


def test_emr_primary_node_without_public_ip_passes():
    assert (
        check_emr_primary_node_public_ip(
            "j-1",
            False,
        )
        is None
    )


def test_emr_primary_node_unknown_is_safe():
    assert (
        check_emr_primary_node_public_ip(
            "j-1",
            None,
        )
        is None
    )


def test_emr_block_public_access_disabled_fails():
    result = check_emr_block_public_access(
        False,
        False,
    )

    assert result is not None
    assert result.reason == "block_public_access_disabled"

    finding = build_emr_block_public_access_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-EMR-002"
    assert finding.severity == Severity.CRITICAL


def test_emr_block_public_access_allows_port_22_exception():
    assert (
        check_emr_block_public_access(
            True,
            False,
        )
        is None
    )


def test_emr_block_public_access_rejects_unsafe_exception():
    result = check_emr_block_public_access(
        True,
        True,
    )

    assert result is not None
    assert result.reason == "unsafe_public_access_exception"


def test_emr_block_public_access_unknown_is_safe():
    assert (
        check_emr_block_public_access(
            None,
            False,
        )
        is None
    )


def test_emr_at_rest_encryption_disabled_fails():
    result = check_emr_at_rest_encryption(
        "secure-emr",
        False,
    )

    assert result is not None

    finding = build_emr_at_rest_encryption_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-EMR-003"
    assert finding.severity == Severity.MEDIUM


def test_emr_at_rest_encryption_enabled_passes():
    assert (
        check_emr_at_rest_encryption(
            "secure-emr",
            True,
        )
        is None
    )


def test_emr_at_rest_encryption_unknown_is_safe():
    assert (
        check_emr_at_rest_encryption(
            "secure-emr",
            None,
        )
        is None
    )


def test_emr_in_transit_encryption_disabled_fails():
    result = check_emr_in_transit_encryption(
        "secure-emr",
        False,
    )

    assert result is not None

    finding = build_emr_in_transit_encryption_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-EMR-004"
    assert finding.severity == Severity.MEDIUM


def test_emr_in_transit_encryption_enabled_passes():
    assert (
        check_emr_in_transit_encryption(
            "secure-emr",
            True,
        )
        is None
    )


def test_emr_in_transit_encryption_unknown_is_safe():
    assert (
        check_emr_in_transit_encryption(
            "secure-emr",
            None,
        )
        is None
    )
