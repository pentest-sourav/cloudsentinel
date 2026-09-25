from datetime import datetime, timedelta, timezone

from engine.findings.model import Severity

from engine.rules.aws.acm.expiration import (
    build_acm_expiration_finding,
    check_acm_expiration,
)
from engine.rules.aws.acm.rsa_key_length import (
    build_acm_rsa_key_length_finding,
    check_acm_rsa_key_length,
)
from engine.rules.aws.acm.tagging import (
    build_acm_tagging_finding,
    check_acm_tagging,
)


NOW = datetime.now(timezone.utc)


def test_expiration_passes_outside_default_window():
    assert (
        check_acm_expiration(
            "arn:cert:a",
            "arn:cert:a",
            NOW + timedelta(days=60),
        )
        is None
    )


def test_expiration_fails_inside_default_window():
    result = check_acm_expiration(
        "arn:cert:a",
        "arn:cert:a",
        NOW + timedelta(days=10),
    )

    finding = build_acm_expiration_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ACM-001"
    assert finding.severity == Severity.MEDIUM


def test_expiration_fails_when_already_expired():
    result = check_acm_expiration(
        "arn:cert:a",
        "arn:cert:a",
        NOW - timedelta(days=1),
    )

    assert result is not None


def test_expiration_ignores_missing_expiration():
    assert (
        check_acm_expiration(
            "arn:cert:a",
            "arn:cert:a",
            None,
        )
        is None
    )


def test_rsa_key_length_passes_for_rsa_2048():
    assert (
        check_acm_rsa_key_length(
            "arn:cert:a",
            "arn:cert:a",
            "RSA_2048",
        )
        is None
    )


def test_rsa_key_length_passes_for_rsa_4096():
    assert (
        check_acm_rsa_key_length(
            "arn:cert:a",
            "arn:cert:a",
            "RSA_4096",
        )
        is None
    )


def test_rsa_key_length_fails_for_rsa_1024():
    result = check_acm_rsa_key_length(
        "arn:cert:a",
        "arn:cert:a",
        "RSA_1024",
    )

    finding = build_acm_rsa_key_length_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ACM-002"
    assert finding.severity == Severity.HIGH
    assert finding.evidence["key_length"] == 1024


def test_rsa_key_length_ignores_ec_certificates():
    assert (
        check_acm_rsa_key_length(
            "arn:cert:a",
            "arn:cert:a",
            "EC_prime256v1",
        )
        is None
    )


def test_rsa_key_length_ignores_missing_algorithm():
    assert (
        check_acm_rsa_key_length(
            "arn:cert:a",
            "arn:cert:a",
            None,
        )
        is None
    )


def test_tagging_passes_with_non_system_tag():
    assert (
        check_acm_tagging(
            "arn:cert:a",
            "arn:cert:a",
            [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        )
        is None
    )


def test_tagging_fails_without_tags():
    result = check_acm_tagging(
        "arn:cert:a",
        "arn:cert:a",
        [],
    )

    finding = build_acm_tagging_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ACM-003"
    assert finding.severity == Severity.LOW


def test_tagging_ignores_system_tags():
    result = check_acm_tagging(
        "arn:cert:a",
        "arn:cert:a",
        [
            {
                "Key": "aws:createdBy",
                "Value": "acm",
            }
        ],
    )

    assert result is not None
