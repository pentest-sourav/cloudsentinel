from engine.findings.model import Severity

from engine.rules.aws.route53.protection import (
    build_route53_health_check_tagging_finding,
    build_route53_query_logging_finding,
    check_route53_health_check_tagging,
    check_route53_query_logging,
)


def test_health_check_tagging_passes_with_non_system_tag():
    assert (
        check_route53_health_check_tagging(
            resource_id="hc-1",
            resource_type="route53_health_check",
            tags=[
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
        )
        is None
    )


def test_health_check_tagging_fails_without_tags():
    result = check_route53_health_check_tagging(
        resource_id="hc-1",
        resource_type="route53_health_check",
        tags=[],
    )

    assert result is not None
    assert result.resource_id == "hc-1"


def test_query_logging_passes_when_enabled():
    assert (
        check_route53_query_logging(
            resource_id="ZONE1",
            private_zone=False,
            query_logging_enabled=True,
        )
        is None
    )


def test_query_logging_fails_when_disabled():
    result = check_route53_query_logging(
        resource_id="ZONE1",
        private_zone=False,
        query_logging_enabled=False,
    )

    assert result is not None
    assert result.resource_id == "ZONE1"


def test_query_logging_skips_private_zone():
    assert (
        check_route53_query_logging(
            resource_id="ZONE1",
            private_zone=True,
            query_logging_enabled=False,
        )
        is None
    )


def test_health_check_finding():
    result = check_route53_health_check_tagging(
        resource_id="hc-1",
        resource_type="route53_health_check",
        tags=[],
    )

    finding = build_route53_health_check_tagging_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ROUTE53-001"
    assert finding.severity == Severity.LOW
    assert finding.compliance == [
        "AWS Security Hub Route53.1",
    ]


def test_query_logging_finding():
    result = check_route53_query_logging(
        resource_id="ZONE1",
        private_zone=False,
        query_logging_enabled=False,
    )

    finding = build_route53_query_logging_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ROUTE53-002"
    assert finding.severity == Severity.MEDIUM
    assert finding.compliance == [
        "AWS Security Hub Route53.2",
    ]
