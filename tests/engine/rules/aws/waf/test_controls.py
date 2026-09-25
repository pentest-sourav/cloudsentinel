from engine.findings.model import Severity
from engine.rules.aws.waf.rule_group_metrics import (
    build_waf_rule_group_metrics_finding,
    check_waf_rule_group_metrics,
)
from engine.rules.aws.waf.web_acl_logging import (
    build_waf_web_acl_logging_finding,
    check_waf_web_acl_logging,
)
from engine.rules.aws.waf.web_acl_rules import (
    build_waf_web_acl_rules_finding,
    check_waf_web_acl_rules,
)


def test_waf_web_acl_rules_passes_when_rules_exist():
    assert (
        check_waf_web_acl_rules(
            resource_id="acl-1",
            resource_arn="arn:acl",
            name="orders",
            scope="REGIONAL",
            rule_count=1,
        )
        is None
    )


def test_waf_web_acl_rules_fails_when_empty():
    result = check_waf_web_acl_rules(
        resource_id="acl-1",
        resource_arn="arn:acl",
        name="orders",
        scope="REGIONAL",
        rule_count=0,
    )

    finding = build_waf_web_acl_rules_finding(result)

    assert finding.rule_id == "CS-AWS-WAF-010"
    assert finding.severity == Severity.MEDIUM


def test_waf_web_acl_logging_passes_when_configured():
    assert (
        check_waf_web_acl_logging(
            resource_id="acl-1",
            resource_arn="arn:acl",
            name="orders",
            scope="REGIONAL",
            logging_configuration={
                "ResourceArn": "arn:logs",
            },
        )
        is None
    )


def test_waf_web_acl_logging_fails_when_missing():
    result = check_waf_web_acl_logging(
        resource_id="acl-1",
        resource_arn="arn:acl",
        name="orders",
        scope="REGIONAL",
        logging_configuration={},
    )

    finding = build_waf_web_acl_logging_finding(result)

    assert finding.rule_id == "CS-AWS-WAF-011"
    assert finding.severity == Severity.LOW


def test_waf_rule_group_metrics_passes_when_enabled():
    assert (
        check_waf_rule_group_metrics(
            resource_id="group-1",
            resource_arn="arn:group",
            name="managed",
            scope="REGIONAL",
            cloudwatch_metrics_enabled=True,
        )
        is None
    )


def test_waf_rule_group_metrics_fails_when_disabled():
    result = check_waf_rule_group_metrics(
        resource_id="group-1",
        resource_arn="arn:group",
        name="managed",
        scope="REGIONAL",
        cloudwatch_metrics_enabled=False,
    )

    finding = build_waf_rule_group_metrics_finding(result)

    assert finding.rule_id == "CS-AWS-WAF-012"
    assert finding.severity == Severity.MEDIUM
