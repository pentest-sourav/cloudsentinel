from engine.rules.registry.route53_registry import (
    ROUTE53_RULES,
)


def test_route53_registry_contains_all_controls():
    rules = ROUTE53_RULES.list_rules()

    assert {
        rule.rule_id
        for rule in rules
    } == {
        "CS-AWS-ROUTE53-001",
        "CS-AWS-ROUTE53-002",
    }


def test_route53_registry_uses_expected_data_sources():
    rules = {
        rule.rule_id: rule
        for rule in ROUTE53_RULES.list_rules()
    }

    assert rules[
        "CS-AWS-ROUTE53-001"
    ].data_source == "route53_health_checks"

    assert rules[
        "CS-AWS-ROUTE53-002"
    ].data_source == "route53_hosted_zones"
