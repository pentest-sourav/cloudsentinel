from engine.rules.registry.cloudfront_handlers import (
    CLOUDFRONT_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.cloudfront_registry import (
    CLOUDFRONT_RULES,
)


def test_cloudfront_registry_contains_expected_rules():
    rule_ids = [
        rule.rule_id
        for rule in CLOUDFRONT_RULES.rules
    ]

    assert rule_ids == [
        "CS-AWS-CLOUDFRONT-001",
        "CS-AWS-CLOUDFRONT-002",
        "CS-AWS-CLOUDFRONT-003",
        "CS-AWS-CLOUDFRONT-004",
        "CS-AWS-CLOUDFRONT-005",
    ]


def test_cloudfront_handlers_cover_all_data_sources():
    assert set(
        CLOUDFRONT_DATA_SOURCE_HANDLERS
    ) == {
        "cloudfront_distributions",
    }
