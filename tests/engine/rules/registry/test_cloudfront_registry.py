from engine.rules.registry.cloudfront_registry import (
    CLOUDFRONT_RULES,
)


def test_cloudfront_12_rule_is_registered():
    rule = CLOUDFRONT_RULES.get_rule(
        "CS-AWS-CLOUDFRONT-015"
    )

    assert rule.name == (
        "cloudfront_nonexistent_s3_origins"
    )
    assert rule.check_arguments == [
        "resource_id",
        "resource_type",
        "s3_origins",
    ]
