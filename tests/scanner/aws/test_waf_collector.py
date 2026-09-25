from unittest.mock import Mock

from scanner.aws.collectors.waf import WAFDataCollector


def make_service():
    service = Mock()
    service.list_web_acls.return_value = []
    service.list_rule_groups.return_value = []
    return service


def test_collect_web_acls_normalizes_regional_and_cloudfront():
    service = make_service()

    service.list_web_acls.side_effect = [
        [
            {
                "Name": "regional-acl",
                "Id": "regional-1",
                "ARN": "arn:regional",
            }
        ],
        [
            {
                "Name": "cloudfront-acl",
                "Id": "global-1",
                "ARN": "arn:cloudfront",
            }
        ],
    ]

    service.get_web_acl.side_effect = [
        {
            "Rules": [
                {
                    "Name": "block-bad",
                }
            ]
        },
        {
            "Rules": [],
        },
    ]

    service.get_logging_configuration.side_effect = [
        {
            "ResourceArn": "arn:logs:regional",
        },
        {},
    ]

    collector = WAFDataCollector(service)

    result = collector.collect_web_acls()

    assert len(result) == 2

    assert result[0]["scope"] == "REGIONAL"
    assert result[0]["rule_count"] == 1
    assert result[0]["logging_configuration"]

    assert result[1]["scope"] == "CLOUDFRONT"
    assert result[1]["rule_count"] == 0
    assert result[1]["logging_configuration"] == {}


def test_collect_rule_groups_normalizes_visibility_config():
    service = make_service()

    service.list_rule_groups.side_effect = [
        [
            {
                "Name": "regional-group",
                "Id": "group-1",
                "ARN": "arn:regional-group",
            }
        ],
        [
            {
                "Name": "cloudfront-group",
                "Id": "group-2",
                "ARN": "arn:cloudfront-group",
            }
        ],
    ]

    service.get_rule_group.side_effect = [
        {
            "VisibilityConfig": {
                "CloudWatchMetricsEnabled": True,
                "MetricName": "regional",
            }
        },
        {
            "VisibilityConfig": {
                "CloudWatchMetricsEnabled": False,
                "MetricName": "cloudfront",
            }
        },
    ]

    collector = WAFDataCollector(service)

    result = collector.collect_rule_groups()

    assert len(result) == 2

    assert result[0]["scope"] == "REGIONAL"
    assert result[0]["cloudwatch_metrics_enabled"] is True
    assert result[0]["metric_name"] == "regional"

    assert result[1]["scope"] == "CLOUDFRONT"
    assert result[1]["cloudwatch_metrics_enabled"] is False
