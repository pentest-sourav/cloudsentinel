from unittest.mock import Mock

from scanner.aws.collectors.cloudtrail import CloudTrailDataCollector


def create_collector():
    service = Mock()
    collector = CloudTrailDataCollector(service)
    return collector, service


def test_collect_trails_normalizes_data():
    collector, service = create_collector()

    service.describe_trails.return_value = [
        {
            "Name": "cloudtrail-main",
            "TrailARN": (
                "arn:aws:cloudtrail:eu-north-1:"
                "123456789012:trail/cloudtrail-main"
            ),
            "HomeRegion": "eu-north-1",
            "S3BucketName": "cloudtrail-logs",
            "S3KeyPrefix": "aws/",
            "IncludeGlobalServiceEvents": True,
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
            "IsOrganizationTrail": False,
            "InsightSelectors": [
                {"InsightType": "ApiCallRateInsight"}
            ],
            "EventSelectors": [
                {"ReadWriteType": "All"}
            ],
        }
    ]

    trails = collector.collect_trails()

    assert len(trails) == 1

    trail = trails[0]

    assert trail["name"] == "cloudtrail-main"
    assert trail["trail_arn"].endswith(
        ":trail/cloudtrail-main"
    )
    assert trail["home_region"] == "eu-north-1"
    assert trail["s3_bucket_name"] == "cloudtrail-logs"
    assert trail["s3_key_prefix"] == "aws/"
    assert trail["include_global_service_events"] is True
    assert trail["is_multi_region_trail"] is True
    assert trail["enable_log_file_validation"] is True
    assert trail["is_organization_trail"] is False
    assert trail["has_insight_selectors"] is True
    assert trail["has_event_selectors"] is True


def test_collect_trails_skips_missing_trail_arn():
    collector, service = create_collector()

    service.describe_trails.return_value = [
        {
            "Name": "invalid-trail",
            "HomeRegion": "eu-north-1",
        },
        {
            "Name": "valid-trail",
            "TrailARN": (
                "arn:aws:cloudtrail:eu-north-1:"
                "123456789012:trail/valid-trail"
            ),
        },
    ]

    trails = collector.collect_trails()

    assert len(trails) == 1
    assert trails[0]["name"] == "valid-trail"


def test_collect_trails_uses_cache():
    collector, service = create_collector()

    service.describe_trails.return_value = [
        {
            "Name": "cloudtrail-main",
            "TrailARN": (
                "arn:aws:cloudtrail:eu-north-1:"
                "123456789012:trail/cloudtrail-main"
            ),
        }
    ]

    first_result = collector.collect_trails()
    second_result = collector.collect_trails()

    assert first_result == second_result
    service.describe_trails.assert_called_once()


def test_get_trail_status_returns_status():
    collector, service = create_collector()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    service.get_trail_status.return_value = {
        "IsLogging": True,
        "LatestDeliveryTime": "2026-09-19T10:00:00Z",
    }

    status = collector.get_trail_status(trail_arn)

    assert status["IsLogging"] is True

    service.get_trail_status.assert_called_once_with(
        trail_arn
    )


def test_get_trail_status_uses_cache():
    collector, service = create_collector()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    service.get_trail_status.return_value = {
        "IsLogging": True,
    }

    first_result = collector.get_trail_status(trail_arn)
    second_result = collector.get_trail_status(trail_arn)

    assert first_result == second_result
    service.get_trail_status.assert_called_once_with(
        trail_arn
    )

def test_collect_account_returns_trail_count():
    service = Mock()

    service.describe_trails.return_value = [
        {
            "TrailARN": "arn:aws:cloudtrail:eu-north-1:123:trail/first"
        },
        {
            "TrailARN": "arn:aws:cloudtrail:eu-north-1:123:trail/second"
        },
    ]

    collector = CloudTrailDataCollector(service)

    result = collector.collect_account()

    assert result == {
        "trail_count": 2,
    }

    service.describe_trails.assert_called_once()


def test_collect_account_returns_zero_when_no_trails_exist():
    service = Mock()

    service.describe_trails.return_value = []

    collector = CloudTrailDataCollector(service)

    result = collector.collect_account()

    assert result == {
        "trail_count": 0,
    }


def test_collect_account_ignores_trails_without_arn():
    service = Mock()

    service.describe_trails.return_value = [
        {
            "Name": "invalid-trail",
        },
        {
            "TrailARN": "arn:aws:cloudtrail:eu-north-1:123:trail/valid"
        },
    ]

    collector = CloudTrailDataCollector(service)

    result = collector.collect_account()

    assert result == {
        "trail_count": 1,
    }
