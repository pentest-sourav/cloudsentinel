from unittest.mock import Mock

from engine.rules.aws.cloudtrail.handlers import (
    CLOUDTRAIL_DATA_SOURCE_HANDLERS,
    collect_cloudtrail_account,
    collect_cloudtrail_trails,
)

def test_collect_cloudtrail_trails_enriches_logging_status():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
            "home_region": "eu-north-1",
            "s3_bucket_name": "cloudtrail-logs",
            "is_multi_region_trail": True,
            "enable_log_file_validation": True,
        }
    ]

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {}

    trails = collect_cloudtrail_trails(collector)

    assert len(trails) == 1
    assert trails[0]["trail_arn"] == trail_arn
    assert trails[0]["is_logging"] is True

    collector.collect_trails.assert_called_once()
    collector.get_trail_status.assert_called_once_with(
        trail_arn
    )


def test_collect_cloudtrail_trails_handles_not_logging():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_status.return_value = {
        "IsLogging": False,
    }

    collector.get_event_selectors.return_value = {}

    trails = collect_cloudtrail_trails(collector)

    assert len(trails) == 1
    assert trails[0]["is_logging"] is False


def test_collect_cloudtrail_trails_defaults_missing_logging_status_to_false():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_status.return_value = {}
    collector.get_event_selectors.return_value = {}

    trails = collect_cloudtrail_trails(collector)

    assert len(trails) == 1
    assert trails[0]["is_logging"] is False


def test_collect_cloudtrail_trails_handles_multiple_trails():
    collector = Mock()

    first_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/first"
    )

    second_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/second"
    )

    collector.collect_trails.return_value = [
        {
            "name": "first",
            "trail_arn": first_arn,
        },
        {
            "name": "second",
            "trail_arn": second_arn,
        },
    ]

    collector.get_trail_status.side_effect = [
        {"IsLogging": True},
        {"IsLogging": False},
    ]

    collector.get_event_selectors.return_value = {}

    trails = collect_cloudtrail_trails(collector)

    assert len(trails) == 2
    assert trails[0]["is_logging"] is True
    assert trails[1]["is_logging"] is False

    assert collector.get_trail_status.call_count == 2

def test_collect_cloudtrail_account_returns_account_data():
    collector = Mock()

    collector.collect_account.return_value = {
        "trail_count": 0,
    }

    result = collect_cloudtrail_account(collector)

    assert result == {
        "trail_count": 0,
    }

    collector.collect_account.assert_called_once()


def test_cloudtrail_account_handler_is_registered():
    assert "cloudtrail_account" in CLOUDTRAIL_DATA_SOURCE_HANDLERS
    assert (
        CLOUDTRAIL_DATA_SOURCE_HANDLERS["cloudtrail_account"]
        is collect_cloudtrail_account
    )


def test_collect_cloudtrail_trails_detects_basic_management_events():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {
        "EventSelectors": [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
            }
        ]
    }

    trails = collect_cloudtrail_trails(collector)

    assert trails[0]["includes_management_events"] is True


def test_collect_cloudtrail_trails_detects_disabled_basic_management_events():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {
        "EventSelectors": [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": False,
            }
        ]
    }

    trails = collect_cloudtrail_trails(collector)

    assert trails[0]["includes_management_events"] is False


def test_collect_cloudtrail_trails_detects_advanced_management_events():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {
        "AdvancedEventSelectors": [
            {
                "FieldSelectors": [
                    {
                        "Field": "eventCategory",
                        "Equals": ["Management"],
                    }
                ]
            }
        ]
    }

    trails = collect_cloudtrail_trails(collector)

    assert trails[0]["includes_management_events"] is True


def test_collect_cloudtrail_trails_ignores_advanced_non_management_events():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {
        "AdvancedEventSelectors": [
            {
                "FieldSelectors": [
                    {
                        "Field": "eventCategory",
                        "Equals": ["Data"],
                    }
                ]
            }
        ]
    }

    trails = collect_cloudtrail_trails(collector)

    assert trails[0]["includes_management_events"] is False


def test_collect_cloudtrail_trails_defaults_missing_management_events_to_false():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {}

    trails = collect_cloudtrail_trails(collector)

    assert trails[0]["includes_management_events"] is False

def test_collect_cloudtrail_trails_normalizes_cloudwatch_logs_configuration():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
            "cloudwatch_logs_log_group_arn": (
                "arn:aws:logs:eu-north-1:"
                "123456789012:log-group:/aws/cloudtrail/main"
            ),
            "cloudwatch_logs_role_arn": (
                "arn:aws:iam::123456789012:"
                "role/CloudTrail_CloudWatchLogs_Role"
            ),
        }
    ]

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {}

    trails = collect_cloudtrail_trails(collector)

    assert trails[0]["cloudwatch_logs_log_group_arn"] == (
        "arn:aws:logs:eu-north-1:"
        "123456789012:log-group:/aws/cloudtrail/main"
    )

    assert trails[0]["cloudwatch_logs_role_arn"] == (
        "arn:aws:iam::123456789012:"
        "role/CloudTrail_CloudWatchLogs_Role"
    )


def test_collect_cloudtrail_trails_normalizes_tags():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_tags.return_value = {
        trail_arn: [
            {
                "Key": "Environment",
                "Value": "Production",
            }
        ]
    }

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {}

    trails = collect_cloudtrail_trails(collector)

    assert trails[0]["tags"] == [
        {
            "Key": "Environment",
            "Value": "Production",
        }
    ]

    collector.get_trail_tags.assert_called_once_with(
        [trail_arn],
    )


def test_collect_cloudtrail_trails_normalizes_tags():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_tags.return_value = {
        trail_arn: [
            {
                "Key": "Environment",
                "Value": "Production",
            }
        ]
    }

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {}

    trails = collect_cloudtrail_trails(collector)

    assert trails[0]["tags"] == [
        {
            "Key": "Environment",
            "Value": "Production",
        }
    ]

    collector.get_trail_tags.assert_called_once_with(
        [trail_arn],
    )


def test_collect_cloudtrail_trails_normalizes_tags():
    collector = Mock()

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    collector.collect_trails.return_value = [
        {
            "name": "cloudtrail-main",
            "trail_arn": trail_arn,
        }
    ]

    collector.get_trail_tags.return_value = {
        trail_arn: [
            {
                "Key": "Environment",
                "Value": "Production",
            }
        ]
    }

    collector.get_trail_status.return_value = {
        "IsLogging": True,
    }

    collector.get_event_selectors.return_value = {}

    trails = collect_cloudtrail_trails(collector)

    assert trails[0]["tags"] == [
        {
            "Key": "Environment",
            "Value": "Production",
        }
    ]

    collector.get_trail_tags.assert_called_once_with(
        [trail_arn],
    )
