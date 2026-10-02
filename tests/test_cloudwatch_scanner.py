from unittest.mock import MagicMock, patch

from scanner.aws.scanners.cloudwatch import CloudWatchScanner


def _scanner_with_no_cloudtrail(service):
    service.session = MagicMock()

    cloudtrail = MagicMock()
    cloudtrail.describe_trails.return_value = []

    return patch(
        "scanner.aws.collectors.cloudwatch.CloudTrailService",
        return_value=cloudtrail,
    )


def test_cloudwatch_scanner_detects_alarm_without_actions():
    service = MagicMock()

    service.list_metric_alarms.return_value = [
        {
            "AlarmName": "root-usage",
            "AlarmArn": "arn:alarm:root-usage",
            "ActionsEnabled": True,
            "AlarmActions": [],
            "StateValue": "OK",
        }
    ]

    service.list_log_groups.return_value = []

    with _scanner_with_no_cloudtrail(service):
        findings = CloudWatchScanner(service).scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-CLOUDWATCH-001"


def test_cloudwatch_scanner_detects_disabled_alarm_actions():
    service = MagicMock()

    service.list_metric_alarms.return_value = [
        {
            "AlarmName": "security-alarm",
            "AlarmArn": "arn:alarm:security-alarm",
            "ActionsEnabled": False,
            "AlarmActions": [
                "arn:sns:security",
            ],
            "StateValue": "OK",
        }
    ]

    service.list_log_groups.return_value = []

    with _scanner_with_no_cloudtrail(service):
        findings = CloudWatchScanner(service).scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-CLOUDWATCH-002"


def test_cloudwatch_scanner_detects_short_log_retention():
    service = MagicMock()

    service.list_metric_alarms.return_value = []

    service.list_log_groups.return_value = [
        {
            "logGroupName": "/aws/application",
            "retentionInDays": 30,
        }
    ]

    with _scanner_with_no_cloudtrail(service):
        findings = CloudWatchScanner(service).scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-CLOUDWATCH-003"


def test_cloudwatch_scanner_returns_no_findings_for_compliant_configuration():
    service = MagicMock()

    service.list_metric_alarms.return_value = [
        {
            "AlarmName": "security-alarm",
            "AlarmArn": "arn:alarm:security-alarm",
            "ActionsEnabled": True,
            "AlarmActions": [
                "arn:sns:security",
            ],
            "StateValue": "OK",
        }
    ]

    service.list_log_groups.return_value = [
        {
            "logGroupName": "/aws/application",
            "retentionInDays": 365,
        }
    ]

    with _scanner_with_no_cloudtrail(service):
        findings = CloudWatchScanner(service).scan()

    assert findings == []


def test_cloudwatch_scanner_handles_empty_account():
    service = MagicMock()

    service.list_metric_alarms.return_value = []
    service.list_log_groups.return_value = []

    with _scanner_with_no_cloudtrail(service):
        findings = CloudWatchScanner(service).scan()

    assert findings == []


def test_cloudwatch_scanner_executes_log_metric_controls():
    service = MagicMock()

    service.list_metric_alarms.return_value = []
    service.list_log_groups.return_value = []
    service.session = MagicMock()

    cloudtrail = MagicMock()
    cloudtrail.describe_trails.return_value = [
        {
            "Name": "security-trail",
            "TrailARN": (
                "arn:aws:cloudtrail:ap-south-1:"
                "123456789012:trail/security-trail"
            ),
            "CloudWatchLogsLogGroupArn": (
                "arn:aws:logs:ap-south-1:"
                "123456789012:log-group:/aws/cloudtrail:*"
            ),
        }
    ]

    with patch(
        "scanner.aws.collectors.cloudwatch.CloudTrailService",
        return_value=cloudtrail,
    ):
        findings = CloudWatchScanner(service).scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        f"CS-AWS-CLOUDWATCH-{index:03d}"
        for index in range(4, 18)
    }
