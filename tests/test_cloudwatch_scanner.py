from unittest.mock import MagicMock

from scanner.aws.scanners.cloudwatch import (
    CloudWatchScanner,
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

    scanner = CloudWatchScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding.rule_id
        == "CS-AWS-CLOUDWATCH-001"
    )
    assert finding.resource_id == "root-usage"
    assert finding.severity.value == "high"


def test_cloudwatch_scanner_detects_disabled_alarm_actions():
    service = MagicMock()

    service.list_metric_alarms.return_value = [
        {
            "AlarmName": "security-alarm",
            "AlarmArn": "arn:alarm:security-alarm",
            "ActionsEnabled": False,
            "AlarmActions": [
                "arn:sns:security"
            ],
            "StateValue": "OK",
        }
    ]

    service.list_log_groups.return_value = []

    scanner = CloudWatchScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding.rule_id
        == "CS-AWS-CLOUDWATCH-002"
    )
    assert finding.resource_id == "security-alarm"


def test_cloudwatch_scanner_detects_short_log_retention():
    service = MagicMock()

    service.list_metric_alarms.return_value = []

    service.list_log_groups.return_value = [
        {
            "logGroupName": "/aws/application",
            "retentionInDays": 30,
        }
    ]

    scanner = CloudWatchScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding.rule_id
        == "CS-AWS-CLOUDWATCH-003"
    )
    assert (
        finding.resource_id
        == "/aws/application"
    )


def test_cloudwatch_scanner_returns_no_findings_for_compliant_configuration():
    service = MagicMock()

    service.list_metric_alarms.return_value = [
        {
            "AlarmName": "security-alarm",
            "AlarmArn": "arn:alarm:security-alarm",
            "ActionsEnabled": True,
            "AlarmActions": [
                "arn:sns:security"
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

    scanner = CloudWatchScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_cloudwatch_scanner_handles_empty_account():
    service = MagicMock()

    service.list_metric_alarms.return_value = []
    service.list_log_groups.return_value = []

    scanner = CloudWatchScanner(service)

    assert scanner.scan() == []
