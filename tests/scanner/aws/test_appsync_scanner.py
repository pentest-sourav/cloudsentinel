from unittest.mock import Mock

from scanner.aws.scanners.appsync import (
    AppSyncScanner,
)


def test_appsync_scanner_executes_registered_rules():
    service = Mock()

    service.list_graphql_apis.return_value = [
        {
            "apiId": "api-1",
            "authenticationType": "API_KEY",
            "additionalAuthenticationProviders": [],
            "logConfig": {
                "fieldLogLevel": "NONE",
            },
            "tags": {},
        },
    ]

    findings = AppSyncScanner(service).scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CS-AWS-APPSYNC-002",
        "CS-AWS-APPSYNC-004",
        "CS-AWS-APPSYNC-005",
    }
