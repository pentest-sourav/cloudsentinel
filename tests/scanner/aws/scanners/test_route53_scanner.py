from unittest.mock import Mock

from scanner.aws.scanners.route53 import Route53Scanner


def test_route53_scanner_executes_registered_rules():
    service = Mock()

    service.list_health_checks.return_value = [
        {"Id": "hc-1"},
    ]

    service.list_tags_for_resource.return_value = []

    service.list_hosted_zones.return_value = [
        {
            "Id": "/hostedzone/ZONE1",
            "Name": "example.com.",
            "Config": {
                "PrivateZone": False,
            },
        },
    ]

    service.list_query_logging_configs.return_value = []

    scanner = Route53Scanner(service)

    findings = scanner.scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CS-AWS-ROUTE53-001",
        "CS-AWS-ROUTE53-002",
    }
