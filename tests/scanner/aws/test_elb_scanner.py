from unittest.mock import Mock

from scanner.aws.scanners.elb import ELBScanner


def test_elb_scanner_executes_registered_rules():
    service = Mock()

    service.list_load_balancers.return_value = [
        {
            "LoadBalancerArn": "arn:lb:insecure",
            "LoadBalancerName": "insecure",
            "Type": "application",
            "Scheme": "internet-facing",
            "AvailabilityZones": [
                {"ZoneName": "us-east-1a"},
            ],
        },
    ]

    service.list_listeners.return_value = [
        {
            "ListenerArn": "arn:listener:80",
            "Protocol": "HTTP",
            "Port": 80,
            "DefaultActions": [
                {
                    "Type": "forward",
                },
            ],
        },
    ]

    service.list_target_groups.return_value = [
        {
            "TargetGroupArn": "arn:tg",
            "Protocol": "HTTP",
            "Port": 80,
            "HealthCheckProtocol": "HTTP",
        },
    ]

    service.describe_load_balancer_attributes.return_value = [
        {
            "Key": "deletion_protection.enabled",
            "Value": "false",
        },
        {
            "Key": "access_logs.s3.enabled",
            "Value": "false",
        },
        {
            "Key": (
                "routing.http."
                "drop_invalid_header_fields.enabled"
            ),
            "Value": "false",
        },
        {
            "Key": (
                "routing.http."
                "desync_mitigation_mode"
            ),
            "Value": "monitor",
        },
    ]

    findings = ELBScanner(service).scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CS-AWS-ELB-001",
        "CS-AWS-ELB-002",
        "CS-AWS-ELB-003",
        "CS-AWS-ELB-004",
        "CS-AWS-ELB-005",
        "CS-AWS-ELB-006",
        "CS-AWS-ELB-007",
        "CS-AWS-ELB-008",
        "CS-AWS-ELB-009",
    }
