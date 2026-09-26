from engine.findings.model import Severity
from engine.rules.aws.elb.protection import (
    build_elb_deletion_protection_finding,
    build_elb_desync_mitigation_finding,
    build_elb_health_check_protocol_finding,
    build_elb_http_to_https_finding,
    build_elb_invalid_headers_finding,
    build_elb_listener_protocol_finding,
    build_elb_logging_finding,
    build_elb_multi_az_finding,
    build_elb_target_transport_finding,
    check_elb_deletion_protection,
    check_elb_desync_mitigation,
    check_elb_health_check_protocol,
    check_elb_http_to_https,
    check_elb_invalid_headers,
    check_elb_listener_protocol,
    check_elb_logging,
    check_elb_multi_az,
    check_elb_target_transport,
)


def test_http_listener_without_redirect_fails():
    result = check_elb_http_to_https(
        "arn:lb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:listener",
                "protocol": "HTTP",
                "port": 80,
                "default_actions": [
                    {"Type": "forward"},
                ],
            },
        ],
    )

    finding = build_elb_http_to_https_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-001"
    assert finding.severity == Severity.MEDIUM


def test_http_redirect_passes():
    assert check_elb_http_to_https(
        "arn:lb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:listener",
                "protocol": "HTTP",
                "port": 80,
                "default_actions": [
                    {
                        "Type": "redirect",
                        "RedirectConfig": {
                            "Protocol": "HTTPS",
                        },
                    },
                ],
            },
        ],
    ) is None


def test_logging_disabled_fails():
    result = check_elb_logging(
        "arn:lb",
        "application_load_balancer",
        False,
    )

    finding = build_elb_logging_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-002"


def test_deletion_protection_disabled_fails():
    result = check_elb_deletion_protection(
        "arn:lb",
        "network_load_balancer",
        False,
    )

    finding = build_elb_deletion_protection_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-003"


def test_invalid_headers_disabled_fails():
    result = check_elb_invalid_headers(
        "arn:lb",
        "application_load_balancer",
        False,
    )

    finding = build_elb_invalid_headers_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-004"


def test_desync_mode_monitor_fails():
    result = check_elb_desync_mitigation(
        "arn:lb",
        "application_load_balancer",
        "monitor",
    )

    finding = build_elb_desync_mitigation_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-005"


def test_two_availability_zones_pass():
    assert check_elb_multi_az(
        "arn:lb",
        "application_load_balancer",
        ["us-east-1a", "us-east-1b"],
    ) is None


def test_one_availability_zone_fails():
    result = check_elb_multi_az(
        "arn:lb",
        "application_load_balancer",
        ["us-east-1a"],
    )

    finding = build_elb_multi_az_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-006"


def test_alb_http_listener_fails():
    result = check_elb_listener_protocol(
        "arn:lb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:listener",
                "protocol": "HTTP",
                "port": 80,
            },
        ],
    )

    finding = build_elb_listener_protocol_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-007"


def test_alb_https_listener_passes():
    assert check_elb_listener_protocol(
        "arn:lb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:listener",
                "protocol": "HTTPS",
                "port": 443,
            },
        ],
    ) is None


def test_unencrypted_health_check_fails():
    result = check_elb_health_check_protocol(
        "arn:lb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:tg",
                "health_check_protocol": "HTTP",
            },
        ],
    )

    finding = build_elb_health_check_protocol_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ELB-008"


def test_encrypted_health_check_passes():
    assert check_elb_health_check_protocol(
        "arn:lb",
        "network_load_balancer",
        [
            {
                "resource_id": "arn:tg",
                "health_check_protocol": "TLS",
            },
        ],
    ) is None


def test_unencrypted_target_transport_fails():
    result = check_elb_target_transport(
        "arn:lb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:tg",
                "protocol": "HTTP",
            },
        ],
    )

    finding = build_elb_target_transport_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-009"


def test_encrypted_target_transport_passes():
    assert check_elb_target_transport(
        "arn:lb",
        "network_load_balancer",
        [
            {
                "resource_id": "arn:tg",
                "protocol": "TLS",
            },
        ],
    ) is None
