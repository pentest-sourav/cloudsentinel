from engine.findings.model import Severity
from engine.rules.aws.elb.protection import (
    CLASSIC_STRONG_SSL_POLICY,
    RECOMMENDED_V2_SSL_POLICIES,
    build_classic_acm_certificate_finding,
    build_classic_connection_draining_finding,
    build_classic_cross_zone_finding,
    build_classic_desync_finding,
    build_classic_listener_protocol_finding,
    build_classic_multi_az_finding,
    build_classic_security_policy_finding,
    build_elb_health_check_protocol_finding,
    build_elb_recommended_security_policy_finding,
    build_elb_target_transport_finding,
    build_elb_waf_finding,
    check_classic_acm_certificate,
    check_classic_connection_draining,
    check_classic_cross_zone,
    check_classic_desync,
    check_classic_listener_protocol,
    check_classic_multi_az,
    check_classic_security_policy,
    check_elb_health_check_protocol,
    check_elb_recommended_security_policy,
    check_elb_target_transport,
    check_elb_waf,
)


def classic(
    listeners=None,
    **kwargs,
):
    return {
        "resource_id": "classic-lb",
        "resource_type": "classic_load_balancer",
        "listeners": listeners or [],
        **kwargs,
    }


def test_classic_non_acm_certificate_fails():
    result = check_classic_acm_certificate(
        "classic-lb",
        "classic_load_balancer",
        [
            {
                "resource_id": "classic-listener:443",
                "protocol": "HTTPS",
                "ssl_certificate_id": (
                    "arn:aws:iam::123:server-certificate/test"
                ),
            }
        ],
    )

    finding = build_classic_acm_certificate_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-010"
    assert finding.severity == Severity.MEDIUM


def test_classic_acm_certificate_passes():
    assert check_classic_acm_certificate(
        "classic-lb",
        "classic_load_balancer",
        [
            {
                "resource_id": "classic-listener:443",
                "protocol": "HTTPS",
                "ssl_certificate_id": (
                    "arn:aws:acm:us-east-1:123:"
                    "certificate/test"
                ),
            }
        ],
    ) is None


def test_classic_http_listener_fails():
    result = check_classic_listener_protocol(
        "classic-lb",
        "classic_load_balancer",
        [
            {
                "resource_id": "classic-listener:80",
                "protocol": "HTTP",
            }
        ],
    )

    finding = build_classic_listener_protocol_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-011"


def test_classic_https_listener_passes():
    assert check_classic_listener_protocol(
        "classic-lb",
        "classic_load_balancer",
        [
            {
                "resource_id": "classic-listener:443",
                "protocol": "HTTPS",
            }
        ],
    ) is None


def test_classic_connection_draining_disabled_fails():
    result = check_classic_connection_draining(
        "classic-lb",
        "classic_load_balancer",
        False,
    )

    finding = build_classic_connection_draining_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-012"
    assert finding.severity == Severity.LOW


def test_classic_connection_draining_enabled_passes():
    assert check_classic_connection_draining(
        "classic-lb",
        "classic_load_balancer",
        True,
    ) is None


def test_classic_security_policy_fails():
    result = check_classic_security_policy(
        "classic-lb",
        "classic_load_balancer",
        [
            {
                "resource_id": "classic-listener:443",
                "protocol": "HTTPS",
                "policy_names": [
                    "ELBSecurityPolicy-Old"
                ],
            }
        ],
    )

    finding = build_classic_security_policy_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-013"


def test_classic_security_policy_passes():
    assert check_classic_security_policy(
        "classic-lb",
        "classic_load_balancer",
        [
            {
                "resource_id": "classic-listener:443",
                "protocol": "HTTPS",
                "policy_names": [
                    CLASSIC_STRONG_SSL_POLICY
                ],
            }
        ],
    ) is None


def test_classic_cross_zone_disabled_fails():
    result = check_classic_cross_zone(
        "classic-lb",
        "classic_load_balancer",
        False,
    )

    finding = build_classic_cross_zone_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-014"


def test_classic_cross_zone_enabled_passes():
    assert check_classic_cross_zone(
        "classic-lb",
        "classic_load_balancer",
        True,
    ) is None


def test_classic_single_az_fails():
    result = check_classic_multi_az(
        "classic-lb",
        "classic_load_balancer",
        ["us-east-1a"],
    )

    finding = build_classic_multi_az_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-015"


def test_classic_two_az_passes():
    assert check_classic_multi_az(
        "classic-lb",
        "classic_load_balancer",
        ["us-east-1a", "us-east-1b"],
    ) is None


def test_classic_desync_monitor_fails():
    result = check_classic_desync(
        "classic-lb",
        "classic_load_balancer",
        "monitor",
    )

    finding = build_classic_desync_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-016"


def test_classic_desync_strictest_passes():
    assert check_classic_desync(
        "classic-lb",
        "classic_load_balancer",
        "strictest",
    ) is None


def test_alb_without_waf_fails():
    result = check_elb_waf(
        "arn:alb",
        "application_load_balancer",
        None,
    )

    finding = build_elb_waf_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-017"


def test_alb_with_waf_passes():
    assert check_elb_waf(
        "arn:alb",
        "application_load_balancer",
        "arn:aws:wafv2:region:123:regional/webacl/test/id",
    ) is None


def test_recommended_alb_policy_fails():
    result = check_elb_recommended_security_policy(
        "arn:alb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:listener",
                "protocol": "HTTPS",
                "ssl_policy": "ELBSecurityPolicy-Old",
            }
        ],
    )

    finding = build_elb_recommended_security_policy_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-ELB-018"


def test_recommended_alb_policy_passes():
    policy = sorted(
        RECOMMENDED_V2_SSL_POLICIES
    )[0]

    assert check_elb_recommended_security_policy(
        "arn:alb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:listener",
                "protocol": "HTTPS",
                "ssl_policy": policy,
            }
        ],
    ) is None


def test_health_check_requires_https():
    result = check_elb_health_check_protocol(
        "arn:alb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:tg",
                "target_type": "instance",
                "health_check_protocol": "HTTP",
            }
        ],
    )

    finding = build_elb_health_check_protocol_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-008"


def test_lambda_health_check_is_not_applicable():
    assert check_elb_health_check_protocol(
        "arn:alb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:tg",
                "target_type": "lambda",
                "health_check_protocol": "HTTP",
            }
        ],
    ) is None


def test_target_transport_accepts_quic():
    assert check_elb_target_transport(
        "arn:alb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:tg",
                "target_type": "ip",
                "protocol": "QUIC",
            }
        ],
    ) is None


def test_target_transport_skips_geneve():
    assert check_elb_target_transport(
        "arn:nlb",
        "network_load_balancer",
        [
            {
                "resource_id": "arn:tg",
                "target_type": "instance",
                "protocol": "GENEVE",
            }
        ],
    ) is None


def test_target_transport_http_fails():
    result = check_elb_target_transport(
        "arn:alb",
        "application_load_balancer",
        [
            {
                "resource_id": "arn:tg",
                "target_type": "instance",
                "protocol": "HTTP",
            }
        ],
    )

    finding = build_elb_target_transport_finding(result)

    assert finding.rule_id == "CS-AWS-ELB-009"
