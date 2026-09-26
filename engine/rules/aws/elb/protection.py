from dataclasses import dataclass

from engine.findings.model import Finding, Severity


CLASSIC_STRONG_SSL_POLICY = (
    "ELBSecurityPolicy-TLS-1-2-2017-01"
)

RECOMMENDED_V2_SSL_POLICIES = {
    "ELBSecurityPolicy-TLS13-1-3-2021-06",
    "ELBSecurityPolicy-TLS13-1-3-FIPS-2023-04",
    "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-2023-04",
    "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
    "ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
}


@dataclass(frozen=True)
class ELBResult:
    resource_id: str
    resource_type: str
    details: dict


def _result(
    resource_id: str,
    resource_type: str,
    details: dict,
) -> ELBResult | None:
    if not resource_id:
        return None

    return ELBResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details=details,
    )


def check_elb_http_to_https(
    resource_id: str,
    resource_type: str,
    listeners: list[dict],
) -> ELBResult | None:
    if resource_type != "application_load_balancer":
        return None

    insecure: list[dict] = []

    for listener in listeners:
        if listener.get("protocol") != "HTTP":
            continue

        actions = listener.get(
            "default_actions",
            [],
        )

        redirects = [
            action
            for action in actions
            if action.get("Type") == "redirect"
        ]

        https_redirect = any(
            action.get("RedirectConfig", {}).get(
                "Protocol"
            ) == "HTTPS"
            and action.get("RedirectConfig", {}).get(
                "Port"
            ) in {None, "443"}
            for action in redirects
            if isinstance(
                action.get("RedirectConfig"),
                dict,
            )
        )

        if not https_redirect:
            insecure.append(
                {
                    "listener_arn": listener.get(
                        "resource_id"
                    ),
                    "protocol": listener.get(
                        "protocol"
                    ),
                    "port": listener.get("port"),
                }
            )

    if not insecure:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "insecure_http_listeners": insecure,
        },
    )


def build_elb_http_to_https_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-001",
        title="Application Load Balancer does not redirect HTTP to HTTPS",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Application Load Balancer "
            f"{result.resource_id} has HTTP listeners "
            "that do not redirect requests to HTTPS."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure every HTTP listener on the "
            "Application Load Balancer to redirect "
            "requests to HTTPS on port 443."
        ),
        compliance=[
            "AWS Security Hub ELB.1",
            "NIST SP 800-53 Rev. 5 SC-8",
            "PCI DSS v4.0.1/4.2.1",
        ],
    )


def check_elb_logging(
    resource_id: str,
    resource_type: str,
    access_logs_enabled: bool | None,
) -> ELBResult | None:
    if resource_type not in {
        "application_load_balancer",
        "classic_load_balancer",
    }:
        return None

    if access_logs_enabled is not False:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "access_logs_enabled": False,
        },
    )


def build_elb_logging_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-002",
        title="Application or Classic Load Balancer access logging is disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The load balancer {result.resource_id} "
            "does not have access logging enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable access logging and deliver the "
            "logs to an appropriate S3 bucket."
        ),
        compliance=[
            "AWS Security Hub ELB.5",
            "NIST SP 800-53 Rev. 5 AU-2",
            "NIST SP 800-53 Rev. 5 AU-12",
        ],
    )


def check_elb_deletion_protection(
    resource_id: str,
    resource_type: str,
    deletion_protection: bool,
) -> ELBResult | None:
    if resource_type not in {
        "application_load_balancer",
        "network_load_balancer",
        "gateway_load_balancer",
    }:
        return None

    if deletion_protection:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "deletion_protection": False,
        },
    )


def build_elb_deletion_protection_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-003",
        title="Load balancer deletion protection is disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The load balancer {result.resource_id} "
            "does not have deletion protection enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable deletion protection for the "
            "load balancer when accidental deletion "
            "could disrupt a production workload."
        ),
        compliance=[
            "AWS Security Hub ELB.6",
            "NIST SP 800-53 Rev. 5 CM-3",
            "NIST SP 800-53 Rev. 5 CP-10",
        ],
    )


def check_elb_invalid_headers(
    resource_id: str,
    resource_type: str,
    drop_invalid_headers: bool,
) -> ELBResult | None:
    if resource_type != "application_load_balancer":
        return None

    if drop_invalid_headers:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "drop_invalid_header_fields_enabled": False,
        },
    )


def build_elb_invalid_headers_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-004",
        title="Application Load Balancer does not drop invalid HTTP headers",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Application Load Balancer "
            f"{result.resource_id} does not have "
            "invalid HTTP header dropping enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable the "
            "routing.http.drop_invalid_header_fields.enabled "
            "attribute."
        ),
        compliance=[
            "AWS Security Hub ELB.4",
            "NIST SP 800-53 Rev. 5 SC-7(4)",
        ],
    )


def check_elb_desync_mitigation(
    resource_id: str,
    resource_type: str,
    desync_mitigation_mode: str | None,
) -> ELBResult | None:
    if resource_type != "application_load_balancer":
        return None

    if desync_mitigation_mode in {
        "defensive",
        "strictest",
    }:
        return None

    if desync_mitigation_mode is None:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "desync_mitigation_mode": (
                desync_mitigation_mode
            ),
        },
    )


def build_elb_desync_mitigation_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-005",
        title="Application Load Balancer desync mitigation is not defensive or strictest",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Application Load Balancer "
            f"{result.resource_id} is not configured "
            "with defensive or strictest HTTP desync "
            "mitigation."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure the load balancer's "
            "routing.http.desync_mitigation_mode "
            "attribute to defensive or strictest."
        ),
        compliance=[
            "AWS Security Hub ELB.12",
            "NIST SP 800-53 Rev. 5 AC-4(21)",
        ],
    )


def check_elb_multi_az(
    resource_id: str,
    resource_type: str,
    availability_zones: list[str],
) -> ELBResult | None:
    if resource_type not in {
        "application_load_balancer",
        "network_load_balancer",
        "gateway_load_balancer",
    }:
        return None

    unique_zones = {
        zone
        for zone in availability_zones
        if isinstance(zone, str) and zone
    }

    if len(unique_zones) >= 2:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "availability_zones": sorted(unique_zones),
            "availability_zone_count": len(unique_zones),
        },
    )


def build_elb_multi_az_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-006",
        title="Load balancer does not span multiple Availability Zones",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The load balancer {result.resource_id} "
            "is configured in fewer than two "
            "Availability Zones."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure the load balancer across at least "
            "two Availability Zones."
        ),
        compliance=[
            "AWS Security Hub ELB.13",
            "NIST SP 800-53 Rev. 5 CP-6",
            "NIST SP 800-53 Rev. 5 SC-5(2)",
        ],
    )


def check_elb_listener_protocol(
    resource_id: str,
    resource_type: str,
    listeners: list[dict],
) -> ELBResult | None:
    if resource_type not in {
        "application_load_balancer",
        "network_load_balancer",
    }:
        return None

    expected_protocol = (
        "HTTPS"
        if resource_type == "application_load_balancer"
        else "TLS"
    )

    insecure = []

    for listener in listeners:
        protocol = listener.get("protocol")

        if protocol != expected_protocol:
            insecure.append(
                {
                    "listener_arn": listener.get(
                        "resource_id"
                    ),
                    "protocol": protocol,
                    "port": listener.get("port"),
                }
            )

    if not insecure:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "expected_protocol": expected_protocol,
            "insecure_listeners": insecure,
        },
    )


def build_elb_listener_protocol_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-007",
        title="Load balancer listener does not use an encrypted protocol",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The load balancer {result.resource_id} "
            "has a listener that does not use the "
            "expected encrypted listener protocol."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure Application Load Balancer "
            "listeners to use HTTPS and Network Load "
            "Balancer listeners to use TLS."
        ),
        compliance=[
            "AWS Security Hub ELB.18",
            "NIST SP 800-53 Rev. 5 SC-8",
            "NIST SP 800-53 Rev. 5 SC-13",
        ],
    )


def check_elb_health_check_protocol(
    resource_id: str,
    resource_type: str,
    target_groups: list[dict],
) -> ELBResult | None:
    if resource_type not in {
        "application_load_balancer",
        "network_load_balancer",
    }:
        return None

    insecure = []

    for target_group in target_groups:
        if target_group.get("target_type") == "lambda":
            continue

        protocol = target_group.get(
            "health_check_protocol"
        )

        if protocol == "HTTPS":
            continue

        if protocol is None:
            continue

        insecure.append(
            {
                "target_group_arn": (
                    target_group.get(
                        "resource_id"
                    )
                ),
                "health_check_protocol": protocol,
            }
        )

    if not insecure:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "insecure_health_checks": insecure,
        },
    )


def build_elb_health_check_protocol_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-008",
        title="Load balancer target group health checks are not encrypted with HTTPS",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The load balancer {result.resource_id} "
            "has target groups whose applicable health "
            "checks do not use HTTPS."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure applicable Application and Network "
            "Load Balancer target group health checks "
            "to use HTTPS."
        ),
        compliance=[
            "AWS Security Hub ELB.21",
            "NIST SP 800-53 Rev. 5 SC-8",
        ],
    )


def check_elb_target_transport(
    resource_id: str,
    resource_type: str,
    target_groups: list[dict],
) -> ELBResult | None:
    if resource_type not in {
        "application_load_balancer",
        "network_load_balancer",
    }:
        return None

    insecure = []

    for target_group in target_groups:
        target_type = target_group.get("target_type")
        protocol = target_group.get("protocol")

        if target_type in {
            "lambda",
        }:
            continue

        if protocol in {
            "HTTPS",
            "TLS",
            "QUIC",
        }:
            continue

        if protocol in {
            "GENEVE",
        }:
            continue

        if target_type == "alb":
            continue

        if protocol is None:
            continue

        insecure.append(
            {
                "target_group_arn": (
                    target_group.get(
                        "resource_id"
                    )
                ),
                "protocol": protocol,
                "protocol_version": (
                    target_group.get(
                        "protocol_version"
                    )
                ),
                "target_type": target_type,
            }
        )

    if not insecure:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "unencrypted_target_groups": insecure,
        },
    )


def build_elb_target_transport_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-009",
        title="Load balancer target groups use unencrypted transport",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The load balancer {result.resource_id} "
            "has applicable target groups that use an "
            "unencrypted transport protocol."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Use HTTPS, TLS, or QUIC target group "
            "protocols where applicable."
        ),
        compliance=[
            "AWS Security Hub ELB.22",
            "NIST SP 800-53 Rev. 5 SC-8",
            "NIST SP 800-53 Rev. 5 SC-13",
        ],
    )


def check_classic_acm_certificate(
    resource_id: str,
    resource_type: str,
    listeners: list[dict],
) -> ELBResult | None:
    if resource_type != "classic_load_balancer":
        return None

    insecure = []

    for listener in listeners:
        if listener.get("protocol") not in {
            "HTTPS",
            "SSL",
        }:
            continue

        certificate = listener.get(
            "ssl_certificate_id"
        )

        if not isinstance(certificate, str):
            insecure.append(
                {
                    "listener_id": listener.get(
                        "resource_id"
                    ),
                    "certificate": certificate,
                }
            )
            continue

        parts = certificate.split(":")

        if len(parts) < 6 or parts[2] != "acm":
            insecure.append(
                {
                    "listener_id": listener.get(
                        "resource_id"
                    ),
                    "certificate": certificate,
                }
            )

    if not insecure:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "non_acm_certificates": insecure,
        },
    )


def build_classic_acm_certificate_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-010",
        title="Classic Load Balancer secure listener does not use an ACM certificate",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Classic Load Balancer {result.resource_id} "
            "has an HTTPS or SSL listener using a certificate "
            "that is not provided by AWS Certificate Manager."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Replace the listener certificate with an "
            "AWS Certificate Manager certificate."
        ),
        compliance=[
            "AWS Security Hub ELB.2",
            "NIST SP 800-53 Rev. 5 SC-8",
            "NIST SP 800-53 Rev. 5 SC-12",
        ],
    )


def check_classic_listener_protocol(
    resource_id: str,
    resource_type: str,
    listeners: list[dict],
) -> ELBResult | None:
    if resource_type != "classic_load_balancer":
        return None

    if not listeners:
        return None

    insecure = [
        {
            "listener_id": listener.get("resource_id"),
            "protocol": listener.get("protocol"),
            "port": listener.get("port"),
        }
        for listener in listeners
        if listener.get("protocol") not in {
            "HTTPS",
            "SSL",
        }
    ]

    if not insecure:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "insecure_listeners": insecure,
        },
    )


def build_classic_listener_protocol_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-011",
        title="Classic Load Balancer listener does not use HTTPS or SSL",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Classic Load Balancer {result.resource_id} "
            "has one or more front-end listeners that do not "
            "use HTTPS or SSL termination."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure Classic Load Balancer front-end "
            "listeners to use HTTPS or SSL."
        ),
        compliance=[
            "AWS Security Hub ELB.3",
            "NIST SP 800-53 Rev. 5 SC-8",
            "NIST SP 800-53 Rev. 5 SC-13",
        ],
    )


def check_classic_connection_draining(
    resource_id: str,
    resource_type: str,
    connection_draining_enabled: bool | None,
) -> ELBResult | None:
    if resource_type != "classic_load_balancer":
        return None

    if connection_draining_enabled is not False:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "connection_draining_enabled": False,
        },
    )


def build_classic_connection_draining_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-012",
        title="Classic Load Balancer connection draining is disabled",
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Classic Load Balancer {result.resource_id} "
            "does not have connection draining enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable connection draining for the Classic "
            "Load Balancer."
        ),
        compliance=[
            "AWS Security Hub ELB.7",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
        ],
    )


def check_classic_security_policy(
    resource_id: str,
    resource_type: str,
    listeners: list[dict],
) -> ELBResult | None:
    if resource_type != "classic_load_balancer":
        return None

    insecure = []

    for listener in listeners:
        if listener.get("protocol") not in {
            "HTTPS",
            "SSL",
        }:
            continue

        policies = listener.get(
            "policy_names",
            [],
        )

        if (
            not isinstance(policies, list)
            or CLASSIC_STRONG_SSL_POLICY not in policies
        ):
            insecure.append(
                {
                    "listener_id": listener.get(
                        "resource_id"
                    ),
                    "policy_names": policies,
                }
            )

    if not insecure:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "insecure_ssl_listeners": insecure,
            "required_policy": CLASSIC_STRONG_SSL_POLICY,
        },
    )


def build_classic_security_policy_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-013",
        title="Classic Load Balancer SSL listener does not use the required strong security policy",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Classic Load Balancer {result.resource_id} "
            "has an SSL listener that does not use the "
            "AWS-required strong predefined security policy."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure every HTTPS/SSL listener to use "
            f"{CLASSIC_STRONG_SSL_POLICY}."
        ),
        compliance=[
            "AWS Security Hub ELB.8",
            "NIST SP 800-53 Rev. 5 SC-13",
        ],
    )


def check_classic_cross_zone(
    resource_id: str,
    resource_type: str,
    cross_zone_load_balancing_enabled: bool | None,
) -> ELBResult | None:
    if resource_type != "classic_load_balancer":
        return None

    if cross_zone_load_balancing_enabled is not False:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "cross_zone_load_balancing_enabled": False,
        },
    )


def build_classic_cross_zone_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-014",
        title="Classic Load Balancer cross-zone load balancing is disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Classic Load Balancer {result.resource_id} "
            "does not have cross-zone load balancing enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable cross-zone load balancing for the "
            "Classic Load Balancer."
        ),
        compliance=[
            "AWS Security Hub ELB.9",
            "NIST SP 800-53 Rev. 5 CP-6(2)",
        ],
    )


def check_classic_multi_az(
    resource_id: str,
    resource_type: str,
    availability_zones: list[str],
) -> ELBResult | None:
    if resource_type != "classic_load_balancer":
        return None

    zones = {
        zone
        for zone in availability_zones
        if isinstance(zone, str) and zone
    }

    if len(zones) >= 2:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "availability_zones": sorted(zones),
            "availability_zone_count": len(zones),
        },
    )


def build_classic_multi_az_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-015",
        title="Classic Load Balancer does not span multiple Availability Zones",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Classic Load Balancer {result.resource_id} "
            "is configured in fewer than two Availability Zones."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure the Classic Load Balancer across "
            "at least two Availability Zones."
        ),
        compliance=[
            "AWS Security Hub ELB.10",
            "NIST SP 800-53 Rev. 5 CP-6(2)",
        ],
    )


def check_classic_desync(
    resource_id: str,
    resource_type: str,
    desync_mitigation_mode: str | None,
) -> ELBResult | None:
    if resource_type != "classic_load_balancer":
        return None

    if desync_mitigation_mode in {
        "defensive",
        "strictest",
    }:
        return None

    if desync_mitigation_mode is None:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "desync_mitigation_mode": (
                desync_mitigation_mode
            ),
        },
    )


def build_classic_desync_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-016",
        title="Classic Load Balancer desync mitigation is not defensive or strictest",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Classic Load Balancer {result.resource_id} "
            "is not configured with defensive or strictest "
            "HTTP desync mitigation."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure elb.http.desyncmitigationmode to "
            "defensive or strictest."
        ),
        compliance=[
            "AWS Security Hub ELB.14",
            "NIST SP 800-53 Rev. 5 AC-4(21)",
        ],
    )


def check_elb_waf(
    resource_id: str,
    resource_type: str,
    waf_web_acl_arn: str | None,
) -> ELBResult | None:
    if resource_type != "application_load_balancer":
        return None

    if isinstance(waf_web_acl_arn, str) and waf_web_acl_arn:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "waf_web_acl_arn": waf_web_acl_arn,
        },
    )


def build_elb_waf_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-017",
        title="Application Load Balancer is not associated with an AWS WAF web ACL",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Application Load Balancer {result.resource_id} "
            "does not have an AWS WAF web ACL associated with it."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Associate the Application Load Balancer with "
            "an appropriate AWS WAF web ACL."
        ),
        compliance=[
            "AWS Security Hub ELB.16",
            "NIST SP 800-53 Rev. 5 AC-4(21)",
        ],
    )


def check_elb_recommended_security_policy(
    resource_id: str,
    resource_type: str,
    listeners: list[dict],
) -> ELBResult | None:
    if resource_type not in {
        "application_load_balancer",
        "network_load_balancer",
    }:
        return None

    insecure = []

    expected_protocol = (
        "HTTPS"
        if resource_type == "application_load_balancer"
        else "TLS"
    )

    for listener in listeners:
        if listener.get("protocol") != expected_protocol:
            continue

        policy = listener.get("ssl_policy")

        if policy not in RECOMMENDED_V2_SSL_POLICIES:
            insecure.append(
                {
                    "listener_arn": listener.get(
                        "resource_id"
                    ),
                    "protocol": listener.get(
                        "protocol"
                    ),
                    "port": listener.get("port"),
                    "ssl_policy": policy,
                }
            )

    if not insecure:
        return None

    return _result(
        resource_id,
        resource_type,
        {
            "insecure_listeners": insecure,
            "recommended_ssl_policies": sorted(
                RECOMMENDED_V2_SSL_POLICIES
            ),
        },
    )


def build_elb_recommended_security_policy_finding(
    result: ELBResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELB-018",
        title="Application or Network Load Balancer listener does not use a recommended security policy",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The load balancer {result.resource_id} "
            "has an HTTPS or TLS listener that does not "
            "use an AWS-recommended security policy."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Update applicable HTTPS/TLS listeners to use "
            "one of the AWS Security Hub recommended "
            "ELB security policies."
        ),
        compliance=[
            "AWS Security Hub ELB.17",
            "NIST SP 800-53 Rev. 5 SC-13",
        ],
    )
