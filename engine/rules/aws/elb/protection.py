from dataclasses import dataclass

from engine.findings.model import Finding, Severity


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
            "requests to HTTPS."
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
    access_logs_enabled: bool,
) -> ELBResult | None:
    if resource_type not in {
        "application_load_balancer",
        "network_load_balancer",
    }:
        return None

    if access_logs_enabled:
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
        title="Load balancer access logging is disabled",
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
            "two Availability Zones to reduce the impact "
            "of an Availability Zone failure."
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
        protocol = target_group.get(
            "health_check_protocol"
        )

        if protocol not in {
            "HTTPS",
            "TLS",
        }:
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
        title="Load balancer target group health checks are not encrypted",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The load balancer {result.resource_id} "
            "has target groups whose health checks "
            "do not use an encrypted protocol."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure target group health checks to "
            "use HTTPS or TLS where supported."
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
        protocol = target_group.get("protocol")

        if protocol in {
            "HTTPS",
            "TLS",
        }:
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
            "has target groups that use an unencrypted "
            "transport protocol."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Use HTTPS or TLS target group protocols "
            "when encrypted transport between the "
            "load balancer and targets is required."
        ),
        compliance=[
            "AWS Security Hub ELB.22",
            "NIST SP 800-53 Rev. 5 SC-8",
            "NIST SP 800-53 Rev. 5 SC-13",
        ],
    )
