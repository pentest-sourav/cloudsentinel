from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class NetworkFirewallResult:
    resource_id: str
    resource_type: str
    details: dict


def _result(
    resource_id: str,
    resource_type: str,
    details: dict,
) -> NetworkFirewallResult | None:
    if not resource_id:
        return None

    return NetworkFirewallResult(
        resource_id=resource_id,
        resource_type=resource_type,
        details=details,
    )


def check_multi_az(
    resource_id: str,
    availability_zone_count: int,
    availability_zones: list[str],
) -> NetworkFirewallResult | None:
    if availability_zone_count >= 2:
        return None

    return _result(
        resource_id,
        "network_firewall",
        {
            "availability_zones": availability_zones,
            "availability_zone_count": (
                availability_zone_count
            ),
        },
    )


def build_multi_az_finding(
    result: NetworkFirewallResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NETWORKFIREWALL-001",
        title=(
            "Network Firewall is not deployed "
            "across multiple Availability Zones"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Network Firewall {result.resource_id} "
            "is deployed in fewer than two Availability "
            "Zones."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Deploy the Network Firewall across at least "
            "two Availability Zones."
        ),
        compliance=[
            "AWS Security Hub NetworkFirewall.1",
            "NIST SP 800-53 Rev. 5 CP-10",
            "NIST SP 800-53 Rev. 5 CP-6(2)",
            "NIST SP 800-53 Rev. 5 SC-36",
        ],
    )


def check_logging(
    resource_id: str,
    logging_enabled: bool,
    log_destination_count: int,
) -> NetworkFirewallResult | None:
    if logging_enabled:
        return None

    return _result(
        resource_id,
        "network_firewall",
        {
            "logging_enabled": False,
            "log_destination_count": (
                log_destination_count
            ),
        },
    )


def build_logging_finding(
    result: NetworkFirewallResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NETWORKFIREWALL-002",
        title="Network Firewall logging is not enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Network Firewall {result.resource_id} "
            "does not have a configured logging destination."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable Network Firewall logging and configure "
            "at least one log destination."
        ),
        compliance=[
            "AWS Security Hub NetworkFirewall.2",
            "NIST SP 800-53 Rev. 5 AU-2",
            "NIST SP 800-53 Rev. 5 AU-12",
            "NIST SP 800-53 Rev. 5 CA-7",
            "NIST SP 800-53 Rev. 5 SI-4",
        ],
    )


def check_policy_rule_group(
    resource_id: str,
    has_rule_group: bool,
    stateless_rule_group_count: int,
    stateful_rule_group_count: int,
) -> NetworkFirewallResult | None:
    if has_rule_group:
        return None

    return _result(
        resource_id,
        "network_firewall_policy",
        {
            "has_rule_group": False,
            "stateless_rule_group_count": (
                stateless_rule_group_count
            ),
            "stateful_rule_group_count": (
                stateful_rule_group_count
            ),
        },
    )


def build_policy_rule_group_finding(
    result: NetworkFirewallResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NETWORKFIREWALL-003",
        title=(
            "Network Firewall policy has no "
            "associated rule group"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Network Firewall policy "
            f"{result.resource_id} has neither a stateful "
            "nor stateless rule group associated with it."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Associate at least one appropriate stateful "
            "or stateless Network Firewall rule group "
            "with the policy."
        ),
        compliance=[
            "AWS Security Hub NetworkFirewall.3",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 CM-2",
        ],
    )


def _has_allowed_default_action(
    actions: list[str],
) -> bool:
    allowed = {
        "aws:drop",
        "aws:forward_to_sfe",
    }

    return any(
        action in allowed
        for action in actions
        if isinstance(action, str)
    )


def check_default_full_packet_action(
    resource_id: str,
    stateless_default_actions: list[str],
) -> NetworkFirewallResult | None:
    if _has_allowed_default_action(
        stateless_default_actions
    ):
        return None

    return _result(
        resource_id,
        "network_firewall_policy",
        {
            "stateless_default_actions": (
                stateless_default_actions
            ),
        },
    )


def build_default_full_packet_action_finding(
    result: NetworkFirewallResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NETWORKFIREWALL-004",
        title=(
            "Network Firewall full-packet default "
            "stateless action is not drop or forward"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Network Firewall policy "
            f"{result.resource_id} does not configure "
            "its full-packet stateless default action "
            "as drop or forward to the stateful engine."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure StatelessDefaultActions to use "
            "aws:drop or aws:forward_to_sfe."
        ),
        compliance=[
            "AWS Security Hub NetworkFirewall.4",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 CM-2",
        ],
    )


def check_default_fragment_action(
    resource_id: str,
    stateless_fragment_default_actions: list[str],
) -> NetworkFirewallResult | None:
    if _has_allowed_default_action(
        stateless_fragment_default_actions
    ):
        return None

    return _result(
        resource_id,
        "network_firewall_policy",
        {
            "stateless_fragment_default_actions": (
                stateless_fragment_default_actions
            ),
        },
    )


def build_default_fragment_action_finding(
    result: NetworkFirewallResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NETWORKFIREWALL-005",
        title=(
            "Network Firewall fragmented-packet default "
            "stateless action is not drop or forward"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Network Firewall policy "
            f"{result.resource_id} does not configure "
            "its fragmented-packet stateless default "
            "action as drop or forward to the stateful engine."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Configure "
            "StatelessFragmentDefaultActions to use "
            "aws:drop or aws:forward_to_sfe."
        ),
        compliance=[
            "AWS Security Hub NetworkFirewall.5",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 CM-2",
            "NIST SP 800-171 Rev. 2 3.1.3",
            "NIST SP 800-171 Rev. 2 3.1.14",
        ],
    )


def check_stateless_rule_group_not_empty(
    resource_id: str,
    stateless_rule_count: int,
) -> NetworkFirewallResult | None:
    if stateless_rule_count > 0:
        return None

    return _result(
        resource_id,
        "network_firewall_stateless_rule_group",
        {
            "stateless_rule_count": stateless_rule_count,
        },
    )


def build_stateless_rule_group_not_empty_finding(
    result: NetworkFirewallResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NETWORKFIREWALL-006",
        title="Network Firewall stateless rule group is empty",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The stateless Network Firewall rule group "
            f"{result.resource_id} contains no stateless rules."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Add one or more stateless rules to the "
            "Network Firewall rule group, or remove the "
            "unused rule group."
        ),
        compliance=[
            "AWS Security Hub NetworkFirewall.6",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 CM-2",
            "NIST SP 800-171 Rev. 2 3.1.3",
            "NIST SP 800-171 Rev. 2 3.13.1",
        ],
    )


def check_deletion_protection(
    resource_id: str,
    delete_protection: bool,
) -> NetworkFirewallResult | None:
    if delete_protection:
        return None

    return _result(
        resource_id,
        "network_firewall",
        {
            "delete_protection": False,
        },
    )


def build_deletion_protection_finding(
    result: NetworkFirewallResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NETWORKFIREWALL-009",
        title="Network Firewall deletion protection is disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Network Firewall {result.resource_id} "
            "does not have deletion protection enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable deletion protection for the Network "
            "Firewall to reduce the risk of accidental deletion."
        ),
        compliance=[
            "AWS Security Hub NetworkFirewall.9",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 CM-2",
            "NIST SP 800-53 Rev. 5 CM-3",
            "NIST SP 800-53 Rev. 5 SC-5(2)",
        ],
    )


def check_subnet_change_protection(
    resource_id: str,
    subnet_change_protection: bool,
) -> NetworkFirewallResult | None:
    if subnet_change_protection:
        return None

    return _result(
        resource_id,
        "network_firewall",
        {
            "subnet_change_protection": False,
        },
    )


def build_subnet_change_protection_finding(
    result: NetworkFirewallResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NETWORKFIREWALL-010",
        title=(
            "Network Firewall subnet change protection "
            "is disabled"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Network Firewall {result.resource_id} "
            "does not have subnet change protection enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable subnet change protection for the "
            "Network Firewall to prevent accidental "
            "changes to subnet associations."
        ),
        compliance=[
            "AWS Security Hub NetworkFirewall.10",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 CM-2",
            "NIST SP 800-53 Rev. 5 CM-3",
            "NIST SP 800-53 Rev. 5 SC-5(2)",
        ],
    )
