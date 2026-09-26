from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RedshiftRuleResult:
    cluster_identifier: str
    evidence: dict[str, object]


def _result(
    cluster_identifier: str,
    evidence: dict[str, object],
) -> RedshiftRuleResult | None:
    if not cluster_identifier:
        return None

    return RedshiftRuleResult(
        cluster_identifier=cluster_identifier,
        evidence=evidence,
    )


def check_redshift_public_access(
    cluster_identifier: str,
    publicly_accessible: bool | None,
) -> RedshiftRuleResult | None:
    if not cluster_identifier or publicly_accessible is not True:
        return None

    return _result(
        cluster_identifier,
        {
            "publicly_accessible": True,
            "internet_exposed": True,
        },
    )


def build_redshift_public_access_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-001",
        title="Redshift Cluster Is Publicly Accessible",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "is configured for public access."
        ),
        evidence=result.evidence,
        remediation=(
            "Disable public accessibility for the Redshift cluster "
            "unless public exposure is explicitly required. "
            "Prefer private connectivity and restricted network access."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
            "PCI DSS v4.0.1",
        ],
    )


def check_redshift_require_ssl(
    cluster_identifier: str,
    require_ssl: str | None,
) -> RedshiftRuleResult | None:
    if not cluster_identifier or require_ssl is None:
        return None

    if str(require_ssl).lower() == "true":
        return None

    return _result(
        cluster_identifier,
        {"require_ssl": require_ssl},
    )


def build_redshift_require_ssl_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-002",
        title="Redshift Cluster Does Not Require SSL",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "does not require encrypted TLS connections."
        ),
        evidence=result.evidence,
        remediation=(
            "Set the Redshift cluster parameter require_ssl to True "
            "in the associated cluster parameter group."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
            "PCI DSS v4.0.1",
        ],
    )


def check_redshift_backup_retention(
    cluster_identifier: str,
    automated_snapshot_retention_period: int | None,
) -> RedshiftRuleResult | None:
    if (
        not cluster_identifier
        or automated_snapshot_retention_period is None
    ):
        return None

    if automated_snapshot_retention_period >= 7:
        return None

    return _result(
        cluster_identifier,
        {
            "automated_snapshot_retention_period":
                automated_snapshot_retention_period,
            "minimum_required_days": 7,
        },
    )


def build_redshift_backup_retention_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-003",
        title="Redshift Automated Snapshot Retention Is Insufficient",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "does not retain automated snapshots for at least "
            "the Security Hub default minimum of seven days."
        ),
        evidence=result.evidence,
        remediation=(
            "Configure automated Redshift snapshot retention to "
            "at least seven days."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_redshift_audit_logging(
    cluster_identifier: str,
    audit_logging_enabled: bool | None,
) -> RedshiftRuleResult | None:
    if (
        not cluster_identifier
        or audit_logging_enabled is None
    ):
        return None

    if audit_logging_enabled:
        return None

    return _result(
        cluster_identifier,
        {"audit_logging_enabled": False},
    )


def build_redshift_audit_logging_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-004",
        title="Redshift Audit Logging Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "does not have audit logging enabled."
        ),
        evidence=result.evidence,
        remediation=(
            "Enable Amazon Redshift audit logging and configure "
            "an appropriate secure S3 destination."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
            "PCI DSS v4.0.1",
        ],
    )


def check_redshift_allow_version_upgrade(
    cluster_identifier: str,
    allow_version_upgrade: bool | None,
) -> RedshiftRuleResult | None:
    if (
        not cluster_identifier
        or allow_version_upgrade is None
    ):
        return None

    if allow_version_upgrade:
        return None

    return _result(
        cluster_identifier,
        {"allow_version_upgrade": False},
    )


def build_redshift_allow_version_upgrade_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-005",
        title="Redshift Automatic Major Version Upgrades Are Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "does not allow automatic major version upgrades."
        ),
        evidence=result.evidence,
        remediation=(
            "Enable AllowVersionUpgrade for the Redshift cluster "
            "so supported major version upgrades can be applied "
            "during the configured maintenance process."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_redshift_enhanced_vpc_routing(
    cluster_identifier: str,
    enhanced_vpc_routing: bool | None,
) -> RedshiftRuleResult | None:
    if (
        not cluster_identifier
        or enhanced_vpc_routing is None
    ):
        return None

    if enhanced_vpc_routing:
        return None

    return _result(
        cluster_identifier,
        {"enhanced_vpc_routing": False},
    )


def build_redshift_enhanced_vpc_routing_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-006",
        title="Redshift Enhanced VPC Routing Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "does not have enhanced VPC routing enabled."
        ),
        evidence=result.evidence,
        remediation=(
            "Enable EnhancedVpcRouting so COPY and UNLOAD traffic "
            "between Redshift and data repositories remains inside "
            "the VPC and can be controlled using VPC security controls."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_redshift_default_admin(
    cluster_identifier: str,
    master_username: str | None,
) -> RedshiftRuleResult | None:
    if not cluster_identifier or master_username is None:
        return None

    if master_username != "awsuser":
        return None

    return _result(
        cluster_identifier,
        {"master_username": master_username},
    )


def build_redshift_default_admin_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-007",
        title="Redshift Cluster Uses the Default Admin Username",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "uses the default administrator username awsuser."
        ),
        evidence=result.evidence,
        remediation=(
            "Use a unique administrator username when creating "
            "Redshift clusters. AWS does not support changing the "
            "administrator username after cluster creation."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_redshift_encryption(
    cluster_identifier: str,
    encrypted: bool | None,
) -> RedshiftRuleResult | None:
    if not cluster_identifier or encrypted is None:
        return None

    if encrypted:
        return None

    return _result(
        cluster_identifier,
        {"encrypted": False},
    )


def build_redshift_encryption_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-008",
        title="Redshift Cluster Encryption at Rest Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "is not encrypted at rest."
        ),
        evidence=result.evidence,
        remediation=(
            "Enable Redshift encryption at rest using an appropriate "
            "AWS KMS key according to the application's key-management "
            "requirements."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_redshift_unrestricted_port(
    cluster_identifier: str,
    cluster_port: int | None,
    security_group_ingress: list[dict[str, object]] | None,
) -> RedshiftRuleResult | None:
    if not cluster_identifier or cluster_port is None:
        return None

    if security_group_ingress is None:
        return None

    unrestricted_rules: list[dict[str, object]] = []

    for rule in security_group_ingress:
        ipv4 = rule.get("ipv4_ranges") or []
        ipv6 = rule.get("ipv6_ranges") or []

        if "0.0.0.0/0" in ipv4 or "::/0" in ipv6:
            unrestricted_rules.append(rule)

    if not unrestricted_rules:
        return None

    return _result(
        cluster_identifier,
        {
            "cluster_port": cluster_port,
            "unrestricted_ingress": unrestricted_rules,
        },
    )


def build_redshift_unrestricted_port_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-009",
        title="Redshift Cluster Port Allows Unrestricted Ingress",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "has a security-group ingress rule allowing unrestricted "
            "internet access to the cluster port."
        ),
        evidence=result.evidence,
        remediation=(
            "Restrict Redshift security-group ingress on the cluster "
            "port to approved source networks or security groups. "
            "Remove 0.0.0.0/0 and ::/0 access unless explicitly required."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "PCI DSS v4.0.1",
        ],
    )


def check_redshift_multi_az(
    cluster_identifier: str,
    multi_az: bool | None,
) -> RedshiftRuleResult | None:
    if not cluster_identifier or multi_az is None:
        return None

    if multi_az:
        return None

    return _result(
        cluster_identifier,
        {"multi_az": False},
    )


def build_redshift_multi_az_finding(
    result: RedshiftRuleResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-REDSHIFT-010",
        title="Redshift Multi-AZ Deployment Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="redshift_cluster",
        resource_id=result.cluster_identifier,
        description=(
            f"The Redshift cluster {result.cluster_identifier} "
            "does not have Multi-AZ deployment enabled."
        ),
        evidence=result.evidence,
        remediation=(
            "Enable Multi-AZ deployment for provisioned Redshift "
            "clusters where high availability across Availability "
            "Zones is required."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
        ],
    )
