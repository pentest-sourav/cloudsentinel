from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EKSAuditLoggingResult:
    resource_id: str
    resource_arn: str
    cluster_logging: list


def check_eks_audit_logging(
    resource_id: str,
    resource_arn: str,
    cluster_logging: list,
) -> EKSAuditLoggingResult | None:
    for configuration in cluster_logging:
        if not isinstance(configuration, dict):
            continue

        if configuration.get("enabled") is not True:
            continue

        types = configuration.get("types")

        if (
            isinstance(types, list)
            and "audit" in types
        ):
            return None

    return EKSAuditLoggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        cluster_logging=cluster_logging,
    )


def build_eks_audit_logging_finding(
    result: EKSAuditLoggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EKS-008",
        title="EKS Cluster Audit Logging Is Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="eks_cluster",
        resource_id=result.resource_id,
        description=(
            "The EKS cluster does not have the Kubernetes "
            "audit control-plane log type enabled."
        ),
        evidence={
            "cluster_arn": result.resource_arn,
            "cluster_logging": result.cluster_logging,
            "audit_logging_enabled": False,
        },
        remediation=(
            "Enable the EKS control-plane audit log type "
            "and export it to CloudWatch Logs."
        ),
        compliance=[
            "AWS Security Hub EKS.8",
        ],
    )
