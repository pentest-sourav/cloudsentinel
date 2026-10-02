from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SecurityHubControlResult:
    resource_id: str
    control_name: str
    expected_configuration: str
    actual_configuration: str
    evidence: dict[str, object]


def check_hub_enabled(
    resource_id: str,
    enabled: bool,
) -> SecurityHubControlResult | None:
    if enabled:
        return None

    return SecurityHubControlResult(
        resource_id=resource_id,
        control_name="AWS Security Hub CSPM",
        expected_configuration="ENABLED",
        actual_configuration="DISABLED",
        evidence={
            "enabled": enabled,
        },
    )


def check_standard_ready(
    resource_id: str,
    standards_subscription_arn: str | None,
    standards_arn: str | None,
    standards_status: str | None,
    standards_controls_updatable: str | None,
    standards_status_reason: str | None,
    provider: str | None,
) -> SecurityHubControlResult | None:
    if standards_status == "READY":
        return None

    return SecurityHubControlResult(
        resource_id=resource_id,
        control_name="Security Hub enabled standard",
        expected_configuration="READY",
        actual_configuration=str(
            standards_status
        ),
        evidence={
            "standards_subscription_arn": (
                standards_subscription_arn
            ),
            "standards_arn": standards_arn,
            "standards_status": standards_status,
            "standards_controls_updatable": (
                standards_controls_updatable
            ),
            "standards_status_reason": (
                standards_status_reason
            ),
            "provider": provider,
        },
    )


def build_hub_finding(
    result: SecurityHubControlResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SH-001",
        title="AWS Security Hub should be enabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="securityhub_hub",
        resource_id=result.resource_id,
        description=(
            "AWS Security Hub CSPM is not enabled "
            "in the scanned AWS Region."
        ),
        evidence=result.evidence,
        remediation=(
            "Enable AWS Security Hub CSPM in the "
            "affected AWS Region."
        ),
        compliance=[
            "AWS Security Hub CSPM",
        ],
    )


def build_standard_finding(
    result: SecurityHubControlResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SH-002",
        title=(
            "Enabled Security Hub standards "
            "should be ready"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="securityhub_standard",
        resource_id=result.resource_id,
        description=(
            "An enabled AWS Security Hub standard "
            "is not currently in READY status."
        ),
        evidence=result.evidence,
        remediation=(
            "Review the Security Hub standard status "
            "and resolve the reported configuration "
            "or enablement issue."
        ),
        compliance=[
            "AWS Security Hub CSPM",
        ],
    )
