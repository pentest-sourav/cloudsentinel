from dataclasses import dataclass

from engine.findings.model import Finding, Severity

from engine.rules.aws.macie.common import (
    MacieControlResult,
    check_enabled,
)


def check_macie_enabled(
    resource_id: str,
    macie_status: str | None,
) -> MacieControlResult | None:
    return check_enabled(
        resource_id,
        macie_status,
        control_name="Amazon Macie",
    )


@dataclass(frozen=True)
class MacieAutomatedDiscoveryResult:
    resource_id: str
    control_name: str
    expected_configuration: str
    actual_configuration: str


def check_automated_sensitive_data_discovery(
    resource_id: str,
    macie_status: str | None,
    is_member_account: bool,
    automated_discovery_status: str | None,
) -> MacieAutomatedDiscoveryResult | None:
    if is_member_account:
        return None

    if macie_status != "ENABLED":
        return MacieAutomatedDiscoveryResult(
            resource_id=resource_id,
            control_name=(
                "Amazon Macie automated sensitive "
                "data discovery"
            ),
            expected_configuration=(
                "Macie=ENABLED; "
                "AutomatedSensitiveDataDiscovery=ENABLED"
            ),
            actual_configuration=(
                "Macie="
                f"{macie_status or 'MISSING'}; "
                "AutomatedSensitiveDataDiscovery="
                f"{automated_discovery_status or 'MISSING'}"
            ),
        )

    if automated_discovery_status == "ENABLED":
        return None

    return MacieAutomatedDiscoveryResult(
        resource_id=resource_id,
        control_name=(
            "Amazon Macie automated sensitive "
            "data discovery"
        ),
        expected_configuration=(
            "Macie=ENABLED; "
            "AutomatedSensitiveDataDiscovery=ENABLED"
        ),
        actual_configuration=(
            "Macie=ENABLED; "
            "AutomatedSensitiveDataDiscovery="
            f"{automated_discovery_status or 'MISSING'}"
        ),
    )


def build_macie_001(
    result: MacieControlResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MACIE-001",
        title="Amazon Macie should be enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="macie_account",
        resource_id=result.resource_id,
        description=(
            "Amazon Macie is not enabled for the "
            "AWS account."
        ),
        evidence={
            "account_id": result.resource_id,
            "expected_configuration": (
                result.expected_configuration
            ),
            "actual_configuration": (
                result.actual_configuration
            ),
        },
        remediation=(
            "Enable Amazon Macie for the AWS account "
            "in the required AWS Region."
        ),
        compliance=[
            "AWS Security Hub Macie.1",
        ],
    )


def build_macie_002(
    result: MacieAutomatedDiscoveryResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MACIE-002",
        title=(
            "Amazon Macie automated sensitive data "
            "discovery should be enabled"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="macie_account",
        resource_id=result.resource_id,
        description=(
            "Amazon Macie automated sensitive data "
            "discovery is not enabled for the "
            "applicable Macie administrator or "
            "standalone account."
        ),
        evidence={
            "account_id": result.resource_id,
            "expected_configuration": (
                result.expected_configuration
            ),
            "actual_configuration": (
                result.actual_configuration
            ),
        },
        remediation=(
            "Enable automated sensitive data discovery "
            "in Amazon Macie for the applicable "
            "administrator or standalone account."
        ),
        compliance=[
            "AWS Security Hub Macie.2",
        ],
    )
