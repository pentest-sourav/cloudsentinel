from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SecretsManagerAutomaticRotationResult:
    resource_id: str
    resource_arn: str
    rotation_enabled: bool | None
    rotation_rules: dict[str, Any]


def check_secretsmanager_automatic_rotation(
    resource_id: str,
    resource_arn: str,
    rotation_enabled: bool | None,
    rotation_rules: dict[str, Any],
) -> SecretsManagerAutomaticRotationResult | None:
    if rotation_enabled is True:
        return None

    return SecretsManagerAutomaticRotationResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        rotation_enabled=rotation_enabled,
        rotation_rules=rotation_rules,
    )


def build_secretsmanager_automatic_rotation_finding(
    result: SecretsManagerAutomaticRotationResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SECRETSMANAGER-001",
        title=(
            "Secrets Manager Secret Does Not Have "
            "Automatic Rotation Enabled"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="secretsmanager_secret",
        resource_id=result.resource_id,
        description=(
            "The Secrets Manager secret is not configured "
            "for automatic rotation."
        ),
        evidence={
            "secret_arn": result.resource_arn,
            "rotation_enabled": result.rotation_enabled,
            "rotation_rules": result.rotation_rules,
        },
        remediation=(
            "Enable automatic rotation for the secret "
            "using an appropriate rotation configuration."
        ),
        compliance=[
            "AWS Security Hub SecretsManager.1",
        ],
    )
