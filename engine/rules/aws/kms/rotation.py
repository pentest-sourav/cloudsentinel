from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class KMSRotationResult:
    key_id: str
    key_arn: str | None
    rotation_enabled: bool


def check_kms_rotation(
    key_id: str,
    key_manager: str | None,
    rotation_enabled: bool | None,
) -> KMSRotationResult | None:
    if not key_id:
        return None

    if key_manager != "CUSTOMER":
        return None

    if rotation_enabled is None:
        return None

    if rotation_enabled:
        return None

    return KMSRotationResult(
        key_id=key_id,
        key_arn=None,
        rotation_enabled=rotation_enabled,
    )


def build_kms_rotation_finding(
    result: KMSRotationResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-KMS-001",
        title="KMS Key Rotation Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="kms_key",
        resource_id=result.key_id,
        description=(
            f"The customer-managed KMS key {result.key_id} does not "
            "have automatic key rotation enabled. Automatic rotation "
            "reduces the operational burden of periodically rotating "
            "cryptographic key material."
        ),
        evidence={
            "key_id": result.key_id,
            "rotation_enabled": result.rotation_enabled,
            "key_manager": "CUSTOMER",
        },
        remediation=(
            "Enable automatic key rotation for the customer-managed "
            "KMS key when compatible with the workload's key-management "
            "requirements."
        ),
    )
