from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ECRCustomerManagedKMSResult:
    repository_name: str
    encryption_type: str | None
    kms_key: str | None
    kms_key_manager: str | None


def check_ecr_customer_managed_kms(
    repository_name: str,
    encryption_type: str | None,
    kms_key: str | None,
    kms_key_manager: str | None,
) -> ECRCustomerManagedKMSResult | None:
    if (
        encryption_type in {"KMS", "KMS_DSSE"}
        and kms_key
        and kms_key_manager == "CUSTOMER"
    ):
        return None

    return ECRCustomerManagedKMSResult(
        repository_name=repository_name,
        encryption_type=encryption_type,
        kms_key=kms_key,
        kms_key_manager=kms_key_manager,
    )


def build_ecr_customer_managed_kms_finding(
    result: ECRCustomerManagedKMSResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ECR-004",
        title="ECR Repository Is Not Encrypted With a Customer-Managed KMS Key",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ecr_repository",
        resource_id=result.repository_name,
        description=(
            "The ECR repository is not encrypted with a customer-managed "
            "AWS KMS key."
        ),
        evidence={
            "repository_name": result.repository_name,
            "encryption_type": result.encryption_type,
            "kms_key": result.kms_key,
            "kms_key_manager": result.kms_key_manager,
        },
        remediation=(
            "Create or select a customer-managed AWS KMS key and "
            "configure the ECR repository to use KMS or KMS_DSSE "
            "encryption with that key."
        ),
        compliance=[
            "AWS Security Hub ECR.5",
        ],
    )
