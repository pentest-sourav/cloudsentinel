from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SSMEC2ManagementResult:
    resource_id: str
    instance_state: str | None
    managed_by_ssm: bool


@dataclass(frozen=True)
class SSMComplianceResult:
    resource_id: str
    compliance_type: str
    status: str | None
    overall_severity: str | None
    execution_summary: Any


@dataclass(frozen=True)
class SSMDocumentPublicResult:
    resource_id: str
    document_name: str
    owner: str | None
    account_ids: list[str]
    public: bool


@dataclass(frozen=True)
class SSMSettingResult:
    resource_id: str
    setting_id: str
    setting_value: str | None
    status: str | None


def check_ec2_managed_by_ssm(
    resource_id: str,
    instance_state: str | None,
    managed_by_ssm: bool,
) -> SSMEC2ManagementResult | None:
    if not resource_id:
        return None

    if managed_by_ssm is True:
        return None

    return SSMEC2ManagementResult(
        resource_id=resource_id,
        instance_state=instance_state,
        managed_by_ssm=managed_by_ssm,
    )


def check_patch_compliance(
    resource_id: str,
    compliance_type: str,
    status: str | None,
    overall_severity: str | None,
    execution_summary: Any,
) -> SSMComplianceResult | None:
    if not resource_id:
        return None

    if compliance_type != "Patch":
        return None

    if status == "COMPLIANT":
        return None

    return SSMComplianceResult(
        resource_id=resource_id,
        compliance_type=compliance_type,
        status=status,
        overall_severity=overall_severity,
        execution_summary=execution_summary,
    )


def check_association_compliance(
    resource_id: str,
    compliance_type: str,
    status: str | None,
    overall_severity: str | None,
    execution_summary: Any,
) -> SSMComplianceResult | None:
    if not resource_id:
        return None

    if compliance_type != "Association":
        return None

    if status == "COMPLIANT":
        return None

    return SSMComplianceResult(
        resource_id=resource_id,
        compliance_type=compliance_type,
        status=status,
        overall_severity=overall_severity,
        execution_summary=execution_summary,
    )


def check_document_not_public(
    resource_id: str,
    document_name: str,
    owner: str | None,
    account_ids: list[str],
    public: bool,
) -> SSMDocumentPublicResult | None:
    if not resource_id:
        return None

    if public is False:
        return None

    return SSMDocumentPublicResult(
        resource_id=resource_id,
        document_name=document_name,
        owner=owner,
        account_ids=account_ids,
        public=public,
    )


def check_automation_logging(
    resource_id: str,
    setting_id: str,
    setting_value: str | None,
    status: str | None,
) -> SSMSettingResult | None:
    if not resource_id:
        return None

    if (
        isinstance(setting_value, str)
        and setting_value.lower() == "cloudwatch"
    ):
        return None

    return SSMSettingResult(
        resource_id=resource_id,
        setting_id=setting_id,
        setting_value=setting_value,
        status=status,
    )


def check_public_sharing_block(
    resource_id: str,
    setting_id: str,
    setting_value: str | None,
    status: str | None,
) -> SSMSettingResult | None:
    if not resource_id:
        return None

    if (
        isinstance(setting_value, str)
        and setting_value.lower() == "disable"
    ):
        return None

    return SSMSettingResult(
        resource_id=resource_id,
        setting_id=setting_id,
        setting_value=setting_value,
        status=status,
    )
