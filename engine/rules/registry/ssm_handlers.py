from typing import Any

from scanner.aws.collectors.ssm import SSMDataCollector


def collect_ssm_ec2_management(
    collector: SSMDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_ec2_management()


def collect_ssm_compliance(
    collector: SSMDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_compliance()


def collect_ssm_document_permissions(
    collector: SSMDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_document_permissions()


def collect_ssm_automation_logging(
    collector: SSMDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_automation_logging()


def collect_ssm_public_sharing_setting(
    collector: SSMDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_public_sharing_setting()


SSM_DATA_SOURCE_HANDLERS = {
    "ssm_ec2_management": collect_ssm_ec2_management,
    "ssm_compliance": collect_ssm_compliance,
    "ssm_document_permissions": collect_ssm_document_permissions,
    "ssm_automation_logging": collect_ssm_automation_logging,
    "ssm_public_sharing_setting": collect_ssm_public_sharing_setting,
}
