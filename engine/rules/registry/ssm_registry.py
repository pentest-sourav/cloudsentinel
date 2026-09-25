from engine.findings.model import Finding, Severity
from engine.rules.aws.ssm.protection import (
    check_association_compliance,
    check_automation_logging,
    check_document_not_public,
    check_ec2_managed_by_ssm,
    check_patch_compliance,
    check_public_sharing_block,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


def build_ssm1_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SSM-001",
        title=(
            "EC2 Instance Is Not Managed by "
            "AWS Systems Manager"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ec2_instance",
        resource_id=result.resource_id,
        description=(
            f"EC2 instance {result.resource_id} "
            f"is in the {result.instance_state!r} "
            "state but is not managed by AWS "
            "Systems Manager."
        ),
        evidence={
            "instance_id": result.resource_id,
            "instance_state": result.instance_state,
            "managed_by_ssm": result.managed_by_ssm,
        },
        remediation=(
            "Configure the EC2 instance as a Systems "
            "Manager managed node, including the required "
            "SSM Agent and IAM permissions."
        ),
        compliance=[
            "AWS Security Hub SSM.1",
        ],
    )


def build_ssm2_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SSM-002",
        title=(
            "SSM Patch Compliance Is Non-Compliant"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ssm_patch_compliance",
        resource_id=result.resource_id,
        description=(
            f"Systems Manager patch compliance for "
            f"{result.resource_id} is "
            f"{result.status!r} instead of COMPLIANT."
        ),
        evidence={
            "resource_id": result.resource_id,
            "compliance_type": result.compliance_type,
            "status": result.status,
            "overall_severity": result.overall_severity,
            "execution_summary": result.execution_summary,
        },
        remediation=(
            "Review the instance's patch compliance "
            "status and remediate non-compliant patches "
            "using Systems Manager Patch Manager."
        ),
        compliance=[
            "AWS Security Hub SSM.2",
        ],
    )


def build_ssm3_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SSM-003",
        title=(
            "SSM Association Compliance Is "
            "Non-Compliant"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type="ssm_association_compliance",
        resource_id=result.resource_id,
        description=(
            f"Systems Manager association compliance "
            f"for {result.resource_id} is "
            f"{result.status!r} instead of COMPLIANT."
        ),
        evidence={
            "resource_id": result.resource_id,
            "compliance_type": result.compliance_type,
            "status": result.status,
            "overall_severity": result.overall_severity,
            "execution_summary": result.execution_summary,
        },
        remediation=(
            "Review the failed Systems Manager State "
            "Manager associations and restore the "
            "required association compliance state."
        ),
        compliance=[
            "AWS Security Hub SSM.3",
        ],
    )


def build_ssm4_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SSM-004",
        title=(
            "SSM Document Is Publicly Shared"
        ),
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="ssm_document",
        resource_id=result.resource_id,
        description=(
            f"SSM document {result.document_name} "
            "is publicly shared."
        ),
        evidence={
            "document_name": result.document_name,
            "owner": result.owner,
            "account_ids": result.account_ids,
            "public": result.public,
        },
        remediation=(
            "Remove public sharing permissions from "
            "the SSM document unless public sharing "
            "is explicitly required."
        ),
        compliance=[
            "AWS Security Hub SSM.4",
        ],
    )


def build_ssm6_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SSM-005",
        title=(
            "SSM Automation CloudWatch Logging "
            "Is Not Enabled"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ssm_account_setting",
        resource_id=result.resource_id,
        description=(
            "SSM Automation customer script logging "
            "is not configured to use CloudWatch Logs."
        ),
        evidence={
            "setting_id": result.setting_id,
            "setting_value": result.setting_value,
            "status": result.status,
        },
        remediation=(
            "Configure the SSM Automation customer "
            "script log destination to CloudWatch."
        ),
        compliance=[
            "AWS Security Hub SSM.6",
        ],
    )


def build_ssm7_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SSM-006",
        title=(
            "SSM Document Public Sharing "
            "Protection Is Disabled"
        ),
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="ssm_account_setting",
        resource_id=result.resource_id,
        description=(
            "The SSM document block-public-sharing "
            "setting is not enabled."
        ),
        evidence={
            "setting_id": result.setting_id,
            "setting_value": result.setting_value,
            "status": result.status,
        },
        remediation=(
            "Set the SSM document public-sharing "
            "permission setting to Disable so that "
            "public sharing is blocked."
        ),
        compliance=[
            "AWS Security Hub SSM.7",
        ],
    )


SSM_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-SSM-001",
            name=(
                "EC2 instances should be managed "
                "by AWS Systems Manager"
            ),
            data_source="ssm_ec2_management",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "instance_state",
                "managed_by_ssm",
            ],
            check=check_ec2_managed_by_ssm,
            build_finding=build_ssm1_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SSM-002",
            name=(
                "SSM patch compliance should "
                "be COMPLIANT"
            ),
            data_source="ssm_compliance",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "compliance_type",
                "status",
                "overall_severity",
                "execution_summary",
            ],
            check=check_patch_compliance,
            build_finding=build_ssm2_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SSM-003",
            name=(
                "SSM association compliance "
                "should be COMPLIANT"
            ),
            data_source="ssm_compliance",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "compliance_type",
                "status",
                "overall_severity",
                "execution_summary",
            ],
            check=check_association_compliance,
            build_finding=build_ssm3_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SSM-004",
            name=(
                "SSM documents should not "
                "be public"
            ),
            data_source="ssm_document_permissions",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "document_name",
                "owner",
                "account_ids",
                "public",
            ],
            check=check_document_not_public,
            build_finding=build_ssm4_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SSM-005",
            name=(
                "SSM Automation should have "
                "CloudWatch logging enabled"
            ),
            data_source="ssm_automation_logging",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "setting_id",
                "setting_value",
                "status",
            ],
            check=check_automation_logging,
            build_finding=build_ssm6_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SSM-006",
            name=(
                "SSM documents should have "
                "block public sharing enabled"
            ),
            data_source="ssm_public_sharing_setting",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "setting_id",
                "setting_value",
                "status",
            ],
            check=check_public_sharing_block,
            build_finding=build_ssm7_finding,
        ),
    ]
)
