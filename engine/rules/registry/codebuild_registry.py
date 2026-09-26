from engine.findings.model import Finding, Severity

from engine.rules.aws.codebuild.protection import (
    check_cleartext_credentials,
    check_logging_configuration,
    check_report_group_export_encryption,
    check_s3_logs_encryption,
    check_source_url_credentials,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


def build_codebuild1_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CODEBUILD-001",
        title=(
            "CodeBuild Bitbucket Source URL "
            "Contains Credentials"
        ),
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="codebuild_project",
        resource_id=result.resource_id,
        description=(
            f"CodeBuild project {result.project_name} "
            "has a Bitbucket source repository URL "
            "containing URL user information."
        ),
        evidence={
            "project_name": result.project_name,
            "source_type": result.source_type,
            "source_identifier": (
                result.source_identifier
            ),
            "source_location_contains_credentials": True,
        },
        remediation=(
            "Remove credentials from the Bitbucket "
            "repository URL and configure a supported "
            "secure source authentication mechanism."
        ),
        compliance=[
            "AWS Security Hub CodeBuild.1",
            "NIST SP 800-53 Rev. 5 SA-3",
            "PCI DSS v3.2.1/8.2.1",
            "PCI DSS v4.0.1/8.3.2",
        ],
    )


def build_codebuild2_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CODEBUILD-002",
        title=(
            "CodeBuild Environment Contains "
            "Clear-Text AWS Credentials"
        ),
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="codebuild_project",
        resource_id=result.resource_id,
        description=(
            f"CodeBuild project {result.project_name} "
            f"defines the credential environment "
            f"variable {result.variable_name}."
        ),
        evidence={
            "project_name": result.project_name,
            "variable_name": result.variable_name,
            "variable_type": result.variable_type,
        },
        remediation=(
            "Remove AWS access-key environment variables "
            "from the project and use IAM roles, AWS Systems "
            "Manager Parameter Store, or AWS Secrets Manager "
            "for sensitive configuration."
        ),
        compliance=[
            "AWS Security Hub CodeBuild.2",
            "NIST SP 800-53 Rev. 5 IA-5(7)",
            "NIST SP 800-53 Rev. 5 SA-3",
            "PCI DSS v3.2.1/8.2.1",
            "PCI DSS v4.0.1/8.3.2",
        ],
    )


def build_codebuild3_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CODEBUILD-003",
        title="CodeBuild S3 Logs Are Not Encrypted",
        severity=Severity.LOW,
        provider="aws",
        resource_type="codebuild_project",
        resource_id=result.resource_id,
        description=(
            f"CodeBuild project {result.project_name} "
            "has S3 build logs enabled with encryption "
            "disabled."
        ),
        evidence={
            "project_name": result.project_name,
            "s3_log_status": result.status,
            "s3_log_location": result.location,
            "encryption_disabled": (
                result.encryption_disabled
            ),
        },
        remediation=(
            "Enable encryption for CodeBuild S3 build logs."
        ),
        compliance=[
            "AWS Security Hub CodeBuild.3",
            "NIST SP 800-53 Rev. 5 CA-9(1)",
            "NIST SP 800-53 Rev. 5 CM-3(6)",
            "NIST SP 800-53 Rev. 5 SC-13",
            "NIST SP 800-53 Rev. 5 SC-28",
            "NIST SP 800-53 Rev. 5 SC-28(1)",
            "NIST SP 800-53 Rev. 5 SI-7(6)",
            "PCI DSS v4.0.1/10.3.2",
        ],
    )


def build_codebuild4_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CODEBUILD-004",
        title="CodeBuild Project Logging Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="codebuild_project",
        resource_id=result.resource_id,
        description=(
            f"CodeBuild project {result.project_name} "
            "does not have CloudWatch Logs or S3 build "
            "logs enabled."
        ),
        evidence={
            "project_name": result.project_name,
            "cloudwatch_status": (
                result.cloudwatch_status
            ),
            "s3_status": result.s3_status,
        },
        remediation=(
            "Enable at least one CodeBuild project logging "
            "destination: CloudWatch Logs or S3."
        ),
        compliance=[
            "AWS Security Hub CodeBuild.4",
            "NIST SP 800-53 Rev. 5 AC-2(12)",
            "NIST SP 800-53 Rev. 5 AC-2(4)",
            "NIST SP 800-53 Rev. 5 AC-4(26)",
            "NIST SP 800-53 Rev. 5 AC-6(9)",
            "NIST SP 800-53 Rev. 5 AU-10",
            "NIST SP 800-53 Rev. 5 AU-12",
            "NIST SP 800-53 Rev. 5 AU-2",
            "NIST SP 800-53 Rev. 5 AU-3",
            "NIST SP 800-53 Rev. 5 AU-6(3)",
            "NIST SP 800-53 Rev. 5 AU-6(4)",
            "NIST SP 800-53 Rev. 5 AU-9(7)",
            "NIST SP 800-53 Rev. 5 CA-7",
            "NIST SP 800-53 Rev. 5 SC-7(9)",
            "NIST SP 800-53 Rev. 5 SI-3(8)",
            "NIST SP 800-53 Rev. 5 SI-4",
            "NIST SP 800-53 Rev. 5 SI-4(20)",
            "NIST SP 800-53 Rev. 5 SI-7(8)",
        ],
    )


def build_codebuild7_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CODEBUILD-005",
        title=(
            "CodeBuild Report Group S3 Export "
            "Is Not Encrypted"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="codebuild_report_group",
        resource_id=result.resource_id,
        description=(
            f"CodeBuild report group "
            f"{result.report_group_name!r} exports "
            "results to S3 with encryption disabled."
        ),
        evidence={
            "report_group_name": (
                result.report_group_name
            ),
            "export_config_type": (
                result.export_config_type
            ),
            "bucket": result.bucket,
            "encryption_disabled": (
                result.encryption_disabled
            ),
        },
        remediation=(
            "Enable encryption for the report group's "
            "S3 export configuration."
        ),
        compliance=[
            "AWS Security Hub CodeBuild.7",
        ],
    )


CODEBUILD_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-CODEBUILD-001",
            name=(
                "CodeBuild Bitbucket source URLs "
                "should not contain credentials"
            ),
            data_source="codebuild_sources",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "project_name",
                "source_identifier",
                "source_location",
                "source_type",
            ],
            check=check_source_url_credentials,
            build_finding=build_codebuild1_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CODEBUILD-002",
            name=(
                "CodeBuild environment should not "
                "contain clear-text AWS credentials"
            ),
            data_source="codebuild_credentials",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "project_name",
                "variable_name",
                "variable_type",
            ],
            check=check_cleartext_credentials,
            build_finding=build_codebuild2_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CODEBUILD-003",
            name=(
                "CodeBuild S3 logs should be encrypted"
            ),
            data_source="codebuild_s3_logs",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "project_name",
                "status",
                "location",
                "encryption_disabled",
            ],
            check=check_s3_logs_encryption,
            build_finding=build_codebuild3_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CODEBUILD-004",
            name=(
                "CodeBuild projects should have "
                "logging configured"
            ),
            data_source="codebuild_logging",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "project_name",
                "cloudwatch_status",
                "s3_status",
            ],
            check=check_logging_configuration,
            build_finding=build_codebuild4_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CODEBUILD-005",
            name=(
                "CodeBuild report-group S3 exports "
                "should be encrypted"
            ),
            data_source="codebuild_report_groups",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "report_group_name",
                "export_config_type",
                "bucket",
                "encryption_disabled",
            ],
            check=check_report_group_export_encryption,
            build_finding=build_codebuild7_finding,
        ),
    ]
)
