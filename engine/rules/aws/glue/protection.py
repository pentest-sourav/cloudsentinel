from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class GlueJobResult:
    job_name: str
    reason: str


@dataclass(frozen=True)
class GlueMLTransformResult:
    transform_id: str
    reason: str


def check_glue_job_tags(
    job_name: str,
    has_non_system_tags: bool,
) -> GlueJobResult | None:
    if not job_name:
        return None

    if has_non_system_tags:
        return None

    return GlueJobResult(
        job_name=job_name,
        reason="missing_non_system_tags",
    )


def build_glue_job_tags_finding(
    result: GlueJobResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-GLUE-001",
        title="AWS Glue Job Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="glue_job",
        resource_id=result.job_name,
        description=(
            f"The AWS Glue job {result.job_name} "
            "does not have any non-system tags."
        ),
        evidence={
            "job_name": result.job_name,
            "configuration_issue": result.reason,
        },
        remediation=(
            "Add at least one non-system tag to the "
            "AWS Glue job. If your organization uses "
            "required tag keys, ensure the job contains "
            "all required keys."
        ),
        compliance=[
            "AWS Security Hub Glue.1",
        ],
    )


def check_glue_ml_transform_encryption(
    transform_id: str,
    encryption_mode: str | None,
) -> GlueMLTransformResult | None:
    if not transform_id or encryption_mode is None:
        return None

    if encryption_mode in {
        "SSEKMS",
        "SSE-KMS",
    }:
        return None

    return GlueMLTransformResult(
        transform_id=transform_id,
        reason=(
            "encryption_at_rest_disabled"
            if encryption_mode == "DISABLED"
            else "encryption_configuration_missing"
        ),
    )


def build_glue_ml_transform_encryption_finding(
    result: GlueMLTransformResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-GLUE-003",
        title=(
            "AWS Glue ML Transform Is Not Encrypted "
            "at Rest"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="glue_ml_transform",
        resource_id=result.transform_id,
        description=(
            f"The AWS Glue machine learning transform "
            f"{result.transform_id} does not have "
            "encryption at rest enabled."
        ),
        evidence={
            "transform_id": result.transform_id,
            "configuration_issue": result.reason,
        },
        remediation=(
            "Configure the Glue ML transform to use "
            "SSE-KMS encryption for user data."
        ),
        compliance=[
            "AWS Security Hub Glue.3",
        ],
    )


SUPPORTED_GLUE_SPARK_VERSIONS = frozenset(
    {
        "3.0",
        "4.0",
        "5.0",
        "5.1",
        "6.0",
    }
)


def check_glue_spark_version(
    job_name: str,
    glue_version: str | None,
    command_name: str | None,
) -> GlueJobResult | None:
    if not job_name:
        return None

    if command_name not in {
        "glueetl",
        "gluestreaming",
    }:
        return None

    if glue_version is None:
        return None

    if glue_version in SUPPORTED_GLUE_SPARK_VERSIONS:
        return None

    return GlueJobResult(
        job_name=job_name,
        reason=f"unsupported_glue_version:{glue_version}",
    )


def build_glue_spark_version_finding(
    result: GlueJobResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-GLUE-004",
        title=(
            "AWS Glue Spark Job Uses an Unsupported "
            "Glue Version"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="glue_job",
        resource_id=result.job_name,
        description=(
            f"The AWS Glue Spark job {result.job_name} "
            f"uses an unsupported Glue version."
        ),
        evidence={
            "job_name": result.job_name,
            "configuration_issue": result.reason,
            "supported_glue_versions": sorted(
                SUPPORTED_GLUE_SPARK_VERSIONS
            ),
        },
        remediation=(
            "Migrate the Glue Spark job to a currently "
            "supported AWS Glue version."
        ),
        compliance=[
            "AWS Security Hub Glue.4",
            "NIST SP 800-53 Rev. 5",
        ],
    )
