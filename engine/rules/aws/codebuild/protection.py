from dataclasses import dataclass


@dataclass(frozen=True)
class CodeBuildSourceResult:
    resource_id: str
    project_name: str
    source_identifier: str | None
    source_location: str | None
    source_type: str


@dataclass(frozen=True)
class CodeBuildCredentialResult:
    resource_id: str
    project_name: str
    variable_name: str
    variable_type: str | None


@dataclass(frozen=True)
class CodeBuildS3LogResult:
    resource_id: str
    project_name: str
    status: str | None
    location: str | None
    encryption_disabled: bool


@dataclass(frozen=True)
class CodeBuildLoggingResult:
    resource_id: str
    project_name: str
    cloudwatch_status: str | None
    s3_status: str | None


@dataclass(frozen=True)
class CodeBuildReportGroupResult:
    resource_id: str
    report_group_name: str | None
    export_config_type: str | None
    bucket: str | None
    encryption_disabled: bool


def _contains_url_userinfo(
    location: str | None,
) -> bool:
    if not isinstance(
        location,
        str,
    ):
        return False

    separator = "://"

    if separator not in location:
        return False

    authority = location.split(
        separator,
        1,
    )[1].split(
        "/",
        1,
    )[0]

    return "@" in authority


def check_source_url_credentials(
    resource_id: str,
    project_name: str,
    source_identifier: str | None,
    source_location: str | None,
    source_type: str,
) -> CodeBuildSourceResult | None:
    if not resource_id:
        return None

    if source_type != "BITBUCKET":
        return None

    if not _contains_url_userinfo(
        source_location
    ):
        return None

    return CodeBuildSourceResult(
        resource_id=resource_id,
        project_name=project_name,
        source_identifier=source_identifier,
        source_location=source_location,
        source_type=source_type,
    )


def check_cleartext_credentials(
    resource_id: str,
    project_name: str,
    variable_name: str,
    variable_type: str | None,
) -> CodeBuildCredentialResult | None:
    if not resource_id:
        return None

    if variable_name not in {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    }:
        return None

    return CodeBuildCredentialResult(
        resource_id=resource_id,
        project_name=project_name,
        variable_name=variable_name,
        variable_type=variable_type,
    )


def check_s3_logs_encryption(
    resource_id: str,
    project_name: str,
    status: str | None,
    location: str | None,
    encryption_disabled: bool,
) -> CodeBuildS3LogResult | None:
    if not resource_id:
        return None

    if status != "ENABLED":
        return None

    if encryption_disabled is not True:
        return None

    return CodeBuildS3LogResult(
        resource_id=resource_id,
        project_name=project_name,
        status=status,
        location=location,
        encryption_disabled=encryption_disabled,
    )


def check_logging_configuration(
    resource_id: str,
    project_name: str,
    cloudwatch_status: str | None,
    s3_status: str | None,
) -> CodeBuildLoggingResult | None:
    if not resource_id:
        return None

    if (
        cloudwatch_status == "ENABLED"
        or s3_status == "ENABLED"
    ):
        return None

    return CodeBuildLoggingResult(
        resource_id=resource_id,
        project_name=project_name,
        cloudwatch_status=cloudwatch_status,
        s3_status=s3_status,
    )


def check_report_group_export_encryption(
    resource_id: str,
    report_group_name: str | None,
    export_config_type: str | None,
    bucket: str | None,
    encryption_disabled: bool,
) -> CodeBuildReportGroupResult | None:
    if not resource_id:
        return None

    if export_config_type != "S3":
        return None

    if encryption_disabled is not True:
        return None

    return CodeBuildReportGroupResult(
        resource_id=resource_id,
        report_group_name=report_group_name,
        export_config_type=export_config_type,
        bucket=bucket,
        encryption_disabled=encryption_disabled,
    )
