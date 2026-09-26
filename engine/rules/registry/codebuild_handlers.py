from typing import Any

from scanner.aws.collectors.codebuild import (
    CodeBuildDataCollector,
)


def collect_codebuild_sources(
    collector: CodeBuildDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_source_urls()


def collect_codebuild_credentials(
    collector: CodeBuildDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_environment_credentials()


def collect_codebuild_s3_logs(
    collector: CodeBuildDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_s3_logs()


def collect_codebuild_logging(
    collector: CodeBuildDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_logging_configuration()


def collect_codebuild_report_groups(
    collector: CodeBuildDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_report_group_exports()


CODEBUILD_DATA_SOURCE_HANDLERS = {
    "codebuild_sources": collect_codebuild_sources,
    "codebuild_credentials": collect_codebuild_credentials,
    "codebuild_s3_logs": collect_codebuild_s3_logs,
    "codebuild_logging": collect_codebuild_logging,
    "codebuild_report_groups": (
        collect_codebuild_report_groups
    ),
}
