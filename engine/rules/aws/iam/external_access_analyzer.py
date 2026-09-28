from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ExternalAccessAnalyzerResult:
    enabled: bool
    analyzer_arns: list[str]


def check_external_access_analyzer(
    external_access_analyzer_enabled: bool,
    analyzer_arns: list[str],
) -> ExternalAccessAnalyzerResult:
    if external_access_analyzer_enabled:
        return ExternalAccessAnalyzerResult(
            enabled=True,
            analyzer_arns=analyzer_arns,
        )

    return ExternalAccessAnalyzerResult(
        enabled=False,
        analyzer_arns=[],
    )


def build_external_access_analyzer_finding(
    result: ExternalAccessAnalyzerResult,
) -> Finding | None:
    if result.enabled:
        return None

    return Finding(
        rule_id="CS-AWS-IAM-045",
        title="IAM Access Analyzer External Access Analyzer Not Enabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="aws_account",
        resource_id="access-analyzer",
        description=(
            "No ACTIVE account-scoped IAM Access Analyzer external "
            "access analyzer is enabled in the current AWS Region."
        ),
        evidence={
            "external_access_analyzer_enabled": False,
            "analyzer_arns": [],
        },
        remediation=(
            "Create and enable an account-scoped IAM Access Analyzer "
            "external access analyzer in this AWS Region."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
