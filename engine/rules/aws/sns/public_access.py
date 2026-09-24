from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SNSPublicAccessResult:
    topic_arn: str
    public_access: bool
    public_statements: list[dict[str, Any]]


def _is_allow_statement(statement: dict[str, Any]) -> bool:
    return statement.get("Effect") == "Allow"


def _has_public_principal(statement: dict[str, Any]) -> bool:
    principal = statement.get("Principal")

    if principal == "*":
        return True

    if not isinstance(principal, dict):
        return False

    aws_principal = principal.get("AWS")

    if aws_principal == "*":
        return True

    if isinstance(aws_principal, list):
        return "*" in aws_principal

    return False


def check_sns_public_access(
    topic_arn: str,
    policy: dict,
) -> SNSPublicAccessResult:
    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        statements = []

    public_statements = [
        statement
        for statement in statements
        if isinstance(statement, dict)
        and _is_allow_statement(statement)
        and _has_public_principal(statement)
    ]

    return SNSPublicAccessResult(
        topic_arn=topic_arn,
        public_access=bool(public_statements),
        public_statements=public_statements,
    )


def build_sns_public_access_finding(
    result: SNSPublicAccessResult,
) -> Finding | None:
    if not result.public_access:
        return None

    return Finding(
        rule_id="CS-AWS-SNS-001",
        title="SNS Topic Allows Public Access",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="sns_topic",
        resource_id=result.topic_arn,
        description=(
            "The SNS topic policy contains an Allow statement "
            "with a public Principal."
        ),
        evidence={
            "public_access": result.public_access,
            "public_statements": result.public_statements,
        },
        remediation=(
            "Review the SNS topic policy and remove public principals "
            "unless public access is explicitly required."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
