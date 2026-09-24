from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SQSPublicAccessResult:
    queue_arn: str
    public_access: bool
    public_statements: list[dict[str, Any]]


def _is_allow_statement(statement: dict[str, Any]) -> bool:
    return statement.get("Effect") == "Allow"


def _has_public_principal(
    statement: dict[str, Any],
) -> bool:
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


def _contains_wildcard_or_variable(value: Any) -> bool:
    if isinstance(value, str):
        return "*" in value or "${" in value

    if isinstance(value, list):
        return any(
            _contains_wildcard_or_variable(item)
            for item in value
        )

    if isinstance(value, dict):
        return any(
            _contains_wildcard_or_variable(item)
            for item in value.values()
        )

    return False


def _has_unsafe_conditions(
    statement: dict[str, Any],
) -> bool:
    condition = statement.get("Condition")

    if condition is None:
        return True

    if not isinstance(condition, dict):
        return True

    return _contains_wildcard_or_variable(condition)


def _is_public_statement(
    statement: dict[str, Any],
) -> bool:
    if not _is_allow_statement(statement):
        return False

    if not _has_public_principal(statement):
        return False

    return _has_unsafe_conditions(statement)


def check_sqs_public_access(
    queue_arn: str,
    policy: dict[str, Any],
) -> SQSPublicAccessResult:
    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        statements = []

    public_statements = [
        statement
        for statement in statements
        if isinstance(statement, dict)
        and _is_public_statement(statement)
    ]

    return SQSPublicAccessResult(
        queue_arn=queue_arn,
        public_access=bool(public_statements),
        public_statements=public_statements,
    )


def build_sqs_public_access_finding(
    result: SQSPublicAccessResult,
) -> Finding | None:
    if not result.public_access:
        return None

    return Finding(
        rule_id="CS-AWS-SQS-003",
        title="SQS Queue Allows Public Access",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="sqs_queue",
        resource_id=result.queue_arn,
        description=(
            "The SQS queue access policy contains an Allow statement "
            "with a public principal and no sufficiently restrictive "
            "fixed-value conditions."
        ),
        evidence={
            "public_access": result.public_access,
            "public_statements": result.public_statements,
        },
        remediation=(
            "Review the SQS queue access policy and replace public "
            "principals with explicitly authorized principals and "
            "fixed-value conditions where cross-account or service "
            "access is required."
        ),
        compliance=[
            "AWS Security Hub SQS.3",
        ],
    )
