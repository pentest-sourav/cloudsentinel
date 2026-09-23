from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PublicLambdaResourcePolicyResult:
    function_name: str
    statement_id: str | None
    principal: Any
    action: Any
    condition: dict[str, Any]


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value

    return [value]


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


def _has_fixed_source_account(
    condition: dict[str, Any],
) -> bool:
    for operator, values in condition.items():
        if not isinstance(values, dict):
            continue

        for key, value in values.items():
            if key.lower() != "aws:sourceaccount":
                continue

            if not _contains_wildcard_or_variable(value):
                return True

    return False


def _has_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True

    if not isinstance(principal, dict):
        return False

    aws_principal = principal.get("AWS")

    if aws_principal == "*":
        return True

    if isinstance(aws_principal, list) and "*" in aws_principal:
        return True

    return False


def _is_s3_service_principal(principal: Any) -> bool:
    if not isinstance(principal, dict):
        return False

    service = principal.get("Service")

    if service == "s3.amazonaws.com":
        return True

    if isinstance(service, list):
        return "s3.amazonaws.com" in service

    return False


def _action_invokes_lambda(action: Any) -> bool:
    actions = _as_list(action)

    for item in actions:
        if not isinstance(item, str):
            continue

        normalized = item.lower()

        if normalized in {
            "lambda:invokefunction",
            "lambda:*",
            "*",
        }:
            return True

    return False


def _statement_is_public(statement: dict[str, Any]) -> bool:
    if statement.get("Effect") != "Allow":
        return False

    if not _action_invokes_lambda(statement.get("Action")):
        return False

    principal = statement.get("Principal")
    condition = statement.get("Condition", {})

    if not isinstance(condition, dict):
        condition = {}

    if _has_public_principal(principal):
        return not _has_fixed_source_account(condition)

    if _is_s3_service_principal(principal):
        return not _has_fixed_source_account(condition)

    return False


def check_public_lambda_resource_policy(
    function_name: str,
    function_policy: dict[str, Any] | None,
) -> PublicLambdaResourcePolicyResult | None:
    """
    Detect Lambda resource-based policies that allow public invocation.

    The rule evaluates Allow statements that can invoke the Lambda
    function. Wildcard principals are treated as public unless a fixed
    AWS:SourceAccount condition restricts the access.

    S3 service-principal permissions are also considered unsafe when
    they lack a fixed AWS:SourceAccount restriction.
    """
    if not function_policy:
        return None

    statements = function_policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return None

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if not _statement_is_public(statement):
            continue

        return PublicLambdaResourcePolicyResult(
            function_name=function_name,
            statement_id=statement.get("Sid"),
            principal=statement.get("Principal"),
            action=statement.get("Action"),
            condition=statement.get("Condition", {}),
        )

    return None


def build_public_lambda_resource_policy_finding(
    result: PublicLambdaResourcePolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-LAMBDA-002",
        title="Lambda function resource policy allows public access",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="lambda_function",
        resource_id=result.function_name,
        description=(
            "The Lambda function has a resource-based policy statement "
            "that permits invocation from a public or insufficiently "
            "restricted principal."
        ),
        evidence={
            "function_name": result.function_name,
            "statement_id": result.statement_id,
            "principal": result.principal,
            "action": result.action,
            "condition": result.condition,
            "public_access": True,
        },
        remediation=(
            "Remove the public resource-based permission or restrict "
            "the statement to the required AWS account, IAM principal, "
            "service resource, or organization. For service-based "
            "invocation, use appropriate SourceArn and SourceAccount "
            "conditions."
        ),
    )
