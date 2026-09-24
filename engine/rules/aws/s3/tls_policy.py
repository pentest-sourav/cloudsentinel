from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3TLSRequiredResult:
    bucket_name: str
    tls_required: bool
    policy: dict[str, Any]


def _matches_star_principal(principal: Any) -> bool:
    if principal == "*":
        return True

    if isinstance(principal, dict):
        aws_principal = principal.get("AWS")

        if aws_principal == "*":
            return True

        if isinstance(aws_principal, list):
            return "*" in aws_principal

    return False


def _matches_s3_all_actions(action: Any) -> bool:
    if action == "s3:*":
        return True

    if isinstance(action, list):
        return "s3:*" in action

    return False


def _matches_secure_transport_false(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False

    for operator, values in condition.items():
        if str(operator).lower() != "bool":
            continue

        if not isinstance(values, dict):
            continue

        for key, value in values.items():
            if str(key).lower() != "aws:securetransport":
                continue

            if isinstance(value, list):
                return any(
                    str(item).lower() == "false"
                    for item in value
                )

            return str(value).lower() == "false"

    return False


def _statement_requires_tls(statement: Any) -> bool:
    if not isinstance(statement, dict):
        return False

    if str(statement.get("Effect", "")).lower() != "deny":
        return False

    if not _matches_star_principal(
        statement.get("Principal")
    ):
        return False

    if not _matches_s3_all_actions(
        statement.get("Action")
    ):
        return False

    return _matches_secure_transport_false(
        statement.get("Condition")
    )


def check_s3_tls_policy(
    bucket_name: str,
    policy: dict[str, Any],
) -> S3TLSRequiredResult:
    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    tls_required = any(
        _statement_requires_tls(statement)
        for statement in statements
    )

    return S3TLSRequiredResult(
        bucket_name=bucket_name,
        tls_required=tls_required,
        policy=policy,
    )


def build_s3_tls_policy_finding(
    result: S3TLSRequiredResult,
) -> Finding | None:
    if result.tls_required:
        return None

    return Finding(
        rule_id="CS-AWS-S3-009",
        title="S3 Bucket Does Not Require TLS",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket policy does not contain a deny statement "
            "that prevents non-TLS requests. Requests to the bucket "
            "may therefore be transmitted without HTTPS enforcement."
        ),
        evidence={
            "tls_required": result.tls_required,
            "policy": result.policy,
        },
        remediation=(
            "Update the S3 bucket policy to deny requests when "
            "aws:SecureTransport is false. Apply the deny to "
            "S3 actions for all principals."
        ),
        compliance=[
            "CIS AWS Foundations 5.0.0/2.1.1",
        ],
    )
