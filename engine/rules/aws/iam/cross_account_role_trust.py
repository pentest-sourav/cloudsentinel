from dataclasses import dataclass
import re
from typing import Any

from engine.findings.model import Finding, Severity


AWS_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
IAM_ROLE_ARN_PATTERN = re.compile(
    r"^arn:[^:]+:iam::(\d{12}):role/"
)


def _values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]

    if isinstance(value, (list, tuple, set)):
        return [
            item
            for item in value
            if isinstance(item, str)
        ]

    return []


def _extract_external_accounts(
    principal: Any,
    trusted_account_id: str,
) -> list[str]:
    account_ids: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, str):
            normalized = value.strip()

            if AWS_ACCOUNT_ID_PATTERN.fullmatch(normalized):
                if normalized != trusted_account_id:
                    account_ids.append(normalized)
                return

            match = IAM_ROLE_ARN_PATTERN.match(normalized)

            if match and match.group(1) != trusted_account_id:
                account_ids.append(match.group(1))

            return

        if isinstance(value, dict):
            for nested in value.values():
                visit(nested)
            return

        if isinstance(value, (list, tuple, set)):
            for nested in value:
                visit(nested)

    visit(principal)

    return list(dict.fromkeys(account_ids))


def _account_id_from_role_arn(
    role_arn: str | None,
) -> str | None:
    if not isinstance(role_arn, str):
        return None

    match = IAM_ROLE_ARN_PATTERN.match(role_arn)

    if not match:
        return None

    return match.group(1)


def _has_external_id_condition(
    condition: Any,
) -> bool:
    if not isinstance(condition, dict):
        return False

    for operator, values in condition.items():
        if not isinstance(values, dict):
            continue

        for key in values:
            if key.lower() == "sts:externalid":
                return True

    return False


@dataclass(frozen=True)
class CrossAccountRoleTrustResult:
    role_name: str
    role_arn: str
    statement_index: int | None
    effect: str
    principal: Any
    external_account_ids: list[str]
    action: Any
    condition: Any


def check_cross_account_role_trust(
    role_name: str,
    role_arn: str,
    statement_index: int | None,
    effect: str | None,
    principal: Any,
    action: Any,
    condition: Any,
) -> CrossAccountRoleTrustResult | None:
    if effect != "Allow":
        return None

    trusted_account_id = _account_id_from_role_arn(role_arn)

    if trusted_account_id is None:
        return None

    actions = {
        value.strip().lower()
        for value in _values(action)
        if value.strip()
    }

    if (
        "sts:assumerole" not in actions
        and "sts:*" not in actions
        and "*" not in actions
    ):
        return None

    external_accounts = _extract_external_accounts(
        principal,
        trusted_account_id,
    )

    if not external_accounts:
        return None

    if _has_external_id_condition(condition):
        return None

    return CrossAccountRoleTrustResult(
        role_name=role_name,
        role_arn=role_arn,
        statement_index=statement_index,
        effect=effect,
        principal=principal,
        external_account_ids=external_accounts,
        action=action,
        condition=condition,
    )


def build_cross_account_role_trust_finding(
    result: CrossAccountRoleTrustResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-037",
        title="Cross-Account IAM Role Trust Missing External ID",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_role",
        resource_id=result.role_arn,
        description=(
            f"IAM role '{result.role_name}' trusts external "
            "AWS account(s) for sts:AssumeRole without an "
            "sts:ExternalId condition."
        ),
        evidence={
            "role_name": result.role_name,
            "role_arn": result.role_arn,
            "statement_index": result.statement_index,
            "effect": result.effect,
            "principal": result.principal,
            "external_account_ids": (
                result.external_account_ids
            ),
            "action": result.action,
            "condition": result.condition,
            "external_id_present": False,
        },
        remediation=(
            "If the trusted account represents a third-party "
            "service provider, require a unique sts:ExternalId "
            "condition in the role trust policy to help prevent "
            "the confused deputy problem. Verify the integration "
            "requirements before changing an intentional "
            "cross-account trust."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
