from dataclasses import dataclass
import re
from typing import Any

from engine.findings.model import Finding, Severity


AWS_ACCOUNT_ID_PATTERN = re.compile(
    r"^\d{12}$"
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


def _extract_account_ids(
    principal: Any,
) -> list[str]:
    account_ids: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, str):
            normalized = value.strip()

            if AWS_ACCOUNT_ID_PATTERN.fullmatch(
                normalized
            ):
                account_ids.append(normalized)
                return

            match = re.match(
                r"^arn:[^:]+:iam::(\d{12}):",
                normalized,
            )

            if match:
                account_ids.append(
                    match.group(1)
                )

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

    match = re.match(
        r"^arn:[^:]+:iam::(\d{12}):role/",
        role_arn,
    )

    if not match:
        return None

    return match.group(1)


@dataclass(frozen=True)
class CrossAccountTrustResult:
    role_name: str
    role_arn: str
    statement_index: int | None
    effect: str
    principal: Any
    external_account_id: str
    action: Any
    condition: Any


def check_cross_account_trust_without_condition(
    role_name: str,
    role_arn: str,
    statement_index: int | None,
    effect: str | None,
    principal: Any,
    action: Any,
    condition: Any,
) -> CrossAccountTrustResult | None:
    if effect != "Allow":
        return None

    role_account_id = _account_id_from_role_arn(
        role_arn
    )

    if role_account_id is None:
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

    external_accounts = [
        account_id
        for account_id in _extract_account_ids(
            principal
        )
        if account_id != role_account_id
    ]

    if not external_accounts:
        return None

    if condition:
        return None

    return CrossAccountTrustResult(
        role_name=role_name,
        role_arn=role_arn,
        statement_index=statement_index,
        effect=effect,
        principal=principal,
        external_account_id=external_accounts[0],
        action=action,
        condition=condition,
    )


def build_cross_account_trust_without_condition_finding(
    result: CrossAccountTrustResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-035",
        title="Cross-Account IAM Role Trust Has No Condition",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_role",
        resource_id=result.role_arn,
        description=(
            f"IAM role '{result.role_name}' trusts external "
            f"AWS account '{result.external_account_id}' for "
            f"sts:AssumeRole without a Condition restriction."
        ),
        evidence={
            "role_name": result.role_name,
            "role_arn": result.role_arn,
            "statement_index": result.statement_index,
            "effect": result.effect,
            "principal": result.principal,
            "external_account_id": (
                result.external_account_id
            ),
            "action": result.action,
            "condition": result.condition,
            "condition_present": bool(result.condition),
        },
        remediation=(
            "Review whether the cross-account trust is required. "
            "If it is intentional, restrict the trust with appropriate "
            "conditions and narrowly scoped principals where supported. "
            "For service-integrated or delegated access, use the "
            "condition keys recommended for that integration."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
