from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class LambdaTaggingResult:
    function_name: str
    function_arn: str
    tags: dict[str, str]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | None,
) -> list[str]:
    if not isinstance(required_tag_keys, list):
        return []

    result = []

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue
        key = key.strip()
        if not key or key.lower().startswith("aws:"):
            continue
        if key not in result:
            result.append(key)

    return result


def check_lambda_tagging(
    function_name: str,
    function_arn: str,
    tags: dict[str, str],
    required_tag_keys: list[str] | None = None,
) -> LambdaTaggingResult | None:
    required = _normalize_required_tag_keys(required_tag_keys)

    present = {
        key
        for key in tags
        if isinstance(key, str)
        and not key.lower().startswith("aws:")
    }

    missing = [key for key in required if key not in present]

    if required and not missing:
        return None

    if not required and present:
        return None

    return LambdaTaggingResult(
        function_name=function_name,
        function_arn=function_arn,
        tags=tags,
        required_tag_keys=required,
        missing_tag_keys=missing,
    )


def build_lambda_tagging_finding(
    result: LambdaTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-LAMBDA-009",
        title="Lambda Function Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="lambda_function",
        resource_id=result.function_arn,
        description=(
            "The Lambda function does not satisfy the configured "
            "tagging requirements."
        ),
        evidence={
            "function_name": result.function_name,
            "function_arn": result.function_arn,
            "tags": result.tags,
            "required_tag_keys": result.required_tag_keys,
            "missing_tag_keys": result.missing_tag_keys,
        },
        remediation=(
            "Add the missing required tag keys using "
            "case-sensitive matching."
            if result.required_tag_keys
            else
            "Add at least one appropriate non-system tag."
        ),
        compliance=["AWS Security Hub Lambda.6"],
    )
