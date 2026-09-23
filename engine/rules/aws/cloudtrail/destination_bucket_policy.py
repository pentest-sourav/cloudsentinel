from dataclasses import dataclass
from typing import Any


from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailDestinationBucketPolicyResult:
    bucket_name: str
    trail_arns: list[str]
    policy: dict[str, Any]
    cloudtrail_statement_found: bool
    source_arn_restricted: bool


def _normalize_statements(
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    statements = policy.get(
        "Statement",
        [],
    )

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return []

    return [
        statement
        for statement in statements
        if isinstance(statement, dict)
    ]


def _contains_service_principal(
    principal: Any,
    service_name: str,
) -> bool:
    if isinstance(principal, str):
        return principal == service_name

    if not isinstance(principal, dict):
        return False

    service = principal.get("Service")

    if isinstance(service, str):
        return service == service_name

    if isinstance(service, list):
        return service_name in service

    return False


def _contains_action(
    action: Any,
    required_actions: set[str],
) -> bool:
    if isinstance(action, str):
        return action.lower() in {
            item.lower()
            for item in required_actions
        }

    if isinstance(action, list):
        normalized_actions = {
            item.lower()
            for item in action
            if isinstance(item, str)
        }

        return bool(
            normalized_actions
            & {
                item.lower()
                for item in required_actions
            }
        )

    return False


def _extract_source_arns(
    condition: Any,
) -> list[str]:
    if not isinstance(condition, dict):
        return []

    source_arns: list[str] = []

    for operator_value in condition.values():
        if not isinstance(operator_value, dict):
            continue

        value = operator_value.get(
            "aws:SourceArn",
        )

        if isinstance(value, str):
            source_arns.append(value)

        elif isinstance(value, list):
            source_arns.extend(
                item
                for item in value
                if isinstance(item, str)
            )

    return source_arns


def check_cloudtrail_destination_bucket_policy(
    bucket_name: str,
    trail_arns: list[str],
    policy: dict[str, Any],
) -> CloudTrailDestinationBucketPolicyResult:
    if not isinstance(policy, dict):
        policy = {}

    if not isinstance(trail_arns, list):
        trail_arns = []

    normalized_trail_arns = sorted(
        {
            trail_arn
            for trail_arn in trail_arns
            if isinstance(trail_arn, str)
            and trail_arn
        }
    )

    cloudtrail_statement_found = False
    source_arn_restricted = bool(
        normalized_trail_arns
    )

    covered_trail_arns: set[str] = set()

    cloudtrail_actions = {
        "s3:GetBucketAcl",
        "s3:PutObject",
    }

    for statement in _normalize_statements(policy):
        if statement.get("Effect") != "Allow":
            continue

        if not _contains_service_principal(
            statement.get("Principal"),
            "cloudtrail.amazonaws.com",
        ):
            continue

        if not _contains_action(
            statement.get("Action"),
            cloudtrail_actions,
        ):
            continue

        cloudtrail_statement_found = True

        source_arns = set(
            _extract_source_arns(
                statement.get("Condition"),
            )
        )

        # Every CloudTrail S3 access Allow statement must
        # contain an aws:SourceArn restriction.
        if not source_arns:
            source_arn_restricted = False
            continue

        # Only exact configured CloudTrail trail ARNs count.
        covered_trail_arns.update(
            source_arns.intersection(
                normalized_trail_arns
            )
        )

    if normalized_trail_arns:
        source_arn_restricted = (
            source_arn_restricted
            and covered_trail_arns
            == set(normalized_trail_arns)
        )

    return CloudTrailDestinationBucketPolicyResult(
        bucket_name=bucket_name,
        trail_arns=normalized_trail_arns,
        policy=policy,
        cloudtrail_statement_found=(
            cloudtrail_statement_found
        ),
        source_arn_restricted=source_arn_restricted,
    )


def build_cloudtrail_destination_bucket_policy_finding(
    result: CloudTrailDestinationBucketPolicyResult,
) -> Finding | None:
    if not result.cloudtrail_statement_found:
        return None

    if result.source_arn_restricted:
        return None

    return Finding(
        rule_id="CS-AWS-CT-020",
        title=(
            "CloudTrail destination S3 bucket policy does not "
            "restrict CloudTrail access with aws:SourceArn"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket policy allows the CloudTrail service "
            "principal to access the destination bucket without "
            "restricting the request to the configured CloudTrail "
            "trail ARN or trail ARNs."
        ),
        evidence={
            "bucket_name": result.bucket_name,
            "trail_arns": result.trail_arns,
            "cloudtrail_statement_found": (
                result.cloudtrail_statement_found
            ),
            "source_arn_restricted": (
                result.source_arn_restricted
            ),
            "policy": result.policy,
        },
        remediation=(
            "Add an aws:SourceArn condition to every CloudTrail "
            "S3 access policy statement. Restrict the condition "
            "to the ARN or ARNs of the CloudTrail trails that "
            "use this S3 bucket as their destination."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
