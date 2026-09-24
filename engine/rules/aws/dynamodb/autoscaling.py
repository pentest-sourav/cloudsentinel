from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DynamoDBAutoscalingResult:
    table_arn: str
    table_name: str
    billing_mode: str | None
    autoscaling_enabled: bool
    scalable_targets: dict[str, list[dict[str, Any]]]
    scaling_policies: dict[str, list[dict[str, Any]]]


def check_dynamodb_autoscaling(
    table_arn: str,
    table_name: str,
    billing_mode: str | None,
    autoscaling_enabled: bool,
    scalable_targets: dict[str, list[dict[str, Any]]],
    scaling_policies: dict[str, list[dict[str, Any]]],
) -> DynamoDBAutoscalingResult:
    return DynamoDBAutoscalingResult(
        table_arn=table_arn,
        table_name=table_name,
        billing_mode=billing_mode,
        autoscaling_enabled=autoscaling_enabled,
        scalable_targets=scalable_targets,
        scaling_policies=scaling_policies,
    )


def build_dynamodb_autoscaling_finding(
    result: DynamoDBAutoscalingResult,
) -> Finding | None:
    if result.autoscaling_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-DYNAMODB-001",
        title="DynamoDB Table Does Not Automatically Scale With Demand",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="dynamodb_table",
        resource_id=result.table_arn,
        description=(
            "The DynamoDB table is not configured for on-demand "
            "capacity or provisioned capacity with read and write "
            "auto scaling."
        ),
        evidence={
            "table_name": result.table_name,
            "billing_mode": result.billing_mode,
            "autoscaling_enabled": result.autoscaling_enabled,
            "scalable_targets": result.scalable_targets,
            "scaling_policies": result.scaling_policies,
        },
        remediation=(
            "Configure the DynamoDB table to use on-demand capacity "
            "or configure auto scaling for both read and write "
            "capacity when using provisioned capacity."
        ),
        compliance=[
            "AWS Security Hub DynamoDB.1",
        ],
    )
