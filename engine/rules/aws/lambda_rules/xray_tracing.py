from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class LambdaXRayTracingResult:
    function_name: str
    tracing_mode: str | None


def _is_xray_unsupported_event_source(
    mapping: dict[str, Any],
) -> bool:
    """
    AWS currently excludes the following event sources from the
    Lambda X-Ray active-tracing control:

    - Amazon MSK
    - self-managed Apache Kafka
    - Amazon MQ
    - Amazon DocumentDB
    """
    if mapping.get("SelfManagedEventSource"):
        return True

    if mapping.get("SelfManagedKafkaEventSourceConfig"):
        return True

    if mapping.get("AmazonManagedKafkaEventSourceConfig"):
        return True

    if mapping.get("DocumentDBEventSourceConfig"):
        return True

    event_source_arn = mapping.get("EventSourceArn")

    if isinstance(event_source_arn, str):
        parts = event_source_arn.split(":")

        if len(parts) > 2:
            service = parts[2].lower()

            if service in {"kafka", "mq", "docdb"}:
                return True

    return False


def check_lambda_xray_tracing(
    function_name: str,
    tracing_mode: str | None,
    event_source_mappings: list[dict[str, Any]],
) -> LambdaXRayTracingResult | None:
    """
    Detect Lambda functions without AWS X-Ray active tracing.

    Functions using event sources for which AWS does not support
    Lambda X-Ray tracing are excluded from this rule.
    """
    if any(
        _is_xray_unsupported_event_source(mapping)
        for mapping in event_source_mappings
        if isinstance(mapping, dict)
    ):
        return None

    if tracing_mode == "Active":
        return None

    return LambdaXRayTracingResult(
        function_name=function_name,
        tracing_mode=tracing_mode,
    )


def build_lambda_xray_tracing_finding(
    result: LambdaXRayTracingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-LAMBDA-006",
        title="Lambda function does not have X-Ray active tracing enabled",
        severity=Severity.LOW,
        provider="aws",
        resource_type="lambda_function",
        resource_id=result.function_name,
        description=(
            "AWS X-Ray active tracing is not enabled for the Lambda "
            "function."
        ),
        evidence={
            "function_name": result.function_name,
            "tracing_mode": result.tracing_mode,
            "xray_active": False,
        },
        remediation=(
            "Enable AWS X-Ray active tracing when tracing is supported "
            "and appropriate for the workload."
        ),
    )
