from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AppFlowResourceResult:
    flow_name: str
    flow_arn: str
    reason: str
    evidence: dict


def check_appflow_flow_tags(
    flow_name: str,
    flow_arn: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
) -> AppFlowResourceResult | None:
    if not flow_name or not flow_arn:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return AppFlowResourceResult(
        flow_name=flow_name,
        flow_arn=flow_arn,
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def build_appflow_flow_tags_finding(
    result: AppFlowResourceResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-APPFLOW-001",
        title="AppFlow Flow Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="appflow_flow",
        resource_id=result.flow_arn,
        description=(
            f"Amazon AppFlow flow {result.flow_name} "
            "does not have any non-system tags."
        ),
        evidence={
            "flow_name": result.flow_name,
            "flow_arn": result.flow_arn,
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=(
            "Add the required organizational tags to the "
            "Amazon AppFlow flow. CloudSentinel evaluates "
            "baseline presence of at least one non-system "
            "tag; Security Hub AppFlow.1 can additionally "
            "enforce configured requiredKeyTags."
        ),
        compliance=[
            "AWS Security Hub AppFlow.1",
        ],
    )
