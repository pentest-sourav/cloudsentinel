from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class VPCFlowLogsResult:
    vpc_id: str
    flow_log_count: int
    active_flow_log_count: int


def check_vpc_flow_logs(
    vpc_id: str,
    flow_log_count: int,
    active_flow_log_count: int,
    flow_logging_enabled: bool,
) -> VPCFlowLogsResult | None:
    if flow_logging_enabled:
        return None

    return VPCFlowLogsResult(
        vpc_id=vpc_id,
        flow_log_count=flow_log_count,
        active_flow_log_count=active_flow_log_count,
    )


def build_vpc_flow_logs_finding(
    result: VPCFlowLogsResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-004",
        title="VPC Flow Logs are not enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="vpc",
        resource_id=result.vpc_id,
        description=(
            "The VPC does not have an active VPC-level Flow Log. "
            "VPC Flow Logs provide visibility into network traffic "
            "and support security monitoring and investigation."
        ),
        evidence={
            "vpc_id": result.vpc_id,
            "flow_log_count": result.flow_log_count,
            "active_flow_log_count": result.active_flow_log_count,
            "flow_logging_enabled": False,
        },
        remediation=(
            "Enable a VPC-level Flow Log and send the flow log data "
            "to an appropriate CloudWatch Logs or Amazon S3 destination "
            "according to your organization's monitoring requirements."
        ),
        compliance=[
            "CIS AWS Foundations Benchmark v5.0.0 / EC2.6",
        ],
    )
