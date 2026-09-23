from engine.findings.model import Severity
from engine.rules.aws.vpc.flow_logs import (
    build_vpc_flow_logs_finding,
    check_vpc_flow_logs,
)


def test_vpc_flow_logs_flags_missing_logging():
    result = check_vpc_flow_logs(
        vpc_id="vpc-123",
        flow_log_count=0,
        active_flow_log_count=0,
        flow_logging_enabled=False,
    )

    assert result is not None
    assert result.vpc_id == "vpc-123"


def test_vpc_flow_logs_does_not_flag_active_logging():
    result = check_vpc_flow_logs(
        vpc_id="vpc-123",
        flow_log_count=1,
        active_flow_log_count=1,
        flow_logging_enabled=True,
    )

    assert result is None


def test_vpc_flow_logs_finding():
    result = check_vpc_flow_logs(
        vpc_id="vpc-123",
        flow_log_count=0,
        active_flow_log_count=0,
        flow_logging_enabled=False,
    )

    finding = build_vpc_flow_logs_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-004"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "vpc"
    assert finding.resource_id == "vpc-123"
