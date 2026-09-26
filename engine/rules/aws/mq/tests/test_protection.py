from engine.findings.model import Severity
from engine.rules.aws.mq.protection import (
    build_mq_active_mq_audit_logs_finding,
    build_mq_activemq_deployment_finding,
    build_mq_rabbitmq_deployment_finding,
    build_mq_tags_finding,
    check_mq_active_mq_audit_logs,
    check_mq_activemq_deployment,
    check_mq_rabbitmq_deployment,
    check_mq_tags,
)


def test_activemq_audit_logging_passes():
    assert (
        check_mq_active_mq_audit_logs(
            "b-1",
            "ACTIVEMQ",
            True,
            "/aws/amazonmq/broker/b-1/audit",
        )
        is None
    )


def test_activemq_audit_logging_fails():
    result = check_mq_active_mq_audit_logs(
        "b-1",
        "ACTIVEMQ",
        False,
        None,
    )

    finding = build_mq_active_mq_audit_logs_finding(result)

    assert finding.rule_id == "CS-AWS-MQ-002"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_id == "b-1"
    assert finding.evidence["logs_audit"] is False


def test_rabbitmq_is_not_evaluated_for_activemq_audit_rule():
    assert (
        check_mq_active_mq_audit_logs(
            "b-1",
            "RABBITMQ",
            False,
            None,
        )
        is None
    )


def test_tagged_broker_passes():
    assert (
        check_mq_tags(
            "b-1",
            [{"Key": "Environment", "Value": "prod"}],
        )
        is None
    )


def test_untagged_broker_fails():
    result = check_mq_tags("b-1", [])

    finding = build_mq_tags_finding(result)

    assert finding.rule_id == "CS-AWS-MQ-004"
    assert finding.severity == Severity.LOW
    assert finding.evidence["tagged"] is False


def test_activemq_active_standby_passes():
    assert (
        check_mq_activemq_deployment(
            "b-1",
            "ACTIVEMQ",
            "ACTIVE_STANDBY_MULTI_AZ",
        )
        is None
    )


def test_activemq_single_instance_fails():
    result = check_mq_activemq_deployment(
        "b-1",
        "ACTIVEMQ",
        "SINGLE_INSTANCE",
    )

    finding = build_mq_activemq_deployment_finding(result)

    assert finding.rule_id == "CS-AWS-MQ-005"
    assert finding.severity == Severity.LOW
    assert finding.evidence["deployment_mode"] == (
        "SINGLE_INSTANCE"
    )


def test_rabbitmq_cluster_passes():
    assert (
        check_mq_rabbitmq_deployment(
            "b-1",
            "RABBITMQ",
            "CLUSTER_MULTI_AZ",
        )
        is None
    )


def test_rabbitmq_single_instance_fails():
    result = check_mq_rabbitmq_deployment(
        "b-1",
        "RABBITMQ",
        "SINGLE_INSTANCE",
    )

    finding = build_mq_rabbitmq_deployment_finding(result)

    assert finding.rule_id == "CS-AWS-MQ-006"
    assert finding.severity == Severity.LOW
    assert finding.evidence["deployment_mode"] == (
        "SINGLE_INSTANCE"
    )
