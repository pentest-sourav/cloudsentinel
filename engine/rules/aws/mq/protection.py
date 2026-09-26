from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class MQResult:
    resource_id: str
    resource_type: str
    details: dict


def check_mq_active_mq_audit_logs(
    resource_id: str,
    engine_type: str | None,
    logs_audit: bool | None,
    audit_log_group: str | None,
) -> MQResult | None:
    if not resource_id:
        return None

    if engine_type != "ACTIVEMQ":
        return None

    if logs_audit is True and isinstance(
        audit_log_group,
        str,
    ) and audit_log_group:
        return None

    return MQResult(
        resource_id=resource_id,
        resource_type="amazonmq_broker",
        details={
            "engine_type": engine_type,
            "logs_audit": logs_audit,
            "audit_log_group": audit_log_group,
        },
    )


def build_mq_active_mq_audit_logs_finding(
    result: MQResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MQ-002",
        title=(
            "Amazon MQ ActiveMQ broker does not "
            "stream audit logs to CloudWatch"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The ActiveMQ broker {result.resource_id} "
            "does not have audit logging enabled and "
            "streamed to an Amazon CloudWatch Logs "
            "audit log group."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable ActiveMQ audit logging and configure "
            "the broker to publish audit logs to "
            "Amazon CloudWatch Logs."
        ),
        compliance=[
            "AWS Security Hub MQ.2",
            "NIST SP 800-53 Rev. 5 AU-2",
            "NIST SP 800-53 Rev. 5 AU-3",
            "NIST SP 800-53 Rev. 5 AU-12",
            "NIST SP 800-53 Rev. 5 SI-4",
            "PCI DSS v4.0.1/10.3.3",
        ],
    )


def check_mq_tags(
    resource_id: str,
    tags: list[dict[str, str]],
) -> MQResult | None:
    if not resource_id:
        return None

    if isinstance(tags, list) and any(
        isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and bool(tag.get("Key"))
        for tag in tags
    ):
        return None

    return MQResult(
        resource_id=resource_id,
        resource_type="amazonmq_broker",
        details={
            "tags": tags,
            "tagged": False,
        },
    )


def build_mq_tags_finding(
    result: MQResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MQ-004",
        title="Amazon MQ broker is not tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Amazon MQ broker {result.resource_id} "
            "does not have any non-system tags."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Apply meaningful non-system tags to the "
            "Amazon MQ broker for ownership, inventory, "
            "and operational tracking."
        ),
        compliance=[
            "AWS Security Hub MQ.4",
            "AWS Resource Tagging Standard",
        ],
    )


def check_mq_activemq_deployment(
    resource_id: str,
    engine_type: str | None,
    deployment_mode: str | None,
) -> MQResult | None:
    if not resource_id:
        return None

    if engine_type != "ACTIVEMQ":
        return None

    if deployment_mode == "ACTIVE_STANDBY_MULTI_AZ":
        return None

    return MQResult(
        resource_id=resource_id,
        resource_type="amazonmq_broker",
        details={
            "engine_type": engine_type,
            "deployment_mode": deployment_mode,
        },
    )


def build_mq_activemq_deployment_finding(
    result: MQResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MQ-005",
        title=(
            "Amazon MQ ActiveMQ broker does not use "
            "active/standby deployment mode"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The ActiveMQ broker {result.resource_id} "
            "is not configured with "
            "ACTIVE_STANDBY_MULTI_AZ deployment mode."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Use ACTIVE_STANDBY_MULTI_AZ deployment mode "
            "for the ActiveMQ broker."
        ),
        compliance=[
            "AWS Security Hub MQ.5",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_mq_rabbitmq_deployment(
    resource_id: str,
    engine_type: str | None,
    deployment_mode: str | None,
) -> MQResult | None:
    if not resource_id:
        return None

    if engine_type != "RABBITMQ":
        return None

    if deployment_mode == "CLUSTER_MULTI_AZ":
        return None

    return MQResult(
        resource_id=resource_id,
        resource_type="amazonmq_broker",
        details={
            "engine_type": engine_type,
            "deployment_mode": deployment_mode,
        },
    )


def build_mq_rabbitmq_deployment_finding(
    result: MQResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-MQ-006",
        title=(
            "Amazon MQ RabbitMQ broker does not use "
            "cluster deployment mode"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The RabbitMQ broker {result.resource_id} "
            "is not configured with "
            "CLUSTER_MULTI_AZ deployment mode."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Use CLUSTER_MULTI_AZ deployment mode "
            "for the RabbitMQ broker."
        ),
        compliance=[
            "AWS Security Hub MQ.6",
            "NIST SP 800-53 Rev. 5",
        ],
    )
