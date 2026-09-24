from dataclasses import dataclass

from engine.findings.model import Finding, Severity


DELIVERY_STATUS_ROLE_ATTRIBUTES = (
    "HTTPFailureFeedbackRoleArn",
    "HTTPSuccessFeedbackRoleArn",
    "LambdaFailureFeedbackRoleArn",
    "LambdaSuccessFeedbackRoleArn",
    "SQSFailureFeedbackRoleArn",
    "SQSSuccessFeedbackRoleArn",
    "FirehoseFailureFeedbackRoleArn",
    "FirehoseSuccessFeedbackRoleArn",
)


@dataclass(frozen=True)
class SNSDeliveryStatusResult:
    topic_arn: str
    logging_configured: bool
    configured_protocols: list[str]


def check_sns_delivery_status(
    topic_arn: str,
    attributes: dict,
) -> SNSDeliveryStatusResult:
    configured_protocols = []

    protocol_prefixes = {
        "HTTP": (
            "HTTPFailureFeedbackRoleArn",
            "HTTPSuccessFeedbackRoleArn",
        ),
        "Lambda": (
            "LambdaFailureFeedbackRoleArn",
            "LambdaSuccessFeedbackRoleArn",
        ),
        "SQS": (
            "SQSFailureFeedbackRoleArn",
            "SQSSuccessFeedbackRoleArn",
        ),
        "Firehose": (
            "FirehoseFailureFeedbackRoleArn",
            "FirehoseSuccessFeedbackRoleArn",
        ),
    }

    for protocol, role_attributes in protocol_prefixes.items():
        if any(attributes.get(attribute) for attribute in role_attributes):
            configured_protocols.append(protocol)

    return SNSDeliveryStatusResult(
        topic_arn=topic_arn,
        logging_configured=bool(configured_protocols),
        configured_protocols=configured_protocols,
    )


def build_sns_delivery_status_finding(
    result: SNSDeliveryStatusResult,
) -> Finding | None:
    if result.logging_configured:
        return None

    return Finding(
        rule_id="CS-AWS-SNS-003",
        title="SNS Delivery Status Logging Not Configured",
        severity=Severity.LOW,
        provider="aws",
        resource_type="sns_topic",
        resource_id=result.topic_arn,
        description=(
            "The SNS topic does not have delivery-status logging "
            "configured for supported delivery protocols."
        ),
        evidence={
            "logging_configured": result.logging_configured,
            "configured_protocols": result.configured_protocols,
        },
        remediation=(
            "Configure SNS delivery-status logging where delivery "
            "observability is required."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
