from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ElasticBeanstalkResult:
    resource_id: str
    resource_type: str
    details: dict


def check_enhanced_health_reporting(
    resource_id: str,
    enhanced_health_reporting: bool,
) -> ElasticBeanstalkResult | None:
    if not resource_id:
        return None

    if enhanced_health_reporting:
        return None

    return ElasticBeanstalkResult(
        resource_id=resource_id,
        resource_type="elasticbeanstalk_environment",
        details={
            "enhanced_health_reporting": (
                enhanced_health_reporting
            ),
        },
    )


def build_enhanced_health_reporting_finding(
    result: ElasticBeanstalkResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELASTICBEANSTALK-001",
        title=(
            "Elastic Beanstalk enhanced health reporting "
            "is not enabled"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Elastic Beanstalk environment "
            f"{result.resource_id} does not have enhanced "
            "health reporting enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable enhanced health reporting for the "
            "Elastic Beanstalk environment."
        ),
        compliance=[
            "AWS Security Hub ElasticBeanstalk.1",
            "NIST SP 800-53 Rev. 5 CA-7",
            "NIST SP 800-53 Rev. 5 SI-2",
        ],
    )


def check_managed_platform_updates(
    resource_id: str,
    managed_actions_enabled: bool,
    managed_update_level: str | None,
) -> ElasticBeanstalkResult | None:
    if not resource_id:
        return None

    if managed_actions_enabled:
        return None

    return ElasticBeanstalkResult(
        resource_id=resource_id,
        resource_type="elasticbeanstalk_environment",
        details={
            "managed_actions_enabled": (
                managed_actions_enabled
            ),
            "managed_update_level": managed_update_level,
        },
    )


def build_managed_platform_updates_finding(
    result: ElasticBeanstalkResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELASTICBEANSTALK-002",
        title=(
            "Elastic Beanstalk managed platform updates "
            "are not enabled"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Elastic Beanstalk environment "
            f"{result.resource_id} does not have managed "
            "platform updates enabled."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable managed platform updates for the "
            "Elastic Beanstalk environment and configure "
            "an appropriate update level."
        ),
        compliance=[
            "AWS Security Hub ElasticBeanstalk.2",
            "NIST SP 800-53 Rev. 5 SI-2",
            "NIST SP 800-53 Rev. 5 SI-2(2)",
            "NIST SP 800-53 Rev. 5 SI-2(4)",
            "NIST SP 800-53 Rev. 5 SI-2(5)",
            "PCI DSS v4.0.1/6.3.3",
        ],
    )


def check_cloudwatch_log_streaming(
    resource_id: str,
    stream_logs: bool,
) -> ElasticBeanstalkResult | None:
    if not resource_id:
        return None

    if stream_logs:
        return None

    return ElasticBeanstalkResult(
        resource_id=resource_id,
        resource_type="elasticbeanstalk_environment",
        details={
            "stream_logs": stream_logs,
        },
    )


def build_cloudwatch_log_streaming_finding(
    result: ElasticBeanstalkResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ELASTICBEANSTALK-003",
        title=(
            "Elastic Beanstalk logs are not streamed "
            "to CloudWatch"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The Elastic Beanstalk environment "
            f"{result.resource_id} is not configured "
            "to stream logs to CloudWatch Logs."
        ),
        evidence={
            "resource_id": result.resource_id,
            **result.details,
        },
        remediation=(
            "Enable Elastic Beanstalk log streaming to "
            "CloudWatch Logs."
        ),
        compliance=[
            "AWS Security Hub ElasticBeanstalk.3",
            "PCI DSS v4.0.1/10.4.2",
        ],
    )
