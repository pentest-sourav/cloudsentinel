from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailEventDataStoreTerminationProtectionResult:
    event_data_store_arn: str
    name: str | None
    termination_protection_enabled: bool | None

    @property
    def termination_protection_disabled(self) -> bool:
        return self.termination_protection_enabled is False


def check_cloudtrail_event_data_store_termination_protection(
    event_data_store_arn: str,
    name: str | None,
    termination_protection_enabled: bool | None,
) -> CloudTrailEventDataStoreTerminationProtectionResult:
    """
    Evaluate whether a CloudTrail Lake event data store
    has termination protection enabled.
    """
    return CloudTrailEventDataStoreTerminationProtectionResult(
        event_data_store_arn=event_data_store_arn,
        name=name,
        termination_protection_enabled=termination_protection_enabled,
    )


def build_cloudtrail_event_data_store_termination_protection_finding(
    result: CloudTrailEventDataStoreTerminationProtectionResult,
) -> Finding | None:
    if not result.termination_protection_disabled:
        return None

    return Finding(
        rule_id="CS-AWS-CT-011",
        title=(
            "CloudTrail Lake event data store does not have "
            "termination protection enabled"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail_event_data_store",
        resource_id=result.event_data_store_arn,
        description=(
            "The CloudTrail Lake event data store does not have "
            "termination protection enabled. Without termination "
            "protection, the event data store can be deleted "
            "without this safeguard against accidental termination."
        ),
        evidence={
            "event_data_store_arn": result.event_data_store_arn,
            "event_data_store_name": result.name,
            "termination_protection_enabled": (
                result.termination_protection_enabled
            ),
        },
        remediation=(
            "Enable termination protection for the CloudTrail Lake "
            "event data store to reduce the risk of accidental "
            "deletion of the event data store."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
