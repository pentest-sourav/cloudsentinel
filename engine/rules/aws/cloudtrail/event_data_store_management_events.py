from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailEventDataStoreManagementEventsResult:
    event_data_store_arn: str
    name: str | None
    management_events_enabled: bool | None

    @property
    def management_events_disabled(self) -> bool:
        return self.management_events_enabled is False


def check_cloudtrail_event_data_store_management_events(
    event_data_store_arn: str,
    name: str | None,
    management_events_enabled: bool | None,
) -> CloudTrailEventDataStoreManagementEventsResult:
    """
    Evaluate whether a CloudTrail Lake event data store
    includes management events.
    """
    return CloudTrailEventDataStoreManagementEventsResult(
        event_data_store_arn=event_data_store_arn,
        name=name,
        management_events_enabled=management_events_enabled,
    )


def build_cloudtrail_event_data_store_management_events_finding(
    result: CloudTrailEventDataStoreManagementEventsResult,
) -> Finding | None:
    if not result.management_events_disabled:
        return None

    return Finding(
        rule_id="CS-AWS-CT-014",
        title=(
            "CloudTrail Lake event data store does not "
            "include management events"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="cloudtrail_event_data_store",
        resource_id=result.event_data_store_arn,
        description=(
            "The CloudTrail Lake event data store does not include "
            "management events. Management events provide visibility "
            "into control-plane activity such as resource creation, "
            "modification, and deletion."
        ),
        evidence={
            "event_data_store_arn": result.event_data_store_arn,
            "event_data_store_name": result.name,
            "management_events_enabled": (
                result.management_events_enabled
            ),
        },
        remediation=(
            "Configure the CloudTrail Lake event data store to "
            "include management events."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
