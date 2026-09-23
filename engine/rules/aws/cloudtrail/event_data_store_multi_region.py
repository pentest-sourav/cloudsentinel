from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailEventDataStoreMultiRegionResult:
    event_data_store_arn: str
    name: str | None
    multi_region_enabled: bool | None

    @property
    def multi_region_disabled(self) -> bool:
        return self.multi_region_enabled is False


def check_cloudtrail_event_data_store_multi_region(
    event_data_store_arn: str,
    name: str | None,
    multi_region_enabled: bool | None,
) -> CloudTrailEventDataStoreMultiRegionResult:
    """
    Evaluate whether a CloudTrail Lake event data store
    is configured for multi-Region collection.
    """
    return CloudTrailEventDataStoreMultiRegionResult(
        event_data_store_arn=event_data_store_arn,
        name=name,
        multi_region_enabled=multi_region_enabled,
    )


def build_cloudtrail_event_data_store_multi_region_finding(
    result: CloudTrailEventDataStoreMultiRegionResult,
) -> Finding | None:
    if not result.multi_region_disabled:
        return None

    return Finding(
        rule_id="CS-AWS-CT-015",
        title=(
            "CloudTrail Lake event data store is not "
            "configured for multi-Region collection"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail_event_data_store",
        resource_id=result.event_data_store_arn,
        description=(
            "The CloudTrail Lake event data store is configured "
            "without multi-Region collection. Events from other "
            "AWS Regions may therefore not be collected by this "
            "event data store."
        ),
        evidence={
            "event_data_store_arn": result.event_data_store_arn,
            "event_data_store_name": result.name,
            "multi_region_enabled": result.multi_region_enabled,
        },
        remediation=(
            "Enable multi-Region collection when centralized "
            "cross-Region CloudTrail Lake coverage is required."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
