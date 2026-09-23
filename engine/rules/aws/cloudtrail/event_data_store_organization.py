from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailEventDataStoreOrganizationResult:
    event_data_store_arn: str
    name: str | None
    organization_enabled: bool | None

    @property
    def organization_disabled(self) -> bool:
        return self.organization_enabled is False


def check_cloudtrail_event_data_store_organization(
    event_data_store_arn: str,
    name: str | None,
    organization_enabled: bool | None,
) -> CloudTrailEventDataStoreOrganizationResult:
    """
    Evaluate whether a CloudTrail Lake event data store
    is configured for organization-wide collection.
    """
    return CloudTrailEventDataStoreOrganizationResult(
        event_data_store_arn=event_data_store_arn,
        name=name,
        organization_enabled=organization_enabled,
    )


def build_cloudtrail_event_data_store_organization_finding(
    result: CloudTrailEventDataStoreOrganizationResult,
) -> Finding | None:
    if not result.organization_disabled:
        return None

    return Finding(
        rule_id="CS-AWS-CT-016",
        title=(
            "CloudTrail Lake event data store is not "
            "configured for organization-wide collection"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail_event_data_store",
        resource_id=result.event_data_store_arn,
        description=(
            "The CloudTrail Lake event data store is not configured "
            "for organization-wide collection. Member-account "
            "CloudTrail activity may therefore require separate "
            "event data store coverage."
        ),
        evidence={
            "event_data_store_arn": result.event_data_store_arn,
            "event_data_store_name": result.name,
            "organization_enabled": result.organization_enabled,
        },
        remediation=(
            "Enable organization-wide collection when centralized "
            "CloudTrail Lake coverage across AWS Organization "
            "accounts is required."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
