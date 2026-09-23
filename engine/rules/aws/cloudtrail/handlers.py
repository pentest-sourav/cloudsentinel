from typing import Any

from scanner.aws.collectors.cloudtrail import CloudTrailDataCollector


def _includes_management_events(
    event_selector_config: dict[str, Any],
) -> bool:
    """
    Determine whether a CloudTrail trail configuration includes
    management events.

    Supports both basic EventSelectors and
    AdvancedEventSelectors.
    """
    if not isinstance(event_selector_config, dict):
        return False

    event_selectors = event_selector_config.get(
        "EventSelectors",
        [],
    )

    if not isinstance(event_selectors, list):
        event_selectors = []

    for selector in event_selectors:
        if not isinstance(selector, dict):
            continue

        if selector.get("IncludeManagementEvents", False):
            return True

    advanced_selectors = event_selector_config.get(
        "AdvancedEventSelectors",
        [],
    )

    if not isinstance(advanced_selectors, list):
        advanced_selectors = []

    for selector in advanced_selectors:
        if not isinstance(selector, dict):
            continue

        for field_selector in selector.get(
            "FieldSelectors",
            [],
        ):
            if not isinstance(field_selector, dict):
                continue

            if field_selector.get("Field") != "eventCategory":
                continue

            if "Management" in field_selector.get(
                "Equals",
                [],
            ):
                return True

    return False


def _includes_event_data_store_management_events(
    advanced_event_selectors: Any,
) -> bool:
    """
    Determine whether a CloudTrail Lake event data store includes
    management events.

    CloudTrail event data stores use AdvancedEventSelectors.
    If no selectors are returned, CloudTrail's default event
    data store configuration includes management events.
    """
    if advanced_event_selectors is None:
        return True

    if not isinstance(advanced_event_selectors, list):
        return False

    if not advanced_event_selectors:
        return True

    for selector in advanced_event_selectors:
        if not isinstance(selector, dict):
            continue

        field_selectors = selector.get(
            "FieldSelectors",
            [],
        )

        if not isinstance(field_selectors, list):
            continue

        for field_selector in field_selectors:
            if not isinstance(field_selector, dict):
                continue

            if field_selector.get("Field") != "eventCategory":
                continue

            equals = field_selector.get("Equals", [])

            if isinstance(equals, list) and "Management" in equals:
                return True

    return False


def collect_cloudtrail_trails(
    collector: CloudTrailDataCollector,
) -> list[dict]:
    """
    Collect normalized CloudTrail trails and enrich each trail
    with its current logging status and management-event coverage.
    """
    trails = collector.collect_trails()

    trail_arns = [
        trail["trail_arn"]
        for trail in trails
    ]

    trail_tags = collector.get_trail_tags(trail_arns)

    normalized_trails = []

    for trail in trails:
        trail_arn = trail["trail_arn"]

        status = collector.get_trail_status(trail_arn)

        event_selector_config = collector.get_event_selectors(
            trail_arn
        )

        normalized_trails.append(
            {
                **trail,
                "is_logging": status.get("IsLogging", False),
                "includes_management_events": (
                    _includes_management_events(
                        event_selector_config
                    )
                ),
                "tags": trail_tags.get(trail_arn, []),
            }
        )

    return normalized_trails


def collect_cloudtrail_account(
    collector: CloudTrailDataCollector,
) -> dict:
    """
    Collect account-level CloudTrail configuration data.
    """
    return collector.collect_account()


def collect_cloudtrail_event_data_stores(
    collector: CloudTrailDataCollector,
) -> list[dict]:
    """
    Collect normalized CloudTrail Lake event data stores.
    """
    normalized = []

    for store in collector.get_event_data_stores():
        event_data_store_arn = store.get("EventDataStoreArn")

        if not event_data_store_arn:
            continue

        normalized.append(
            {
                "event_data_store_arn": event_data_store_arn,
                "name": store.get("Name"),
                "kms_key_id": store.get("KmsKeyId"),
                "status": store.get("Status"),
                "multi_region_enabled": store.get(
                    "MultiRegionEnabled"
                ),
                "organization_enabled": store.get(
                    "OrganizationEnabled"
                ),
                "retention_period": store.get(
                    "RetentionPeriod"
                ),
                "termination_protection_enabled": store.get(
                    "TerminationProtectionEnabled"
                ),
                "management_events_enabled": (
                    _includes_event_data_store_management_events(
                        store.get("AdvancedEventSelectors")
                    )
                ),
            }
        )

    return normalized


def collect_cloudtrail_destination_bucket_security(
    collector: CloudTrailDataCollector,
) -> list[dict]:
    return collector.collect_destination_bucket_security()


def collect_cloudtrail_sns_topic_security(
    collector: CloudTrailDataCollector,
) -> list[dict]:
    return collector.collect_sns_topic_security()


CLOUDTRAIL_DATA_SOURCE_HANDLERS = {
    "cloudtrail_trails": collect_cloudtrail_trails,
    "cloudtrail_account": collect_cloudtrail_account,
    "cloudtrail_event_data_stores": collect_cloudtrail_event_data_stores,
    "cloudtrail_destination_bucket_security": (
        collect_cloudtrail_destination_bucket_security
    ),
    "cloudtrail_sns_topic_security": (
        collect_cloudtrail_sns_topic_security
    ),
}
