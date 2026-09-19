from scanner.aws.collectors.cloudtrail import CloudTrailDataCollector


def collect_cloudtrail_trails(
    collector: CloudTrailDataCollector,
) -> list[dict]:
    """
    Collect normalized CloudTrail trails and enrich each trail
    with its current logging status.
    """
    trails = collector.collect_trails()

    normalized_trails = []

    for trail in trails:
        trail_arn = trail["trail_arn"]

        status = collector.get_trail_status(trail_arn)

        normalized_trails.append(
            {
                **trail,
                "is_logging": status.get("IsLogging", False),
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


CLOUDTRAIL_DATA_SOURCE_HANDLERS = {
    "cloudtrail_trails": collect_cloudtrail_trails,
    "cloudtrail_account": collect_cloudtrail_account,
}
