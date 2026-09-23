from typing import Any

from scanner.aws.services.cloudtrail import CloudTrailService


class CloudTrailDataCollector:
    """
    Normalizes AWS CloudTrail configuration data
    for security rules.
    """

    def __init__(self, service: CloudTrailService):
        self.service = service
        self._trails_cache: list[dict[str, Any]] | None = None
        self._trail_status_cache: dict[str, dict[str, Any]] = {}
        self._event_selectors_cache: dict[str, dict[str, Any]] = {}
        self._trail_tags_cache: dict[str, list[dict[str, str]]] | None = None

    def _get_trails(self) -> list[dict[str, Any]]:
        """
        Discover CloudTrail trails once and cache the result.
        """
        if self._trails_cache is None:
            self._trails_cache = self.service.describe_trails()

        return self._trails_cache

    def collect_trails(self) -> list[dict[str, Any]]:
        """
        Return normalized CloudTrail trail configuration.
        """
        normalized = []

        for trail in self._get_trails():
            trail_arn = trail.get("TrailARN")

            if not trail_arn:
                continue

            normalized.append(
                {
                    "name": trail.get("Name"),
                    "trail_arn": trail_arn,
                    "home_region": trail.get("HomeRegion"),
                    "s3_bucket_name": trail.get("S3BucketName"),
                    "s3_key_prefix": trail.get("S3KeyPrefix"),
                    "kms_key_id": trail.get("KmsKeyId"),
                    "include_global_service_events": trail.get(
                        "IncludeGlobalServiceEvents"
                    ),
                    "is_multi_region_trail": trail.get(
                        "IsMultiRegionTrail"
                    ),
                    "enable_log_file_validation": trail.get(
                        "LogFileValidationEnabled"
                    ),
                    "is_organization_trail": trail.get(
                        "IsOrganizationTrail"
                    ),
                    "cloudwatch_logs_log_group_arn": trail.get(
                        "CloudWatchLogsLogGroupArn"
                    ),
                    "cloudwatch_logs_role_arn": trail.get(
                        "CloudWatchLogsRoleArn"
                    ),
                    "has_insight_selectors": bool(
                        trail.get("InsightSelectors")
                    ),
                    "has_event_selectors": bool(
                        trail.get("EventSelectors")
                    ),
                }
            )

        return normalized

    def collect_account(self) -> dict[str, Any]:
        """
        Return account-level CloudTrail configuration data.
        """
        trails = self._get_trails()

        valid_trails = [
            trail
            for trail in trails
            if trail.get("TrailARN")
        ]

        return {
            "trail_count": len(valid_trails),
        }

    def get_trail_status(
        self,
        trail_arn: str,
    ) -> dict[str, Any]:
        """
        Return and cache the current logging status
        for a CloudTrail trail.
        """
        if trail_arn not in self._trail_status_cache:
            self._trail_status_cache[trail_arn] = (
                self.service.get_trail_status(trail_arn)
            )

        return self._trail_status_cache[trail_arn]

    def get_event_selectors(
        self,
        trail_arn: str,
    ) -> dict[str, Any]:
        """
        Return and cache event selector configuration
        for a CloudTrail trail.
        """
        if trail_arn not in self._event_selectors_cache:
            self._event_selectors_cache[trail_arn] = (
                self.service.get_event_selectors(trail_arn)
            )

        return self._event_selectors_cache[trail_arn]

    def get_trail_tags(
        self,
        trail_arns: list[str],
    ) -> dict[str, list[dict[str, str]]]:
        """
        Return and cache tags for CloudTrail trails.
        """
        if self._trail_tags_cache is None:
            self._trail_tags_cache = self.service.list_trail_tags(
                trail_arns
            )

        return self._trail_tags_cache
