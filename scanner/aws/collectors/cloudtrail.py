from typing import Any

from scanner.aws.collectors.s3 import S3DataCollector
from scanner.aws.services.cloudtrail import CloudTrailService
from scanner.aws.services.s3 import S3Service


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
        self._event_data_stores_cache: list[dict[str, Any]] | None = None
        self._s3_collector: S3DataCollector | None = None
        self._destination_bucket_cache: dict[str, dict[str, Any]] = {}

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
            trail for trail in trails if trail.get("TrailARN")
        ]

        return {
            "trail_count": len(valid_trails),
        }

    def get_trail_status(
        self,
        trail_arn: str,
    ) -> dict[str, Any]:
        """
        Get and cache CloudTrail trail status.
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
        Get and cache CloudTrail event selectors.
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
        Get and cache CloudTrail trail tags.
        """
        if self._trail_tags_cache is None:
            self._trail_tags_cache = self.service.list_trail_tags(
                trail_arns
            )

        return self._trail_tags_cache

    def get_event_data_stores(self) -> list[dict[str, Any]]:
        """
        Get and cache CloudTrail Lake event data stores.
        """
        if self._event_data_stores_cache is None:
            self._event_data_stores_cache = (
                self.service.list_event_data_stores()
            )

        return self._event_data_stores_cache

    def _get_s3_collector(self) -> S3DataCollector:
        """
        Lazily create the S3 collector using the CloudTrail session.
        """
        if self._s3_collector is None:
            s3_service = S3Service(self.service.session)
            self._s3_collector = S3DataCollector(s3_service)

        return self._s3_collector

    def _get_destination_bucket_security_data(
        self,
        bucket_name: str,
    ) -> dict[str, Any]:
        """
        Collect and cache security configuration for a
        CloudTrail destination S3 bucket.
        """
        if bucket_name in self._destination_bucket_cache:
            return self._destination_bucket_cache[bucket_name]

        s3_collector = self._get_s3_collector()

        result = {
            "bucket_name": bucket_name,
            "public_access_block": (
                s3_collector.service.get_public_access_block(
                    bucket_name
                )
            ),
            "logging_configuration": (
                s3_collector.service.get_bucket_logging(
                    bucket_name
                )
            ),
        }

        self._destination_bucket_cache[bucket_name] = result

        return result

    def collect_destination_bucket_security(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect security configuration for S3 buckets used by
        CloudTrail trails.

        Multiple trails may use the same destination bucket, so
        each bucket is collected only once.
        """
        collected = []
        seen_buckets: set[str] = set()

        for trail in self.collect_trails():
            bucket_name = trail.get("s3_bucket_name")

            if not bucket_name or bucket_name in seen_buckets:
                continue

            seen_buckets.add(bucket_name)

            bucket_data = self._get_destination_bucket_security_data(
                bucket_name
            )

            collected.append(
                {
                    "bucket_name": bucket_name,
                    "public_access_block": bucket_data[
                        "public_access_block"
                    ],
                    "logging_configuration": bucket_data[
                        "logging_configuration"
                    ],
                }
            )

        return collected
