from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.session import AWS_RETRY_CONFIG


class CloudTrailService:
    """
    Read-only AWS CloudTrail discovery service.

    This service is responsible only for collecting CloudTrail
    configuration data. Security evaluation is handled separately
    by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.cloudtrail_client = session.client(
            "cloudtrail",
            config=AWS_RETRY_CONFIG,
        )

    def describe_trails(self) -> list[dict[str, Any]]:
        """
        Return all CloudTrail trails available to the current
        AWS account and region.
        """
        try:
            response = self.cloudtrail_client.describe_trails(
                includeShadowTrails=True
            )

            return response.get("trailList", [])

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"CloudTrail trail discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during CloudTrail discovery: "
                f"{exc}"
            ) from exc

    def get_trail_status(
        self,
        trail_arn: str,
    ) -> dict[str, Any]:
        """
        Return the current logging status of a CloudTrail trail.
        """
        try:
            response = self.cloudtrail_client.get_trail_status(
                Name=trail_arn
            )

            return response

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"CloudTrail trail status discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during CloudTrail status discovery: "
                f"{exc}"
            ) from exc

    def get_event_selectors(
        self,
        trail_arn: str,
    ) -> dict[str, Any]:
        """
        Return the event selector configuration for a CloudTrail trail.
        """
        try:
            response = self.cloudtrail_client.get_event_selectors(
                TrailName=trail_arn
            )

            return response

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                f"CloudTrail event selector discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during CloudTrail event selector "
                f"discovery: {exc}"
            ) from exc

    def list_trail_tags(
        self,
        trail_arns: list[str],
    ) -> dict[str, list[dict[str, str]]]:
        """
        Return tags for the supplied CloudTrail trail ARNs.

        CloudTrail accepts up to 20 resource ARNs per ListTags request,
        so callers can batch trail lookups instead of issuing one AWS
        API request per trail.
        """
        if not trail_arns:
            return {}

        tags_by_trail: dict[str, list[dict[str, str]]] = {}

        for start in range(0, len(trail_arns), 20):
            batch = trail_arns[start : start + 20]

            try:
                response = self.cloudtrail_client.list_tags(
                    ResourceIdList=batch
                )

            except ClientError as exc:
                error = exc.response.get("Error", {})
                code = error.get("Code", "UnknownError")
                message = error.get(
                    "Message",
                    "AWS request failed",
                )

                raise RuntimeError(
                    f"CloudTrail tag discovery failed: "
                    f"{code}: {message}"
                ) from exc

            except BotoCoreError as exc:
                raise RuntimeError(
                    "AWS SDK error during CloudTrail tag discovery: "
                    f"{exc}"
                ) from exc

            for resource in response.get("ResourceTagList", []):
                resource_id = resource.get("ResourceId")

                if not resource_id:
                    continue

                tags = resource.get("TagsList", [])

                if not isinstance(tags, list):
                    tags = []

                tags_by_trail[resource_id] = tags

        return tags_by_trail
