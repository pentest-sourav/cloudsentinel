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
                "AWS SDK error during CloudTrail trail status "
                f"discovery: {exc}"
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

    def get_event_data_store(
        self,
        event_data_store_arn: str,
    ) -> dict[str, Any]:
        """
        Return detailed configuration for a CloudTrail Lake
        event data store.
        """
        try:
            return self.cloudtrail_client.get_event_data_store(
                EventDataStore=event_data_store_arn
            )

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"CloudTrail event data store discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during CloudTrail event data store "
                f"discovery: {exc}"
            ) from exc

    def list_event_data_stores(self) -> list[dict[str, Any]]:
        """
        Return detailed configuration for all CloudTrail Lake
        event data stores.

        ListEventDataStores is paginated. Each returned event data
        store is enriched with GetEventDataStore so encryption
        configuration such as KmsKeyId is available to the rules.
        """
        event_data_stores: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxResults": 50,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = self.cloudtrail_client.list_event_data_stores(
                    **request
                )

                stores = response.get("EventDataStores", [])

                if isinstance(stores, list):
                    for store in stores:
                        event_data_store_arn = store.get(
                            "EventDataStoreArn"
                        )

                        if not event_data_store_arn:
                            continue

                        details = self.get_event_data_store(
                            event_data_store_arn
                        )

                        merged_store = {
                            **store,
                            **details,
                        }

                        event_data_stores.append(merged_store)

                next_token = response.get("NextToken")

                if not next_token:
                    break

            return event_data_stores

        except RuntimeError:
            raise

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"CloudTrail event data store discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during CloudTrail event data store "
                f"discovery: {exc}"
            ) from exc
