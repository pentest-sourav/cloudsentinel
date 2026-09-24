import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class EventBridgeService:
    """
    Read-only AWS EventBridge discovery service.

    This service retrieves event bus metadata, resource policies,
    tags, and global endpoint replication configuration.
    Security evaluation is handled separately by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.eventbridge_client = create_aws_client(
            session,
            "events",
        )

    def list_event_buses(self) -> list[dict[str, Any]]:
        try:
            paginator = self.eventbridge_client.get_paginator(
                "list_event_buses"
            )

            event_buses: list[dict[str, Any]] = []

            for page in paginator.paginate():
                buses = page.get("EventBuses", [])

                if isinstance(buses, list):
                    event_buses.extend(
                        bus
                        for bus in buses
                        if isinstance(bus, dict)
                    )

            return event_buses

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                "EventBridge event bus discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during EventBridge event bus "
                f"discovery: {exc}"
            ) from exc

    def describe_event_bus(
        self,
        event_bus_name: str,
    ) -> dict[str, Any]:
        try:
            response = self.eventbridge_client.describe_event_bus(
                Name=event_bus_name,
            )

            policy = response.get("Policy")

            if isinstance(policy, str) and policy:
                try:
                    policy = json.loads(policy)
                except json.JSONDecodeError:
                    policy = None

            if not isinstance(policy, dict):
                policy = None

            return {
                "arn": response.get("Arn"),
                "name": response.get("Name"),
                "description": response.get("Description"),
                "event_source_name": response.get(
                    "EventSourceName"
                ),
                "policy": policy,
            }

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                "EventBridge event bus description failed for "
                f"'{event_bus_name}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error while describing EventBridge "
                f"event bus '{event_bus_name}': {exc}"
            ) from exc

    def list_event_bus_tags(
        self,
        event_bus_arn: str,
    ) -> list[dict[str, Any]]:
        try:
            response = self.eventbridge_client.list_tags_for_resource(
                ResourceARN=event_bus_arn,
            )

            tags = response.get("Tags", [])

            if not isinstance(tags, list):
                return []

            return [
                tag
                for tag in tags
                if isinstance(tag, dict)
            ]

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                "EventBridge event bus tag discovery failed for "
                f"'{event_bus_arn}': {code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error while retrieving EventBridge "
                f"event bus tags for '{event_bus_arn}': {exc}"
            ) from exc

    def list_endpoints(self) -> list[dict[str, Any]]:
        try:
            paginator = self.eventbridge_client.get_paginator(
                "list_endpoints"
            )

            endpoints: list[dict[str, Any]] = []

            for page in paginator.paginate():
                page_endpoints = page.get("Endpoints", [])

                if isinstance(page_endpoints, list):
                    endpoints.extend(
                        endpoint
                        for endpoint in page_endpoints
                        if isinstance(endpoint, dict)
                    )

            return endpoints

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")

            raise RuntimeError(
                "EventBridge global endpoint discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during EventBridge global endpoint "
                f"discovery: {exc}"
            ) from exc
