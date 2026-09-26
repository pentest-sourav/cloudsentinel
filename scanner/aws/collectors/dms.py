from __future__ import annotations

import json
from typing import Any

from scanner.aws.services.dms import DMSService


class DMSDataCollector:
    """Normalize AWS DMS resources for CloudSentinel."""

    def __init__(self, service: DMSService):
        self.service = service

        self._replication_instances_cache = None
        self._certificates_cache = None
        self._event_subscriptions_cache = None
        self._subnet_groups_cache = None
        self._tasks_cache = None
        self._endpoints_cache = None

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> tuple[dict[str, str], bool]:
        if not isinstance(tags, dict):
            return {}, False

        normalized: dict[str, str] = {}

        for key, value in tags.items():
            if (
                not isinstance(key, str)
                or not key
                or key.startswith("aws:")
            ):
                continue

            normalized[key] = str(value)

        return normalized, True

    def _tags(
        self,
        arn: Any,
    ) -> tuple[dict[str, str], bool]:
        if not isinstance(arn, str) or not arn:
            return {}, False

        return self._normalize_tags(
            self.service.list_tags_for_resource(arn)
        )

    @staticmethod
    def _resource(
        *,
        name: str,
        arn: str,
        resource_type: str,
        tags: dict[str, str],
        tag_data_available: bool,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = {
            "resource_name": name,
            "resource_arn": arn,
            "resource_type": resource_type,
            "tags": tags,
            "tag_data_available": tag_data_available,
            "has_non_system_tags": bool(tags),
        }

        if extra:
            result.update(extra)

        return result

    def _instances(self):
        if self._replication_instances_cache is None:
            self._replication_instances_cache = (
                self.service.describe_replication_instances()
            )

        return self._replication_instances_cache

    def _certificates(self):
        if self._certificates_cache is None:
            self._certificates_cache = (
                self.service.describe_certificates()
            )

        return self._certificates_cache

    def _event_subscriptions(self):
        if self._event_subscriptions_cache is None:
            self._event_subscriptions_cache = (
                self.service.describe_event_subscriptions()
            )

        return self._event_subscriptions_cache

    def _subnet_groups(self):
        if self._subnet_groups_cache is None:
            self._subnet_groups_cache = (
                self.service.describe_replication_subnet_groups()
            )

        return self._subnet_groups_cache

    def _tasks(self):
        if self._tasks_cache is None:
            self._tasks_cache = (
                self.service.describe_replication_tasks()
            )

        return self._tasks_cache

    def _endpoints(self):
        if self._endpoints_cache is None:
            self._endpoints_cache = (
                self.service.describe_endpoints()
            )

        return self._endpoints_cache

    def collect_replication_instances(self):
        result = []

        for item in self._instances():
            arn = item.get(
                "ReplicationInstanceArn"
            )
            name = item.get(
                "ReplicationInstanceIdentifier"
            )

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(name, str) or not name:
                name = arn

            tags, available = self._tags(arn)

            result.append(
                self._resource(
                    name=name,
                    arn=arn,
                    resource_type=(
                        "dms_replication_instance"
                    ),
                    tags=tags,
                    tag_data_available=available,
                    extra={
                        "publicly_accessible": item.get(
                            "PubliclyAccessible"
                        ),
                        "auto_minor_version_upgrade": (
                            item.get(
                                "AutoMinorVersionUpgrade"
                            )
                        ),
                        "multi_az": item.get("MultiAZ"),
                    },
                )
            )

        return result

    def collect_certificates(self):
        result = []

        for item in self._certificates():
            arn = item.get("CertificateArn")
            name = item.get("CertificateIdentifier")

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(name, str) or not name:
                name = arn

            tags, available = self._tags(arn)

            result.append(
                self._resource(
                    name=name,
                    arn=arn,
                    resource_type="dms_certificate",
                    tags=tags,
                    tag_data_available=available,
                )
            )

        return result

    def collect_event_subscriptions(self):
        result = []

        for item in self._event_subscriptions():
            arn = item.get(
                "EventSubscriptionArn"
            )
            name = item.get(
                "CustSubscriptionId"
            )

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(name, str) or not name:
                name = arn

            tags, available = self._tags(arn)

            result.append(
                self._resource(
                    name=name,
                    arn=arn,
                    resource_type=(
                        "dms_event_subscription"
                    ),
                    tags=tags,
                    tag_data_available=available,
                )
            )

        return result

    def collect_replication_subnet_groups(self):
        result = []

        for item in self._subnet_groups():
            arn = item.get(
                "ReplicationSubnetGroupArn"
            )
            name = item.get(
                "ReplicationSubnetGroupIdentifier"
            )

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(name, str) or not name:
                name = arn

            tags, available = self._tags(arn)

            result.append(
                self._resource(
                    name=name,
                    arn=arn,
                    resource_type=(
                        "dms_replication_subnet_group"
                    ),
                    tags=tags,
                    tag_data_available=available,
                )
            )

        return result

    @staticmethod
    def _parse_task_settings(
        settings: Any,
    ) -> dict[str, Any]:
        if isinstance(settings, dict):
            return settings

        if not isinstance(settings, str) or not settings:
            return {}

        try:
            parsed = json.loads(settings)
        except (TypeError, ValueError):
            return {}

        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _logging_components(
        settings: dict[str, Any],
    ) -> dict[str, str]:
        logging = settings.get("Logging")

        if not isinstance(logging, dict):
            return {}

        components = logging.get(
            "LogComponents",
            [],
        )

        if not isinstance(components, list):
            return {}

        result: dict[str, str] = {}

        for component in components:
            if not isinstance(component, dict):
                continue

            component_id = component.get("Id")
            severity = component.get("Severity")

            if (
                isinstance(component_id, str)
                and isinstance(severity, str)
            ):
                result[component_id] = severity

        return result

    def collect_replication_tasks(self):
        result = []

        for item in self._tasks():
            arn = item.get(
                "ReplicationTaskArn"
            )
            name = item.get(
                "ReplicationTaskIdentifier"
            )

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(name, str) or not name:
                name = arn

            settings = self._parse_task_settings(
                item.get("ReplicationTaskSettings")
            )

            logging = settings.get("Logging")

            logging_enabled = (
                isinstance(logging, dict)
                and logging.get("EnableLogging") is True
            )

            components = self._logging_components(
                settings
            )

            tags, available = self._tags(arn)

            result.append(
                self._resource(
                    name=name,
                    arn=arn,
                    resource_type="dms_replication_task",
                    tags=tags,
                    tag_data_available=available,
                    extra={
                        "logging_enabled": logging_enabled,
                        "log_components": components,
                        "replication_task_settings": settings,
                    },
                )
            )

        return result

    def collect_endpoints(self):
        result = []

        for item in self._endpoints():
            arn = item.get("EndpointArn")
            name = item.get(
                "EndpointIdentifier"
            )

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(name, str) or not name:
                name = arn

            engine_name = str(
                item.get("EngineName", "")
            ).lower()

            mongo = item.get("MongoDbSettings")
            if not isinstance(mongo, dict):
                mongo = {}

            neptune = item.get("NeptuneSettings")
            if not isinstance(neptune, dict):
                neptune = {}

            tags, available = self._tags(arn)

            result.append(
                self._resource(
                    name=name,
                    arn=arn,
                    resource_type="dms_endpoint",
                    tags=tags,
                    tag_data_available=available,
                    extra={
                        "engine_name": engine_name,
                        "endpoint_type": item.get(
                            "EndpointType"
                        ),
                        "ssl_mode": item.get(
                            "SslMode"
                        ),
                        "mongo_auth_type": mongo.get(
                            "AuthType"
                        ),
                        "mongo_auth_mechanism": mongo.get(
                            "AuthMechanism"
                        ),
                        "neptune_iam_auth_mode": (
                            neptune.get("IamAuthMode")
                        ),
                        "neptune_settings": neptune,
                        "mongo_settings": mongo,
                    },
                )
            )

        return result
