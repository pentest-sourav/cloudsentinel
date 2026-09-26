from typing import Any

from scanner.aws.services.mq import MQService


class MQDataCollector:
    """
    Normalize Amazon MQ broker configuration for security rules.

    AWS API responses are cached for the duration of one scan.
    """

    def __init__(self, service: MQService):
        self.service = service
        self._brokers_cache: list[dict[str, Any]] | None = None

    def _get_brokers(self) -> list[dict[str, Any]]:
        if self._brokers_cache is None:
            self._brokers_cache = self.service.list_broker_details()

        return self._brokers_cache

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> list[dict[str, str]]:
        normalized: list[dict[str, str]] = []

        if isinstance(tags, dict):
            for key, value in tags.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or key.startswith("aws:")
                ):
                    continue

                normalized.append(
                    {
                        "Key": key,
                        "Value": (
                            value
                            if isinstance(value, str)
                            else str(value)
                        ),
                    }
                )

            return normalized

        if isinstance(tags, list):
            for tag in tags:
                if not isinstance(tag, dict):
                    continue

                key = tag.get("Key")
                value = tag.get("Value", "")

                if (
                    not isinstance(key, str)
                    or not key
                    or key.startswith("aws:")
                ):
                    continue

                normalized.append(
                    {
                        "Key": key,
                        "Value": (
                            value
                            if isinstance(value, str)
                            else str(value)
                        ),
                    }
                )

        return normalized

    @staticmethod
    def _normalize_logs(
        logs: Any,
    ) -> dict[str, Any]:
        if not isinstance(logs, dict):
            return {
                "audit": None,
                "audit_log_group": None,
                "general": None,
                "general_log_group": None,
            }

        return {
            "audit": logs.get("Audit"),
            "audit_log_group": logs.get("AuditLogGroup"),
            "general": logs.get("General"),
            "general_log_group": logs.get(
                "GeneralLogGroup"
            ),
        }

    def collect_brokers(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for broker in self._get_brokers():
            broker_id = broker.get("BrokerId")

            if (
                not isinstance(broker_id, str)
                or not broker_id
            ):
                continue

            logs = self._normalize_logs(
                broker.get("Logs")
            )

            normalized.append(
                {
                    "resource_id": broker_id,
                    "resource_type": "amazonmq_broker",
                    "resource_arn": broker.get("BrokerArn"),
                    "name": broker.get("BrokerName"),
                    "engine_type": broker.get("EngineType"),
                    "engine_version": broker.get(
                        "EngineVersion"
                    ),
                    "deployment_mode": broker.get(
                        "DeploymentMode"
                    ),
                    "broker_state": broker.get(
                        "BrokerState"
                    ),
                    "publicly_accessible": broker.get(
                        "PubliclyAccessible"
                    ),
                    "logs_audit": logs["audit"],
                    "audit_log_group": logs[
                        "audit_log_group"
                    ],
                    "logs_general": logs["general"],
                    "general_log_group": logs[
                        "general_log_group"
                    ],
                    "tags": self._normalize_tags(
                        broker.get("Tags")
                    ),
                }
            )

        return normalized
