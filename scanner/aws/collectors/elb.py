from typing import Any

from scanner.aws.services.elb import ELBService


class ELBDataCollector:
    """
    Normalize ELBv2 security configuration.

    AWS API responses are cached for the duration of one scan.
    """

    def __init__(
        self,
        service: ELBService,
    ):
        self.service = service

        self._load_balancers_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._listeners_cache: (
            dict[str, list[dict[str, Any]]] | None
        ) = None

        self._target_groups_cache: (
            dict[str, list[dict[str, Any]]] | None
        ) = None

        self._attributes_cache: (
            dict[str, list[dict[str, Any]]] | None
        ) = None

    def _get_load_balancers(self) -> list[dict[str, Any]]:
        if self._load_balancers_cache is None:
            self._load_balancers_cache = (
                self.service.list_load_balancers()
            )

        return self._load_balancers_cache

    def _get_listeners(
        self,
        load_balancer_arn: str,
    ) -> list[dict[str, Any]]:
        if self._listeners_cache is None:
            self._listeners_cache = {}

        if load_balancer_arn not in self._listeners_cache:
            self._listeners_cache[load_balancer_arn] = (
                self.service.list_listeners(
                    load_balancer_arn
                )
            )

        return self._listeners_cache[load_balancer_arn]

    def _get_target_groups(
        self,
        load_balancer_arn: str,
    ) -> list[dict[str, Any]]:
        if self._target_groups_cache is None:
            self._target_groups_cache = {}

        if load_balancer_arn not in self._target_groups_cache:
            self._target_groups_cache[load_balancer_arn] = (
                self.service.list_target_groups(
                    load_balancer_arn
                )
            )

        return self._target_groups_cache[load_balancer_arn]

    def _get_attributes(
        self,
        load_balancer_arn: str,
    ) -> list[dict[str, Any]]:
        if self._attributes_cache is None:
            self._attributes_cache = {}

        if load_balancer_arn not in self._attributes_cache:
            self._attributes_cache[load_balancer_arn] = (
                self.service.describe_load_balancer_attributes(
                    load_balancer_arn
                )
            )

        return self._attributes_cache[load_balancer_arn]

    @staticmethod
    def _attribute_map(
        attributes: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            item["Key"]: item.get("Value")
            for item in attributes
            if isinstance(item.get("Key"), str)
        }

    def collect_load_balancers(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for lb in self._get_load_balancers():
            arn = lb.get("LoadBalancerArn")

            if not isinstance(arn, str) or not arn:
                continue

            lb_type = lb.get("Type")

            listeners = self._get_listeners(arn)
            target_groups = self._get_target_groups(arn)
            attributes = self._attribute_map(
                self._get_attributes(arn)
            )

            normalized_listeners: list[dict[str, Any]] = []

            for listener in listeners:
                listener_arn = listener.get(
                    "ListenerArn"
                )

                if not isinstance(listener_arn, str):
                    continue

                normalized_listeners.append(
                    {
                        "resource_id": listener_arn,
                        "resource_type": "elb_listener",
                        "protocol": listener.get(
                            "Protocol"
                        ),
                        "port": listener.get("Port"),
                        "ssl_policy": listener.get(
                            "SslPolicy"
                        ),
                        "default_actions": (
                            listener.get(
                                "DefaultActions",
                                [],
                            )
                            if isinstance(
                                listener.get(
                                    "DefaultActions",
                                    [],
                                ),
                                list,
                            )
                            else []
                        ),
                    }
                )

            normalized_target_groups: list[dict[str, Any]] = []

            for target_group in target_groups:
                target_group_arn = target_group.get(
                    "TargetGroupArn"
                )

                if not isinstance(
                    target_group_arn,
                    str,
                ):
                    continue

                normalized_target_groups.append(
                    {
                        "resource_id": target_group_arn,
                        "resource_type": "elb_target_group",
                        "protocol": target_group.get(
                            "Protocol"
                        ),
                        "port": target_group.get("Port"),
                        "protocol_version": target_group.get(
                            "ProtocolVersion"
                        ),
                        "health_check_protocol": (
                            target_group.get(
                                "HealthCheckProtocol"
                            )
                        ),
                    }
                )

            normalized.append(
                {
                    "resource_id": arn,
                    "resource_type": (
                        "application_load_balancer"
                        if lb_type == "application"
                        else (
                            "network_load_balancer"
                            if lb_type == "network"
                            else (
                                "gateway_load_balancer"
                                if lb_type == "gateway"
                                else "load_balancer"
                            )
                        )
                    ),
                    "resource_arn": arn,
                    "name": lb.get("LoadBalancerName"),
                    "type": lb_type,
                    "scheme": lb.get("Scheme"),
                    "state": (
                        lb.get("State", {}).get("Code")
                        if isinstance(
                            lb.get("State"),
                            dict,
                        )
                        else None
                    ),
                    "availability_zones": [
                        zone.get("ZoneName")
                        for zone in (
                            lb.get(
                                "AvailabilityZones",
                                [],
                            )
                            if isinstance(
                                lb.get(
                                    "AvailabilityZones",
                                    [],
                                ),
                                list,
                            )
                            else []
                        )
                        if isinstance(
                            zone,
                            dict,
                        )
                        and isinstance(
                            zone.get("ZoneName"),
                            str,
                        )
                    ],
                    "security_groups": (
                        lb.get(
                            "SecurityGroups",
                            [],
                        )
                        if isinstance(
                            lb.get(
                                "SecurityGroups",
                                [],
                            ),
                            list,
                        )
                        else []
                    ),
                    "listeners": normalized_listeners,
                    "target_groups": normalized_target_groups,
                    "attributes": attributes,
                    "deletion_protection": (
                        attributes.get(
                            "deletion_protection.enabled"
                        )
                        == "true"
                    ),
                    "access_logs_enabled": (
                        attributes.get(
                            "access_logs.s3.enabled"
                        )
                        == "true"
                    ),
                    "drop_invalid_headers": (
                        attributes.get(
                            "routing.http.drop_invalid_header_fields.enabled"
                        )
                        == "true"
                    ),
                    "desync_mitigation_mode": (
                        attributes.get(
                            "routing.http.desync_mitigation_mode"
                        )
                    ),
                }
            )

        return normalized
