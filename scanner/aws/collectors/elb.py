from typing import Any

from scanner.aws.services.elb import ELBService


class ELBDataCollector:
    """
    Normalize Classic ELB and ELBv2 security configuration.

    AWS API responses are cached for the duration of one scan.
    """

    def __init__(
        self,
        service: ELBService,
    ):
        self.service = service

        self._classic_load_balancers_cache: (
            list[dict[str, Any]] | None
        ) = None

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

        self._classic_attributes_cache: (
            dict[str, dict[str, Any]] | None
        ) = None

        self._waf_cache: (
            dict[str, dict[str, Any] | None] | None
        ) = None

    def _get_classic_load_balancers(
        self,
    ) -> list[dict[str, Any]]:
        if self._classic_load_balancers_cache is None:
            self._classic_load_balancers_cache = (
                self.service.list_classic_load_balancers()
            )

        return self._classic_load_balancers_cache

    def _get_load_balancers(
        self,
    ) -> list[dict[str, Any]]:
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

    def _get_classic_attributes(
        self,
        load_balancer_name: str,
    ) -> dict[str, Any]:
        if self._classic_attributes_cache is None:
            self._classic_attributes_cache = {}

        if load_balancer_name not in self._classic_attributes_cache:
            self._classic_attributes_cache[
                load_balancer_name
            ] = (
                self.service
                .describe_classic_load_balancer_attributes(
                    load_balancer_name
                )
            )

        return self._classic_attributes_cache[
            load_balancer_name
        ]

    def _get_waf(
        self,
        load_balancer_arn: str,
    ) -> dict[str, Any] | None:
        if self._waf_cache is None:
            self._waf_cache = {}

        if load_balancer_arn not in self._waf_cache:
            self._waf_cache[load_balancer_arn] = (
                self.service.get_web_acl_for_resource(
                    load_balancer_arn
                )
            )

        return self._waf_cache[load_balancer_arn]

    @staticmethod
    def _attribute_map(
        attributes: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            item["Key"]: item.get("Value")
            for item in attributes
            if isinstance(item.get("Key"), str)
        }

    @staticmethod
    def _classic_listener(
        entry: dict[str, Any],
    ) -> dict[str, Any] | None:
        listener = entry.get("Listener")

        if not isinstance(listener, dict):
            return None

        protocol = listener.get("Protocol")
        port = listener.get("LoadBalancerPort")

        return {
            "resource_id": (
                f"classic-listener:{port}"
                if port is not None
                else "classic-listener"
            ),
            "resource_type": "classic_elb_listener",
            "protocol": protocol,
            "port": port,
            "instance_protocol": listener.get(
                "InstanceProtocol"
            ),
            "instance_port": listener.get(
                "InstancePort"
            ),
            "ssl_certificate_id": listener.get(
                "SSLCertificateId"
            ),
            "policy_names": (
                entry.get("PolicyNames", [])
                if isinstance(
                    entry.get("PolicyNames", []),
                    list,
                )
                else []
            ),
        }

    def _normalize_classic(
        self,
        lb: dict[str, Any],
    ) -> dict[str, Any] | None:
        name = lb.get("LoadBalancerName")

        if not isinstance(name, str) or not name:
            return None

        listener_descriptions = lb.get(
            "ListenerDescriptions",
            [],
        )

        listeners: list[dict[str, Any]] = []

        if isinstance(listener_descriptions, list):
            for entry in listener_descriptions:
                if not isinstance(entry, dict):
                    continue

                normalized = self._classic_listener(entry)

                if normalized is not None:
                    listeners.append(normalized)

        attributes = self._get_classic_attributes(name)

        connection_draining = attributes.get(
            "ConnectionDraining"
        )
        cross_zone = attributes.get(
            "CrossZoneLoadBalancing"
        )
        access_log = attributes.get(
            "AccessLog"
        )
        additional_attributes = attributes.get(
            "AdditionalAttributes"
        )

        desync_mode = None

        if isinstance(additional_attributes, list):
            for item in additional_attributes:
                if not isinstance(item, dict):
                    continue

                if item.get("Key") == (
                    "elb.http.desyncmitigationmode"
                ):
                    desync_mode = item.get("Value")
                    break

        return {
            "resource_id": name,
            "resource_type": "classic_load_balancer",
            "resource_arn": None,
            "name": name,
            "type": "classic",
            "scheme": None,
            "state": None,
            "availability_zones": (
                [
                    zone
                    for zone in lb.get(
                        "AvailabilityZones",
                        [],
                    )
                    if isinstance(zone, str)
                ]
                if isinstance(
                    lb.get(
                        "AvailabilityZones",
                        [],
                    ),
                    list,
                )
                else []
            ),
            "security_groups": (
                lb.get("SecurityGroups", [])
                if isinstance(
                    lb.get("SecurityGroups", []),
                    list,
                )
                else []
            ),
            "listeners": listeners,
            "target_groups": [],
            "attributes": attributes,
            "deletion_protection": None,
            "access_logs_enabled": (
                access_log.get("Enabled")
                if isinstance(access_log, dict)
                else None
            ),
            "drop_invalid_headers": None,
            "desync_mitigation_mode": desync_mode,
            "connection_draining_enabled": (
                connection_draining.get("Enabled")
                if isinstance(
                    connection_draining,
                    dict,
                )
                else None
            ),
            "cross_zone_load_balancing_enabled": (
                cross_zone.get("Enabled")
                if isinstance(cross_zone, dict)
                else None
            ),
            "waf_web_acl_arn": None,
        }

    def collect_load_balancers(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for classic_lb in self._get_classic_load_balancers():
            item = self._normalize_classic(classic_lb)

            if item is not None:
                normalized.append(item)

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
                        "target_type": target_group.get(
                            "TargetType"
                        ),
                        "health_check_protocol": (
                            target_group.get(
                                "HealthCheckProtocol"
                            )
                        ),
                    }
                )

            waf_web_acl = None

            if lb_type == "application":
                waf_web_acl = self._get_waf(arn)

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
                        if isinstance(zone, dict)
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
                    "connection_draining_enabled": None,
                    "cross_zone_load_balancing_enabled": None,
                    "waf_web_acl_arn": (
                        waf_web_acl.get("ARN")
                        if isinstance(
                            waf_web_acl,
                            dict,
                        )
                        else None
                    ),
                }
            )

        return normalized
