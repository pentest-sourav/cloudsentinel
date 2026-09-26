from typing import Any

from scanner.aws.services.network_firewall import (
    NetworkFirewallService,
)


class NetworkFirewallDataCollector:
    """
    Normalize AWS Network Firewall resources for security rules.

    AWS API responses are cached for the duration of one scan.
    """

    def __init__(
        self,
        service: NetworkFirewallService,
    ):
        self.service = service

        self._firewalls_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._firewall_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._policy_list_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._policy_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._rule_groups_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._rule_group_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._logging_cache: dict[
            str,
            dict[str, Any],
        ] = {}

    def _get_firewalls(self) -> list[dict[str, Any]]:
        if self._firewalls_cache is None:
            self._firewalls_cache = (
                self.service.list_firewalls()
            )

        return self._firewalls_cache

    def _get_firewall_details(
        self,
        firewall_arn: str,
    ) -> dict[str, Any]:
        if firewall_arn not in self._firewall_details_cache:
            self._firewall_details_cache[firewall_arn] = (
                self.service.describe_firewall(
                    firewall_arn
                )
            )

        return self._firewall_details_cache[
            firewall_arn
        ]

    def _get_policies(self) -> list[dict[str, Any]]:
        if self._policy_list_cache is None:
            self._policy_list_cache = (
                self.service.list_firewall_policies()
            )

        return self._policy_list_cache

    def _get_policy_details(
        self,
        policy_arn: str,
    ) -> dict[str, Any]:
        if policy_arn not in self._policy_details_cache:
            self._policy_details_cache[policy_arn] = (
                self.service.describe_firewall_policy(
                    policy_arn
                )
            )

        return self._policy_details_cache[
            policy_arn
        ]

    def _get_rule_groups(
        self,
    ) -> list[dict[str, Any]]:
        if self._rule_groups_cache is None:
            self._rule_groups_cache = (
                self.service.list_stateless_rule_groups()
            )

        return self._rule_groups_cache

    def _get_rule_group_details(
        self,
        rule_group_arn: str,
    ) -> dict[str, Any]:
        if (
            rule_group_arn
            not in self._rule_group_details_cache
        ):
            self._rule_group_details_cache[
                rule_group_arn
            ] = self.service.describe_rule_group(
                rule_group_arn
            )

        return self._rule_group_details_cache[
            rule_group_arn
        ]

    def _get_logging(
        self,
        firewall_arn: str,
    ) -> dict[str, Any]:
        if firewall_arn not in self._logging_cache:
            self._logging_cache[firewall_arn] = (
                self.service.describe_logging_configuration(
                    firewall_arn
                )
            )

        return self._logging_cache[firewall_arn]

    @staticmethod
    def _availability_zone_data(
        firewall_details: dict[str, Any],
    ) -> tuple[list[str], int]:
        az_mappings = firewall_details.get(
            "AvailabilityZoneMappings",
            [],
        )

        availability_zones = sorted(
            {
                mapping.get("AvailabilityZone")
                for mapping in az_mappings
                if isinstance(mapping, dict)
                and isinstance(
                    mapping.get("AvailabilityZone"),
                    str,
                )
                and mapping.get("AvailabilityZone")
            }
        )

        if availability_zones:
            return availability_zones, len(
                availability_zones
            )

        subnet_mappings = firewall_details.get(
            "SubnetMappings",
            [],
        )

        subnet_ids = {
            mapping.get("SubnetId")
            for mapping in subnet_mappings
            if isinstance(mapping, dict)
            and isinstance(
                mapping.get("SubnetId"),
                str,
            )
            and mapping.get("SubnetId")
        }

        return [], len(subnet_ids)

    def collect_firewalls(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for firewall in self._get_firewalls():
            arn = firewall.get("FirewallArn")
            name = firewall.get("FirewallName")

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(name, str) or not name:
                continue

            details = self._get_firewall_details(arn)
            logging = self._get_logging(arn)

            subnet_mappings = details.get(
                "SubnetMappings",
                [],
            )

            if not isinstance(subnet_mappings, list):
                subnet_mappings = []

            (
                availability_zones,
                availability_zone_count,
            ) = self._availability_zone_data(details)

            log_destinations = logging.get(
                "LogDestinationConfigs",
                [],
            )

            normalized.append(
                {
                    "resource_id": arn,
                    "resource_type": "network_firewall",
                    "resource_arn": arn,
                    "firewall_name": name,
                    "firewall_policy_arn": (
                        details.get(
                            "FirewallPolicyArn"
                        )
                    ),
                    "vpc_id": details.get("VpcId"),
                    "availability_zones": availability_zones,
                    "availability_zone_count": (
                        availability_zone_count
                    ),
                    "subnet_mappings": subnet_mappings,
                    "delete_protection": (
                        details.get(
                            "DeleteProtection",
                            False,
                        )
                        is True
                    ),
                    "subnet_change_protection": (
                        details.get(
                            "SubnetChangeProtection",
                            False,
                        )
                        is True
                    ),
                    "logging_enabled": bool(
                        isinstance(
                            log_destinations,
                            list,
                        )
                        and log_destinations
                    ),
                    "log_destination_count": (
                        len(log_destinations)
                        if isinstance(
                            log_destinations,
                            list,
                        )
                        else 0
                    ),
                }
            )

        return normalized

    def collect_firewall_policies(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for policy in self._get_policies():
            arn = policy.get("Arn")
            name = policy.get("Name")

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(name, str) or not name:
                continue

            details = self._get_policy_details(arn)

            stateless_refs = details.get(
                "StatelessRuleGroupReferences",
                [],
            )

            stateful_refs = details.get(
                "StatefulRuleGroupReferences",
                [],
            )

            if not isinstance(stateless_refs, list):
                stateless_refs = []

            if not isinstance(stateful_refs, list):
                stateful_refs = []

            normalized.append(
                {
                    "resource_id": arn,
                    "resource_type": (
                        "network_firewall_policy"
                    ),
                    "resource_arn": arn,
                    "policy_name": name,
                    "stateless_rule_group_count": len(
                        stateless_refs
                    ),
                    "stateful_rule_group_count": len(
                        stateful_refs
                    ),
                    "has_rule_group": bool(
                        stateless_refs or stateful_refs
                    ),
                    "stateless_default_actions": (
                        details.get(
                            "StatelessDefaultActions",
                            [],
                        )
                    ),
                    "stateless_fragment_default_actions": (
                        details.get(
                            "StatelessFragmentDefaultActions",
                            [],
                        )
                    ),
                }
            )

        return normalized

    def collect_stateless_rule_groups(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for group in self._get_rule_groups():
            arn = group.get("Arn")
            name = group.get("Name")

            if not isinstance(arn, str) or not arn:
                continue

            if not isinstance(name, str) or not name:
                continue

            details = self._get_rule_group_details(arn)

            rule_group = details.get(
                "RuleGroup",
                {},
            )

            if not isinstance(rule_group, dict):
                rule_group = {}

            rules_source = rule_group.get(
                "RulesSource",
                {},
            )

            if not isinstance(rules_source, dict):
                rules_source = {}

            stateless_rules_config = (
                rules_source.get(
                    "StatelessRulesAndCustomActions",
                    {},
                )
            )

            if not isinstance(
                stateless_rules_config,
                dict,
            ):
                stateless_rules_config = {}

            rules = stateless_rules_config.get(
                "StatelessRules",
                [],
            )

            normalized.append(
                {
                    "resource_id": arn,
                    "resource_type": (
                        "network_firewall_stateless_rule_group"
                    ),
                    "resource_arn": arn,
                    "rule_group_name": name,
                    "rule_group_type": "STATELESS",
                    "stateless_rule_count": (
                        len(rules)
                        if isinstance(
                            rules,
                            list,
                        )
                        else 0
                    ),
                }
            )

        return normalized
