from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class NetworkFirewallService:
    """
    Read-only AWS Network Firewall discovery service.
    """

    def __init__(self, session):
        self.session = session
        self.client = create_aws_client(
            session,
            "network-firewall",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"Network Firewall {operation} failed: "
                f"{code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during Network Firewall "
            f"{operation}: {exc}"
        ) from exc

    def list_firewalls(self) -> list[dict[str, Any]]:
        try:
            paginator = self.client.get_paginator(
                "list_firewalls"
            )

            firewalls: list[dict[str, Any]] = []

            for page in paginator.paginate():
                firewalls.extend(
                    page.get("Firewalls", [])
                )

            return firewalls

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "firewall discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_firewall(
        self,
        firewall_arn: str,
    ) -> dict[str, Any]:
        try:
            response = self.client.describe_firewall(
                FirewallArn=firewall_arn,
            )

            return response.get("Firewall") or {}

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"firewall lookup for {firewall_arn}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_firewall_policies(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.client.get_paginator(
                "list_firewall_policies"
            )

            policies: list[dict[str, Any]] = []

            for page in paginator.paginate():
                policies.extend(
                    page.get("FirewallPolicies", [])
                )

            return policies

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "firewall policy discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_firewall_policy(
        self,
        policy_arn: str,
    ) -> dict[str, Any]:
        try:
            response = self.client.describe_firewall_policy(
                FirewallPolicyArn=policy_arn,
            )

            return response.get(
                "FirewallPolicy"
            ) or {}

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"firewall policy lookup for {policy_arn}",
                exc,
            )
            raise AssertionError("unreachable")

    def list_stateless_rule_groups(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.client.get_paginator(
                "list_rule_groups"
            )

            rule_groups: list[dict[str, Any]] = []

            for page in paginator.paginate(
                Scope="ACCOUNT",
                Type="STATELESS",
            ):
                rule_groups.extend(
                    page.get("RuleGroups", [])
                )

            return rule_groups

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "stateless rule group discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_rule_group(
        self,
        rule_group_arn: str,
    ) -> dict[str, Any]:
        try:
            response = self.client.describe_rule_group(
                RuleGroupArn=rule_group_arn,
                Type="STATELESS",
            )

            return {
                "RuleGroup": (
                    response.get("RuleGroup") or {}
                ),
                "RuleGroupResponse": (
                    response.get(
                        "RuleGroupResponse"
                    ) or {}
                ),
            }

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"rule group lookup for {rule_group_arn}",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_logging_configuration(
        self,
        firewall_arn: str,
    ) -> dict[str, Any]:
        try:
            response = (
                self.client.describe_logging_configuration(
                    FirewallArn=firewall_arn,
                )
            )

            return response.get(
                "LoggingConfiguration"
            ) or {}

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")

            if code == "ResourceNotFoundException":
                return {}

            self._raise_api_error(
                f"logging configuration lookup for "
                f"{firewall_arn}",
                exc,
            )
            raise AssertionError("unreachable")

        except BotoCoreError as exc:
            self._raise_api_error(
                "logging configuration discovery",
                exc,
            )
            raise AssertionError("unreachable")
