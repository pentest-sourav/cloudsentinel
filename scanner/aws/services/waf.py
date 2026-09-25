from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class WAFService:
    """
    Read-only AWS WAFv2 discovery service.

    Collects Web ACLs, Web ACL logging configuration, and rule groups
    across both REGIONAL and CLOUDFRONT scopes.
    """

    CLOUDFRONT_REGION = "us-east-1"

    def __init__(self, session):
        self.session = session

        self.regional_client = create_aws_client(
            session,
            "wafv2",
        )

        self.cloudfront_client = create_aws_client(
            session,
            "wafv2",
            region_name=self.CLOUDFRONT_REGION,
        )

    def _client_for_scope(self, scope: str):
        if scope == "CLOUDFRONT":
            return self.cloudfront_client

        if scope == "REGIONAL":
            return self.regional_client

        raise ValueError(f"Unsupported WAF scope: {scope}")

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
                f"WAF {operation} failed: {code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during WAF {operation}: {exc}"
        ) from exc

    def list_web_acls(
        self,
        scope: str,
    ) -> list[dict[str, Any]]:
        client = self._client_for_scope(scope)

        try:
            paginator = client.get_paginator("list_web_acls")

            web_acls: list[dict[str, Any]] = []

            for page in paginator.paginate(Scope=scope):
                web_acls.extend(
                    page.get("WebACLs", [])
                )

            return web_acls

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "web ACL discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_web_acl(
        self,
        scope: str,
        name: str,
        web_acl_id: str,
    ) -> dict[str, Any]:
        client = self._client_for_scope(scope)

        try:
            response = client.get_web_acl(
                Name=name,
                Scope=scope,
                Id=web_acl_id,
            )

            return response.get("WebACL") or {}

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"Web ACL lookup for {name}",
                exc,
            )
            raise AssertionError("unreachable")

    def get_logging_configuration(
        self,
        scope: str,
        resource_arn: str,
    ) -> dict[str, Any]:
        client = self._client_for_scope(scope)

        try:
            response = client.get_logging_configuration(
                ResourceArn=resource_arn,
            )

            return response.get(
                "LoggingConfiguration"
            ) or {}

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")

            if code in {
                "WAFNonexistentItemException",
                "WAFUnavailableEntityException",
            }:
                return {}

            self._raise_api_error(
                "Web ACL logging discovery",
                exc,
            )
            raise AssertionError("unreachable")

        except BotoCoreError as exc:
            self._raise_api_error(
                "Web ACL logging discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def list_rule_groups(
        self,
        scope: str,
    ) -> list[dict[str, Any]]:
        client = self._client_for_scope(scope)

        try:
            paginator = client.get_paginator(
                "list_rule_groups"
            )

            rule_groups: list[dict[str, Any]] = []

            for page in paginator.paginate(Scope=scope):
                rule_groups.extend(
                    page.get("RuleGroups", [])
                )

            return rule_groups

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "rule group discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def get_rule_group(
        self,
        scope: str,
        name: str,
        rule_group_id: str,
    ) -> dict[str, Any]:
        client = self._client_for_scope(scope)

        try:
            response = client.get_rule_group(
                Name=name,
                Scope=scope,
                Id=rule_group_id,
            )

            return response.get("RuleGroup") or {}

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"rule group lookup for {name}",
                exc,
            )
            raise AssertionError("unreachable")
