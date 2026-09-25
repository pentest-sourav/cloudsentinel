from typing import Any

from scanner.aws.services.waf import WAFService


class WAFDataCollector:
    """
    Normalize AWS WAFv2 configuration for CloudSentinel rules.
    """

    def __init__(self, service: WAFService):
        self.service = service

        self._web_acls_cache: list[dict[str, Any]] | None = None
        self._rule_groups_cache: list[dict[str, Any]] | None = None

    def _collect_web_acls(self) -> list[dict[str, Any]]:
        if self._web_acls_cache is not None:
            return self._web_acls_cache

        normalized: list[dict[str, Any]] = []

        for scope in ("REGIONAL", "CLOUDFRONT"):
            for summary in self.service.list_web_acls(scope):
                name = summary.get("Name")
                web_acl_id = summary.get("Id")
                arn = summary.get("ARN")

                if not isinstance(name, str) or not name:
                    continue

                if not isinstance(web_acl_id, str) or not web_acl_id:
                    continue

                if not isinstance(arn, str) or not arn:
                    continue

                web_acl = self.service.get_web_acl(
                    scope=scope,
                    name=name,
                    web_acl_id=web_acl_id,
                )

                logging_configuration = (
                    self.service.get_logging_configuration(
                        scope=scope,
                        resource_arn=arn,
                    )
                )

                rules = web_acl.get("Rules") or []

                normalized.append(
                    {
                        "resource_id": web_acl_id,
                        "resource_arn": arn,
                        "name": name,
                        "scope": scope,
                        "rules": rules,
                        "rule_count": len(rules),
                        "logging_configuration": (
                            logging_configuration
                        ),
                        "resource": web_acl,
                    }
                )

        self._web_acls_cache = normalized
        return normalized

    def _collect_rule_groups(self) -> list[dict[str, Any]]:
        if self._rule_groups_cache is not None:
            return self._rule_groups_cache

        normalized: list[dict[str, Any]] = []

        for scope in ("REGIONAL", "CLOUDFRONT"):
            for summary in self.service.list_rule_groups(scope):
                name = summary.get("Name")
                rule_group_id = summary.get("Id")
                arn = summary.get("ARN")

                if not isinstance(name, str) or not name:
                    continue

                if not isinstance(
                    rule_group_id,
                    str,
                ) or not rule_group_id:
                    continue

                if not isinstance(arn, str) or not arn:
                    continue

                rule_group = self.service.get_rule_group(
                    scope=scope,
                    name=name,
                    rule_group_id=rule_group_id,
                )

                visibility_config = (
                    rule_group.get("VisibilityConfig")
                    or {}
                )

                normalized.append(
                    {
                        "resource_id": rule_group_id,
                        "resource_arn": arn,
                        "name": name,
                        "scope": scope,
                        "cloudwatch_metrics_enabled": (
                            visibility_config.get(
                                "CloudWatchMetricsEnabled"
                            )
                        ),
                        "metric_name": visibility_config.get(
                            "MetricName"
                        ),
                        "resource": rule_group,
                    }
                )

        self._rule_groups_cache = normalized
        return normalized

    def collect_web_acls(self) -> list[dict[str, Any]]:
        return self._collect_web_acls()

    def collect_rule_groups(self) -> list[dict[str, Any]]:
        return self._collect_rule_groups()
