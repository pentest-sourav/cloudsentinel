from typing import Any

from scanner.aws.models.security_group_normalizer import (
    SecurityGroupNormalizer,
)


class SecurityGroupRuleCollector:
    """
    Converts raw AWS security-group responses into
    RuleExecutor-compatible security-group rule records.

    Security analysis is not performed here.
    """

    def collect(
        self,
        security_groups: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        collected_rules: list[dict[str, Any]] = []

        for security_group in security_groups:
            security_group_id = security_group.get("GroupId")

            if not security_group_id:
                continue

            normalized_rules = (
                SecurityGroupNormalizer.normalize_security_group(
                    security_group
                )
            )

            for rule in normalized_rules:
                collected_rules.append(
                    {
                        "security_group_id": security_group_id,
                        "rule": rule,
                    }
                )

        return collected_rules
