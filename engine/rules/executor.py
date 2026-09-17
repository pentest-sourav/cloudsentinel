from collections.abc import Callable
from typing import Any

from engine.findings.model import Finding
from engine.rules.model import RuleDefinition


class RuleExecutor:
    """
    Generic execution engine for CloudSentinel security rules.

    The executor is responsible for:
    - resolving the rule's data source handler
    - collecting required configuration data
    - executing the rule check
    - building a Finding when the check fails

    Cloud/provider-specific collection logic remains outside
    this layer.
    """

    def __init__(
        self,
        handlers: dict[str, Callable[..., Any]],
    ):
        self.handlers = handlers

    def execute_rule(
        self,
        rule: RuleDefinition,
        collector: Any,
    ) -> list[Finding]:
        handler = self.handlers.get(rule.data_source)

        if handler is None:
            raise KeyError(
                f"No data source handler registered for "
                f"'{rule.data_source}'"
            )

        collected_data = handler(collector)

        findings: list[Finding] = []

        if rule.collection_mode == "single":
            finding = self._evaluate_single(
                rule=rule,
                collected_data=collected_data,
            )

            if finding is not None:
                findings.append(finding)

        elif rule.collection_mode == "multiple":
            for item in collected_data:
                finding = self._evaluate_single(
                    rule=rule,
                    collected_data=item,
                )

                if finding is not None:
                    findings.append(finding)

        else:
            raise ValueError(
                f"Unsupported collection mode: "
                f"{rule.collection_mode}"
            )

        return findings

    @staticmethod
    def _evaluate_single(
        rule: RuleDefinition,
        collected_data: dict[str, Any],
    ) -> Finding | None:
        result = rule.check(**collected_data)

        if result is None:
            return None

        return rule.build_finding(result)

    def execute_registry(
        self,
        registry: Any,
        collector: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for rule in registry.list_rules():
            findings.extend(
                self.execute_rule(
                    rule=rule,
                    collector=collector,
                )
            )

        return findings
