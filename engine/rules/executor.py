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
    - applying optional per-rule parameter overrides

    Cloud/provider-specific collection logic remains outside
    this layer.
    """

    def __init__(
        self,
        handlers: dict[str, Callable[..., Any]],
        rule_parameters: dict[str, dict[str, Any]] | None = None,
    ):
        self.handlers = handlers
        self.rule_parameters = rule_parameters or {}

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

    def _evaluate_single(
        self,
        rule: RuleDefinition,
        collected_data: dict[str, Any],
    ) -> Finding | None:
        check_data = {
            argument: collected_data[argument]
            for argument in rule.check_arguments
        }

        parameters = dict(rule.parameters)

        configured_parameters = self.rule_parameters.get(
            rule.rule_id,
            {},
        )

        if isinstance(configured_parameters, dict):
            parameters.update(configured_parameters)

        check_data.update(parameters)

        result = rule.check(**check_data)

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
