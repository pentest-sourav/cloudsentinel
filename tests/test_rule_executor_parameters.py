from dataclasses import dataclass

from engine.findings.model import Finding, Severity
from engine.rules.executor import RuleExecutor
from engine.rules.model import RuleDefinition


@dataclass(frozen=True)
class DummyResult:
    value: str


def check_dummy(
    resource_id: str,
    required_value: str,
) -> DummyResult | None:
    if resource_id == required_value:
        return None

    return DummyResult(value=resource_id)


def build_dummy_finding(
    result: DummyResult,
) -> Finding:
    return Finding(
        rule_id="TEST-PARAM-001",
        title="Parameter Test",
        severity=Severity.LOW,
        provider="aws",
        resource_type="test",
        resource_id=result.value,
        description="parameter plumbing test",
        evidence={},
        remediation="none",
        compliance=[],
    )


class DummyCollector:
    def collect(self):
        return [
            {
                "resource_id": "configured",
            }
        ]


def collect_dummy(
    collector: DummyCollector,
):
    return collector.collect()


def test_rule_parameters_are_applied():
    rule = RuleDefinition(
        rule_id="TEST-PARAM-001",
        name="parameter_test",
        data_source="dummy",
        collection_mode="multiple",
        check_arguments=["resource_id"],
        check=check_dummy,
        build_finding=build_dummy_finding,
        parameters={
            "required_value": "default",
        },
    )

    executor = RuleExecutor(
        handlers={
            "dummy": collect_dummy,
        },
    )

    findings = executor.execute_rule(
        rule=rule,
        collector=DummyCollector(),
    )

    assert len(findings) == 1


def test_external_rule_parameters_override_rule_defaults():
    rule = RuleDefinition(
        rule_id="TEST-PARAM-001",
        name="parameter_test",
        data_source="dummy",
        collection_mode="multiple",
        check_arguments=["resource_id"],
        check=check_dummy,
        build_finding=build_dummy_finding,
        parameters={
            "required_value": "default",
        },
    )

    executor = RuleExecutor(
        handlers={
            "dummy": collect_dummy,
        },
        rule_parameters={
            "TEST-PARAM-001": {
                "required_value": "configured",
            },
        },
    )

    findings = executor.execute_rule(
        rule=rule,
        collector=DummyCollector(),
    )

    assert findings == []
