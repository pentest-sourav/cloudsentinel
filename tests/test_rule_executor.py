from dataclasses import dataclass

import pytest

from engine.findings.model import Finding, Severity
from engine.rules.executor import RuleExecutor
from engine.rules.model import RuleDefinition


@dataclass(frozen=True)
class FakeResult:
    passed: bool


def check_single(value: bool) -> FakeResult:
    return FakeResult(passed=value)


def build_single_finding(
    result: FakeResult,
) -> Finding | None:
    if result.passed:
        return None

    return Finding(
        rule_id="TEST-001",
        title="Test Rule Failed",
        severity=Severity.HIGH,
        provider="test",
        resource_type="test_resource",
        resource_id="test-1",
        description="Test finding.",
    )


def check_multiple(name: str, enabled: bool) -> FakeResult:
    return FakeResult(passed=enabled)


def build_multiple_finding(
    result: FakeResult,
) -> Finding | None:
    if result.passed:
        return None

    return Finding(
        rule_id="TEST-002",
        title="Test Multiple Rule Failed",
        severity=Severity.MEDIUM,
        provider="test",
        resource_type="test_resource",
        resource_id="test",
        description="Test multiple finding.",
    )


class FakeCollector:
    def collect_single(self) -> dict:
        return {"value": False}

    def collect_multiple(self) -> list[dict]:
        return [
            {"name": "resource-1", "enabled": False},
            {"name": "resource-2", "enabled": True},
        ]


def test_execute_single_rule():
    executor = RuleExecutor(
        handlers={
            "test_single": FakeCollector.collect_single,
        }
    )

    rule = RuleDefinition(
        rule_id="TEST-001",
        name="test_single",
        data_source="test_single",
        collection_mode="single",
        check_arguments=["value"],
        check=check_single,
        build_finding=build_single_finding,
    )

    findings = executor.execute_rule(
        rule=rule,
        collector=FakeCollector(),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "TEST-001"


def test_execute_multiple_rule():
    executor = RuleExecutor(
        handlers={
            "test_multiple": FakeCollector.collect_multiple,
        }
    )

    rule = RuleDefinition(
        rule_id="TEST-002",
        name="test_multiple",
        data_source="test_multiple",
        collection_mode="multiple",
        check_arguments=["name", "enabled"],
        check=check_multiple,
        build_finding=build_multiple_finding,
    )

    findings = executor.execute_rule(
        rule=rule,
        collector=FakeCollector(),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "TEST-002"


def test_execute_registry():
    executor = RuleExecutor(
        handlers={
            "test_single": FakeCollector.collect_single,
        }
    )

    rule = RuleDefinition(
        rule_id="TEST-001",
        name="test_single",
        data_source="test_single",
        collection_mode="single",
        check_arguments=["value"],
        check=check_single,
        build_finding=build_single_finding,
    )

    class FakeRegistry:
        def list_rules(self):
            return [rule]

    findings = executor.execute_registry(
        registry=FakeRegistry(),
        collector=FakeCollector(),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "TEST-001"


def test_missing_handler_raises_key_error():
    executor = RuleExecutor(handlers={})

    rule = RuleDefinition(
        rule_id="TEST-003",
        name="missing_handler",
        data_source="missing",
        collection_mode="single",
        check_arguments=["value"],
        check=check_single,
        build_finding=build_single_finding,
    )

    with pytest.raises(KeyError, match="No data source handler"):
        executor.execute_rule(
            rule=rule,
            collector=FakeCollector(),
        )


def test_unsupported_collection_mode_raises_value_error():
    executor = RuleExecutor(
        handlers={
            "test_invalid": lambda collector: {"value": False},
        }
    )

    rule = RuleDefinition(
        rule_id="TEST-004",
        name="test_invalid",
        data_source="test_invalid",
        collection_mode="invalid",
        check_arguments=["value"],
        check=check_single,
        build_finding=build_single_finding,
    )

    with pytest.raises(
        ValueError,
        match="Unsupported collection mode",
    ):
        executor.execute_rule(
            rule=rule,
            collector=FakeCollector(),
        )


def test_execute_iam_020_no_active_authentication_credential_rule():
    from engine.rules.registry.iam_handlers import (
        collect_no_active_authentication_credentials,
    )
    from engine.rules.registry.iam_registry import IAM_RULES

    class IAM020Collector:
        def collect_no_active_authentication_credentials(self):
            return [
                {
                    "username": "alice",
                    "password_enabled": False,
                    "active_access_key_count": 0,
                    "active_access_key_ids": [],
                },
                {
                    "username": "bob",
                    "password_enabled": True,
                    "active_access_key_count": 0,
                    "active_access_key_ids": [],
                },
                {
                    "username": "charlie",
                    "password_enabled": False,
                    "active_access_key_count": 1,
                    "active_access_key_ids": ["AKIACHARLIE01"],
                },
            ]

    rule = IAM_RULES.get_rule("CS-AWS-IAM-020")

    assert rule is not None

    executor = RuleExecutor(
        handlers={
            "no_active_authentication_credentials": (
                collect_no_active_authentication_credentials
            ),
        }
    )

    findings = executor.execute_rule(
        rule=rule,
        collector=IAM020Collector(),
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-IAM-020"
    assert finding.title == (
        "IAM User Has No Active Authentication Credential"
    )
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"

    assert finding.evidence == {
        "username": "alice",
        "password_enabled": False,
        "active_access_key_count": 0,
        "active_access_key_ids": [],
        "has_active_authentication_credential": False,
    }
