import pytest

from engine.risk.model import RiskContext, RiskLevel
from engine.risk.scorer import calculate_risk


def test_critical_risk_reaches_critical_level():
    context = RiskContext(
        internet_exposed=True,
        sensitive_data=True,
        asset_criticality=5,
        exploitability=5,
    )

    result = calculate_risk(
        severity="critical",
        context=context,
    )

    assert result.level == RiskLevel.CRITICAL
    assert result.score == 10.0


def test_low_risk_stays_low():
    context = RiskContext(
        internet_exposed=False,
        sensitive_data=False,
        asset_criticality=1,
        exploitability=1,
    )

    result = calculate_risk(
        severity="low",
        context=context,
    )

    assert result.level == RiskLevel.LOW
    assert result.score < 4.0


def test_risk_score_is_bounded():
    context = RiskContext(
        internet_exposed=True,
        sensitive_data=True,
        asset_criticality=5,
        exploitability=5,
    )

    result = calculate_risk(
        severity="critical",
        context=context,
    )

    assert 0.0 <= result.score <= 10.0


def test_severity_is_case_insensitive():
    context = RiskContext()

    result = calculate_risk(
        severity="HIGH",
        context=context,
    )

    assert result.level == RiskLevel.HIGH


def test_invalid_severity_is_rejected():
    context = RiskContext()

    with pytest.raises(ValueError):
        calculate_risk(
            severity="unknown",
            context=context,
        )


def test_context_values_are_clamped():
    context = RiskContext(
        internet_exposed=False,
        sensitive_data=False,
        asset_criticality=100,
        exploitability=100,
    )

    result = calculate_risk(
        severity="medium",
        context=context,
    )

    assert result.score == 7.0
    assert result.level == RiskLevel.HIGH
