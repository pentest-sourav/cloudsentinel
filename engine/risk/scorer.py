from engine.risk.model import RiskContext, RiskLevel, RiskScore


SEVERITY_BASE_SCORE = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


def calculate_risk(
    severity: str,
    context: RiskContext,
) -> RiskScore:
    """
    Calculate an effective risk score from finding severity
    and contextual security factors.
    """

    normalized_severity = severity.lower()

    if normalized_severity not in SEVERITY_BASE_SCORE:
        raise ValueError(
            f"Unsupported severity: {severity}"
        )

    base_score = SEVERITY_BASE_SCORE[normalized_severity]

    exposure_factor = 0.0
    sensitivity_factor = 0.0
    criticality_factor = 0.0
    exploitability_factor = 0.0

    if context.internet_exposed:
        exposure_factor = 1.0

    if context.sensitive_data:
        sensitivity_factor = 1.0

    criticality_factor = (
        max(1, min(context.asset_criticality, 5)) - 1
    ) * 0.25

    exploitability_factor = (
        max(1, min(context.exploitability, 5)) - 1
    ) * 0.25

    raw_score = (
        base_score
        + exposure_factor
        + sensitivity_factor
        + criticality_factor
        + exploitability_factor
    )

    score = min(10.0, round(raw_score, 2))

    if score >= 9.0:
        level = RiskLevel.CRITICAL
    elif score >= 7.0:
        level = RiskLevel.HIGH
    elif score >= 4.0:
        level = RiskLevel.MEDIUM
    elif score >= 2.0:
        level = RiskLevel.LOW
    else:
        level = RiskLevel.INFO

    return RiskScore(
        score=score,
        level=level,
        factors={
            "base_severity": base_score,
            "internet_exposure": exposure_factor,
            "sensitive_data": sensitivity_factor,
            "asset_criticality": criticality_factor,
            "exploitability": exploitability_factor,
        },
    )
