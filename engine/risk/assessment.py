from engine.findings.model import Finding
from engine.risk.model import RiskContext, RiskScore
from engine.risk.scorer import calculate_risk


def assess_finding_risk(
    finding: Finding,
    context: RiskContext,
) -> RiskScore:
    """
    Calculate effective risk for a CloudSentinel finding.
    """

    return calculate_risk(
        severity=finding.severity.value,
        context=context,
    )
