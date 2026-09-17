from engine.findings.model import Finding
from engine.risk.model import RiskContext


def enrich_risk_context(finding: Finding) -> RiskContext:
    """
    Build a RiskContext from finding evidence.

    Evidence is used as the primary source for contextual
    risk signals discovered by scanners and rules.
    """

    evidence = finding.evidence

    internet_exposed = bool(
        evidence.get(
            "internet_exposed",
            evidence.get("public_access_signal", False),
        )
    )

    sensitive_data = bool(
        evidence.get("sensitive_data", False)
    )

    asset_criticality = evidence.get(
        "asset_criticality",
        1,
    )

    exploitability = evidence.get(
        "exploitability",
        1,
    )

    return RiskContext(
        internet_exposed=internet_exposed,
        sensitive_data=sensitive_data,
        asset_criticality=asset_criticality,
        exploitability=exploitability,
    )
