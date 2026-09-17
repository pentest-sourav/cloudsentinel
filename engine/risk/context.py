from engine.findings.model import Finding
from engine.risk.enrichment import enrich_risk_context
from engine.risk.model import RiskContext


def build_risk_context(
    finding: Finding,
) -> RiskContext:
    """
    Build a RiskContext using the risk enrichment layer.

    Kept as a compatibility wrapper for existing callers.
    """

    return enrich_risk_context(finding)
