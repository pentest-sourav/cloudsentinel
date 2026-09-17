from engine.findings.model import Finding, Severity
from engine.risk.enrichment import enrich_risk_context


def make_finding(evidence: dict) -> Finding:
    return Finding(
        rule_id="CS-AWS-S3-001",
        title="S3 Public Access",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="test-bucket",
        description="Test finding",
        evidence=evidence,
        remediation="Fix the configuration.",
        compliance=[],
    )


def test_enrichment_detects_internet_exposure():
    finding = make_finding({
        "public_access_signal": True,
    })

    context = enrich_risk_context(finding)

    assert context.internet_exposed is True


def test_enrichment_detects_sensitive_data():
    finding = make_finding({
        "sensitive_data": True,
    })

    context = enrich_risk_context(finding)

    assert context.sensitive_data is True


def test_enrichment_uses_asset_criticality():
    finding = make_finding({
        "asset_criticality": 5,
    })

    context = enrich_risk_context(finding)

    assert context.asset_criticality == 5


def test_enrichment_uses_exploitability():
    finding = make_finding({
        "exploitability": 4,
    })

    context = enrich_risk_context(finding)

    assert context.exploitability == 4


def test_enrichment_defaults_to_safe_values():
    finding = make_finding({})

    context = enrich_risk_context(finding)

    assert context.internet_exposed is False
    assert context.sensitive_data is False
    assert context.asset_criticality == 1
    assert context.exploitability == 1

def test_enrichment_prefers_explicit_internet_exposure():
    finding = make_finding({
        "internet_exposed": False,
        "public_access_signal": True,
    })

    context = enrich_risk_context(finding)

    assert context.internet_exposed is False
