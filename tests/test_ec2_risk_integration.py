from engine.findings.model import Finding, Severity
from engine.risk.assessment import assess_finding_risk
from engine.risk.enrichment import enrich_risk_context


def test_ec2_public_management_exposure_gets_higher_risk():
    finding = Finding(
        rule_id="CS-AWS-EC2-001",
        title="SSH Port Exposed to the Internet",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ec2_security_group",
        resource_id="sg-public-ssh",
        description="SSH is publicly exposed.",
        evidence={
            "security_group_id": "sg-public-ssh",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "source": "0.0.0.0/0",
            "internet_exposed": True,
            "exposure_type": "ssh_port_range",
            "management_service": "SSH",
        },
        remediation="Restrict SSH access to trusted source IP ranges.",
        compliance=["CIS AWS Foundations"],
    )

    context = enrich_risk_context(finding)

    risk = assess_finding_risk(
        finding=finding,
        context=context,
    )

    assert context.internet_exposed is True
    assert risk.score == 8.0
    assert risk.level.value == "high"
    assert risk.factors["base_severity"] == 7.0
    assert risk.factors["internet_exposure"] == 1.0
    assert risk.factors["sensitive_data"] == 0.0
    assert risk.factors["asset_criticality"] == 0.0
    assert risk.factors["exploitability"] == 0.0
