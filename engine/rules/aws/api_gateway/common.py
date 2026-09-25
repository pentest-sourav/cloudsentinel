from engine.findings.model import Finding


def build_finding(
    *,
    rule_id: str,
    title: str,
    severity,
    resource_type: str,
    result: dict,
    description: str,
    remediation: str,
    compliance: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        provider="aws",
        resource_type=resource_type,
        resource_id=result["resource_id"],
        description=description,
        evidence=result.get("evidence", {}),
        remediation=remediation,
        compliance=[compliance],
    )
