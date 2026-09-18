from backend.app.models.scan import Scan
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from engine.findings.model import Finding as EngineFinding, Severity
from backend.app.models.finding import Finding as FindingModel
from engine.risk.assessment import assess_finding_risk
from engine.risk.context import build_risk_context


def create_finding(
    db: Session,
    scan_id: int,
    rule_id: str,
    title: str,
    severity: str,
    provider: str,
    resource_type: str,
    resource_id: str,
    description: str,
    evidence: dict,
    remediation: str,
    compliance: list,
) -> FindingModel:
    engine_finding = EngineFinding(
        rule_id=rule_id,
        title=title,
        severity=Severity(severity),
        provider=provider,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        evidence=evidence,
        remediation=remediation,
        compliance=compliance,
    )

    risk_context = build_risk_context(engine_finding)

    risk_score = assess_finding_risk(
        finding=engine_finding,
        context=risk_context,
    )

    finding = FindingModel(
        scan_id=scan_id,
        rule_id=engine_finding.rule_id,
        title=engine_finding.title,
        severity=engine_finding.severity.value,
        risk_score=risk_score.score,
        risk_level=risk_score.level.value,
        provider=engine_finding.provider,
        resource_type=engine_finding.resource_type,
        resource_id=engine_finding.resource_id,
        description=engine_finding.description,
        evidence=engine_finding.evidence,
        remediation=engine_finding.remediation,
        compliance=engine_finding.compliance,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding


def persist_finding(
    db: Session,
    scan_id: int,
    finding: EngineFinding,
) -> FindingModel:
    """
    Convert an engine Finding into a database Finding,
    calculate its effective risk, and persist it.
    """

    risk_context = build_risk_context(finding)

    risk_score = assess_finding_risk(
        finding=finding,
        context=risk_context,
    )

    db_finding = FindingModel(
        scan_id=scan_id,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity.value,
        risk_score=risk_score.score,
        risk_level=risk_score.level.value,
        provider=finding.provider,
        resource_type=finding.resource_type,
        resource_id=finding.resource_id,
        description=finding.description,
        evidence=finding.evidence,
        remediation=finding.remediation,
        compliance=finding.compliance,
    )

    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)

    return db_finding


def get_findings_by_scan(
    db: Session,
    scan_id: int,
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    risk_level: str | None = None,
) -> dict | None:
    scan_exists = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if scan_exists is None:
        return None

    statement = (
        select(FindingModel)
        .where(FindingModel.scan_id == scan_id)
        .order_by(FindingModel.id.desc())
        .limit(limit)
        .offset(offset)
    )

    count_statement = (
        select(func.count())
        .select_from(FindingModel)
        .where(FindingModel.scan_id == scan_id)
    )

    if severity is not None:
        statement = statement.where(
            FindingModel.severity == severity.lower()
        )

        count_statement = count_statement.where(
            FindingModel.severity == severity.lower()
        )

    if risk_level is not None:
        statement = statement.where(
            FindingModel.risk_level == risk_level.lower()
        )

        count_statement = count_statement.where(
            FindingModel.risk_level == risk_level.lower()
        )

    findings = list(db.scalars(statement).all())
    total = db.scalar(count_statement) or 0

    return {
        "items": findings,
        "total": total,
        "limit": limit,
        "offset": offset,
    }

def get_finding(
    db: Session,
    finding_id: int,
) -> FindingModel | None:
    return (
        db.query(FindingModel)
        .filter(FindingModel.id == finding_id)
        .first()
    )
