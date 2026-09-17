from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.finding import Finding as FindingModel
from backend.app.models.scan import Scan
from backend.app.services.finding_service import persist_finding
from engine.findings.model import Finding, Severity


def test_persist_finding_stores_risk_data():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="test-bucket",
            description="Bucket has a public access signal.",
            evidence={
                "internet_exposed": True,
                "sensitive_data": True,
                "asset_criticality": 4,
                "exploitability": 3,
            },
        )

        db_finding = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=finding,
        )

        assert db_finding.risk_score == 10.0
        assert db_finding.risk_level == "critical"
        assert db_finding.severity == "high"

    finally:
        db.close()
