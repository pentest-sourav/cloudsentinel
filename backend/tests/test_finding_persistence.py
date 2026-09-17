from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.cloud_account import CloudAccount
from backend.app.models.scan import Scan
from backend.app.models.finding import Finding as FindingModel
from backend.app.services.finding_service import persist_finding
from engine.findings.model import Finding, Severity


def test_persist_engine_finding():
    engine = create_engine("sqlite:///:memory:")

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

        engine_finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access Block Not Fully Enabled",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="test-bucket",
            description="S3 Public Access Block is not fully enabled.",
            evidence={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
            },
            remediation="Enable all S3 Public Access Block settings.",
            compliance=["CIS AWS Foundations"],
        )

        db_finding = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=engine_finding,
        )

        assert db_finding.id is not None
        assert db_finding.scan_id == scan.id
        assert db_finding.rule_id == "CS-AWS-S3-001"
        assert db_finding.severity == "high"
        assert db_finding.provider == "aws"
        assert db_finding.resource_id == "test-bucket"
        assert db_finding.evidence["BlockPublicAcls"] is False
        assert db_finding.compliance == ["CIS AWS Foundations"]

    finally:
        db.close()
