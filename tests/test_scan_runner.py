from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.scan import Scan
from backend.app.models.finding import Finding as FindingModel
from backend.app.services.scan_runner import ScanRunner
from engine.findings.model import Finding, Severity


def test_scan_runner_persists_findings_and_completes_scan():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="pending",
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
            },
            remediation="Enable all S3 Public Access Block settings.",
            compliance=["CIS AWS Foundations"],
        )

        runner = ScanRunner(db=db)

        result = runner.run(
            scan=scan,
            findings=[engine_finding],
        )

        assert result.id == scan.id
        assert result.status == "completed"
        assert result.started_at is not None
        assert result.completed_at is not None

        findings = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .all()
        )

        assert len(findings) == 1
        assert findings[0].rule_id == "CS-AWS-S3-001"
        assert findings[0].severity == "high"
        assert findings[0].resource_id == "test-bucket"

    finally:
        db.close()
