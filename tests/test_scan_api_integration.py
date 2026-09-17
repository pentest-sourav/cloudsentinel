from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.finding import Finding as FindingModel
from backend.app.models.scan import Scan
from engine.findings.model import Finding, Severity


def test_aws_scan_api_persists_findings(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    fake_finding = Finding(
        rule_id="CS-AWS-S3-001",
        title="S3 Public Access Block Not Fully Enabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="s3_bucket",
        resource_id="test-insecure-bucket",
        description="S3 Public Access Block is not fully enabled.",
        evidence={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
        },
        remediation="Enable all S3 Public Access Block settings.",
        compliance=["CIS AWS Foundations"],
    )

    monkeypatch.setattr(
        "backend.app.api.routes.scans.run_aws_scan",
        lambda: [fake_finding],
    )

    client = TestClient(app)

    try:
        response = client.post(
            "/api/v1/scans",
            json={"provider": "aws"},
        )

        assert response.status_code == 201

        data = response.json()

        assert data["provider"] == "aws"
        assert data["status"] == "completed"
        assert data["error_message"] is None

        db = SessionLocal()

        try:
            scan = (
                db.query(Scan)
                .filter(Scan.id == data["id"])
                .first()
            )

            assert scan is not None
            assert scan.status == "completed"

            findings = (
                db.query(FindingModel)
                .filter(FindingModel.scan_id == scan.id)
                .all()
            )

            assert len(findings) == 1
            assert findings[0].rule_id == "CS-AWS-S3-001"
            assert findings[0].severity == "high"
            assert findings[0].risk_score == 7.0
            assert findings[0].risk_level == "high"
            assert findings[0].resource_id == "test-insecure-bucket"

        finally:
            db.close()

    finally:
        app.dependency_overrides.clear()
