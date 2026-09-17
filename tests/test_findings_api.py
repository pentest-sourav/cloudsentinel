from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.finding import Finding as FindingModel
from backend.app.models.scan import Scan


def test_get_finding_returns_risk_fields():
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

    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="completed",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding = FindingModel(
            scan_id=scan.id,
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access",
            severity="high",
            risk_score=9.5,
            risk_level="critical",
            provider="aws",
            resource_type="s3_bucket",
            resource_id="test-bucket",
            description="Test finding",
            evidence={},
            remediation="Fix the configuration.",
            compliance=[],
        )

        db.add(finding)
        db.commit()
        db.refresh(finding)

        client = TestClient(app)

        response = client.get(
            f"/api/v1/findings/{finding.id}"
        )

        assert response.status_code == 200

        data = response.json()

        assert data["rule_id"] == "CS-AWS-S3-001"
        assert data["severity"] == "high"
        assert data["risk_score"] == 9.5
        assert data["risk_level"] == "critical"

    finally:
        db.close()
        app.dependency_overrides.clear()
