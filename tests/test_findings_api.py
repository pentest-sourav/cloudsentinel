from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.finding import Finding as FindingModel
from backend.app.models.scan import Scan


def create_test_db():
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

    return engine, SessionLocal


def test_get_finding_returns_risk_fields():
    engine, SessionLocal = create_test_db()

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


def test_list_findings_returns_paginated_results():
    engine, SessionLocal = create_test_db()

    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="completed",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        findings = [
            FindingModel(
                scan_id=scan.id,
                rule_id=f"CS-AWS-S3-00{i}",
                title=f"Finding {i}",
                severity="high",
                risk_score=8.0,
                risk_level="high",
                provider="aws",
                resource_type="s3_bucket",
                resource_id=f"bucket-{i}",
                description="Test finding",
                evidence={},
                remediation="Fix it.",
                compliance=[],
            )
            for i in range(1, 6)
        ]

        db.add_all(findings)
        db.commit()

        client = TestClient(app)

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}?limit=2&offset=1"
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 5
        assert data["limit"] == 2
        assert data["offset"] == 1

        assert len(data["items"]) == 2

        # Newest findings first
        assert data["items"][0]["id"] == findings[3].id
        assert data["items"][1]["id"] == findings[2].id

    finally:
        db.close()
        app.dependency_overrides.clear()


def test_list_findings_filters_by_severity():
    engine, SessionLocal = create_test_db()

    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="completed",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        findings = [
            FindingModel(
                scan_id=scan.id,
                rule_id="CS-001",
                title="Critical finding",
                severity="critical",
                risk_score=9.5,
                risk_level="critical",
                provider="aws",
                resource_type="s3_bucket",
                resource_id="critical-bucket",
                description="Critical test finding",
                evidence={},
                remediation="Fix it.",
                compliance=[],
            ),
            FindingModel(
                scan_id=scan.id,
                rule_id="CS-002",
                title="High finding",
                severity="high",
                risk_score=8.0,
                risk_level="high",
                provider="aws",
                resource_type="s3_bucket",
                resource_id="high-bucket",
                description="High test finding",
                evidence={},
                remediation="Fix it.",
                compliance=[],
            ),
            FindingModel(
                scan_id=scan.id,
                rule_id="CS-003",
                title="Low finding",
                severity="low",
                risk_score=3.0,
                risk_level="low",
                provider="aws",
                resource_type="s3_bucket",
                resource_id="low-bucket",
                description="Low test finding",
                evidence={},
                remediation="Fix it.",
                compliance=[],
            ),
        ]

        db.add_all(findings)
        db.commit()

        client = TestClient(app)

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}?severity=high"
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 1
        assert len(data["items"]) == 1

        assert data["items"][0]["severity"] == "high"
        assert data["items"][0]["rule_id"] == "CS-002"

    finally:
        db.close()
        app.dependency_overrides.clear()


def test_list_findings_filters_by_risk_level():
    engine, SessionLocal = create_test_db()

    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="completed",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        findings = [
            FindingModel(
                scan_id=scan.id,
                rule_id="CS-001",
                title="Critical risk",
                severity="high",
                risk_score=9.5,
                risk_level="critical",
                provider="aws",
                resource_type="s3_bucket",
                resource_id="critical-bucket",
                description="Critical risk finding",
                evidence={},
                remediation="Fix it.",
                compliance=[],
            ),
            FindingModel(
                scan_id=scan.id,
                rule_id="CS-002",
                title="High risk",
                severity="high",
                risk_score=7.5,
                risk_level="high",
                provider="aws",
                resource_type="s3_bucket",
                resource_id="high-bucket",
                description="High risk finding",
                evidence={},
                remediation="Fix it.",
                compliance=[],
            ),
        ]

        db.add_all(findings)
        db.commit()

        client = TestClient(app)

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}?risk_level=critical"
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 1
        assert len(data["items"]) == 1

        assert data["items"][0]["risk_level"] == "critical"
        assert data["items"][0]["rule_id"] == "CS-001"

    finally:
        db.close()
        app.dependency_overrides.clear()


def test_list_findings_returns_404_for_missing_scan():
    engine, SessionLocal = create_test_db()

    db = SessionLocal()

    try:
        client = TestClient(app)

        response = client.get(
            "/api/v1/findings/scan/99999"
        )

        assert response.status_code == 404

    finally:
        db.close()
        app.dependency_overrides.clear()


def test_list_findings_rejects_invalid_limit():
    engine, SessionLocal = create_test_db()

    db = SessionLocal()

    try:
        client = TestClient(app)

        response = client.get(
            "/api/v1/findings/scan/1?limit=0"
        )

        assert response.status_code == 422

    finally:
        db.close()
        app.dependency_overrides.clear()


def test_list_findings_rejects_negative_offset():
    engine, SessionLocal = create_test_db()

    db = SessionLocal()

    try:
        client = TestClient(app)

        response = client.get(
            "/api/v1/findings/scan/1?offset=-1"
        )

        assert response.status_code == 422

    finally:
        db.close()
        app.dependency_overrides.clear()

def test_list_findings_rejects_invalid_severity():
    client = TestClient(app)

    response = client.get(
        "/api/v1/findings/scan/1?severity=random"
    )

    assert response.status_code == 422


def test_list_findings_rejects_invalid_risk_level():
    client = TestClient(app)

    response = client.get(
        "/api/v1/findings/scan/1?risk_level=random"
    )

    assert response.status_code == 422
