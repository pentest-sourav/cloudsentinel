from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan


engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def setup_test_environment():
    """
    Reset the test database and FastAPI dependency override
    before and after every test.
    """

    db = TestingSessionLocal()

    try:
        db.query(Finding).delete()
        db.query(Scan).delete()
        db.commit()
    finally:
        db.close()

    def override_get_db():
        db = TestingSessionLocal()

        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    yield

    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def client():
    return TestClient(app)


def setup_scan_with_findings():
    db = TestingSessionLocal()

    scan = Scan(
        provider="aws",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    findings = [
        Finding(
            scan_id=scan.id,
            rule_id="TEST-CRITICAL",
            title="Critical Test Finding",
            severity="critical",
            risk_score=9.0,
            risk_level="critical",
            provider="aws",
            resource_type="test_resource",
            resource_id="resource-critical",
            description="Critical test finding",
            evidence={},
            remediation="Test remediation",
            compliance=["Test"],
        ),
        Finding(
            scan_id=scan.id,
            rule_id="TEST-HIGH",
            title="High Test Finding",
            severity="high",
            risk_score=7.0,
            risk_level="high",
            provider="aws",
            resource_type="test_resource",
            resource_id="resource-high",
            description="High test finding",
            evidence={},
            remediation="Test remediation",
            compliance=["Test"],
        ),
        Finding(
            scan_id=scan.id,
            rule_id="TEST-MEDIUM-1",
            title="Medium Test Finding 1",
            severity="medium",
            risk_score=5.0,
            risk_level="medium",
            provider="aws",
            resource_type="test_resource",
            resource_id="resource-medium-1",
            description="Medium test finding",
            evidence={},
            remediation="Test remediation",
            compliance=["Test"],
        ),
        Finding(
            scan_id=scan.id,
            rule_id="TEST-MEDIUM-2",
            title="Medium Test Finding 2",
            severity="medium",
            risk_score=5.0,
            risk_level="medium",
            provider="aws",
            resource_type="test_resource",
            resource_id="resource-medium-2",
            description="Medium test finding",
            evidence={},
            remediation="Test remediation",
            compliance=["Test"],
        ),
    ]

    db.add_all(findings)
    db.commit()

    scan_id = scan.id

    db.close()

    return scan_id


def test_get_scan_summary(client):
    scan_id = setup_scan_with_findings()

    response = client.get(
        f"/api/v1/scans/{scan_id}/summary"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == scan_id
    assert data["provider"] == "aws"
    assert data["status"] == "completed"

    assert data["total_findings"] == 4
    assert data["critical_count"] == 1
    assert data["high_count"] == 1
    assert data["medium_count"] == 2
    assert data["low_count"] == 0
    assert data["info_count"] == 0


def test_get_scan_summary_returns_404_for_unknown_scan(client):
    response = client.get(
        "/api/v1/scans/99999/summary"
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Scan not found"
    }

def test_get_scan_summary_returns_zero_counts_when_no_findings(client):
    db = TestingSessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="completed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        scan_id = scan.id

    finally:
        db.close()

    response = client.get(
        f"/api/v1/scans/{scan_id}/summary"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scan_id"] == scan_id
    assert data["provider"] == "aws"
    assert data["status"] == "completed"

    assert data["total_findings"] == 0
    assert data["critical_count"] == 0
    assert data["high_count"] == 0
    assert data["medium_count"] == 0
    assert data["low_count"] == 0
    assert data["info_count"] == 0
