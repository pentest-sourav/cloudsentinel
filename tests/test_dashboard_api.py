from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.core.security import hash_password
from backend.app.main import app
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.models.user import User


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
    db = TestingSessionLocal()
    try:
        db.query(Finding).delete()
        db.query(Scan).delete()
        db.query(User).delete()
        db.query(Tenant).delete()
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
    app.state.testing = True

    yield

    app.dependency_overrides.pop(get_db, None)
    app.state.testing = False


@pytest.fixture
def client():
    return TestClient(app)


def create_user(email: str, tenant_name: str, tenant_slug: str):
    db = TestingSessionLocal()

    tenant = Tenant(
        name=tenant_name,
        slug=tenant_slug,
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    db.add(tenant)
    db.flush()

    user = User(
        tenant_id=tenant.id,
        email=email,
        password_hash=hash_password("StrongPassword-2026!"),
        full_name="Dashboard Owner",
        role="owner",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    tenant_id = tenant.id
    db.close()

    return tenant_id, user.email


def login(client, email):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": "StrongPassword-2026!",
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def add_scan_with_findings(tenant_id: int):
    db = TestingSessionLocal()

    scan = Scan(
        tenant_id=tenant_id,
        provider="aws",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.flush()

    db.add_all(
        [
            Finding(
                scan_id=scan.id,
                rule_id="TEST-PUBLIC-S3",
                title="Public storage test",
                severity="critical",
                risk_score=10.0,
                risk_level="critical",
                provider="aws",
                region="us-east-1",
                resource_type="s3_bucket",
                resource_id="bucket-prod",
                description="Test",
                evidence={
                    "internet_exposed": True,
                    "sensitive_data": True,
                    "asset_criticality": 5,
                    "exploitability": 5,
                },
                remediation="Remove public access",
                compliance=["CIS AWS Foundations"],
            ),
            Finding(
                scan_id=scan.id,
                rule_id="TEST-LOGGING",
                title="Logging test",
                severity="high",
                risk_score=7.0,
                risk_level="high",
                provider="aws",
                region="us-east-1",
                resource_type="cloudtrail",
                resource_id="trail-prod",
                description="Test",
                evidence={
                    "asset_criticality": 4,
                },
                remediation="Enable logging",
                compliance=["CIS AWS Foundations"],
            ),
        ]
    )

    db.commit()
    scan_id = scan.id
    db.close()
    return scan_id


def test_dashboard_overview_aggregates_real_security_signals(client):
    tenant_id, email = create_user(
        "dashboard-owner@example.com",
        "Dashboard Tenant",
        "dashboard-tenant",
    )
    scan_id = add_scan_with_findings(tenant_id)

    token = login(client, email)
    response = client.get(
        "/api/v1/scans/dashboard/overview",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["latest_scan_id"] == scan_id
    assert data["total_findings"] == 2
    assert data["critical_count"] == 1
    assert data["high_count"] == 1
    assert data["posture_score"] == 15.0
    assert data["posture_grade"] == "F"
    assert data["exposed_asset_count"] == 1
    assert data["sensitive_asset_count"] == 1
    assert data["attack_path_count"] == 1

    assert data["top_risks"][0]["resource_id"] == "bucket-prod"
    assert data["top_risks"][0]["internet_exposed"] is True
    assert data["top_risks"][0]["sensitive_data"] is True
    assert data["top_risks"][0]["asset_criticality"] == 5
    assert "critical risk" in data["top_risks"][0]["priority_reason"].lower()
    assert data["compliance"]["items"][0]["framework"] == "CIS AWS Foundations"
    assert len(data["risk_trend"]) == 1


def test_dashboard_overview_has_clean_empty_state(client):
    _, email = create_user(
        "empty-dashboard@example.com",
        "Empty Dashboard Tenant",
        "empty-dashboard-tenant",
    )

    token = login(client, email)
    response = client.get(
        "/api/v1/scans/dashboard/overview",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["latest_scan_id"] is None
    assert data["total_findings"] == 0
    assert data["posture_score"] == 100.0
    assert data["posture_grade"] == "A"
    assert data["attack_path_count"] == 0
    assert data["top_risks"] == []
    assert data["compliance"] is None
    assert data["data_quality_notes"]


def test_dashboard_overview_is_tenant_scoped(client):
    tenant_a, email_a = create_user(
        "dashboard-a@example.com",
        "Dashboard A",
        "dashboard-a",
    )
    scan_id = add_scan_with_findings(tenant_a)

    _, email_b = create_user(
        "dashboard-b@example.com",
        "Dashboard B",
        "dashboard-b",
    )

    token_b = login(client, email_b)
    response = client.get(
        "/api/v1/scans/dashboard/overview",
        headers={"Authorization": f"Bearer {token_b}"},
    )

    assert response.status_code == 200
    assert response.json()["latest_scan_id"] is None

    direct_scan_response = client.get(
        f"/api/v1/scans/{scan_id}/summary",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert direct_scan_response.status_code == 404
