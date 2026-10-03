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
from backend.app.services.auth_service import create_user_access_token


engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(bind=engine)


@pytest.fixture
def environment():
    db = SessionLocal()
    try:
        db.query(Finding).delete()
        db.query(Scan).delete()
        db.query(User).delete()
        db.query(Tenant).delete()
        db.commit()
    finally:
        db.close()

    def override_get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client, SessionLocal

    app.dependency_overrides.clear()


def create_tenant_user(db, slug: str):
    tenant = Tenant(
        name=f"Tenant {slug}",
        slug=slug,
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    db.add(tenant)
    db.flush()

    user = User(
        tenant_id=tenant.id,
        email=f"{slug}@example.com",
        password_hash=hash_password("StrongPassword-2026!"),
        full_name="Risk Graph User",
        role="owner",
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token, _expires_in = create_user_access_token(user)
    return tenant, token


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_risk_graph_builds_asset_inventory_and_attack_path(environment):
    client, session_factory = environment
    db = session_factory()

    tenant, user_token = create_tenant_user(db, "risk-graph")
    scan = Scan(
        tenant_id=tenant.id,
        provider="aws",
        status="completed",
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.flush()

    db.add_all(
        [
            Finding(
                scan_id=scan.id,
                rule_id="CS-AWS-S3-001",
                title="Public S3",
                severity="high",
                risk_score=8.5,
                risk_level="high",
                provider="aws",
                region="ap-south-1",
                resource_type="s3_bucket",
                resource_id="customer-data",
                description="Public access signal",
                evidence={
                    "public_access_signal": True,
                    "sensitive_data": True,
                    "asset_criticality": 5,
                    "exploitability": 4,
                },
                remediation="Block public access.",
                compliance=["CIS AWS Foundations"],
            ),
            Finding(
                scan_id=scan.id,
                rule_id="CS-AWS-S3-002",
                title="Encryption",
                severity="medium",
                risk_score=5.0,
                risk_level="medium",
                provider="aws",
                region="ap-south-1",
                resource_type="s3_bucket",
                resource_id="customer-data",
                description="Encryption signal",
                evidence={},
                remediation="Enable encryption.",
                compliance=["CIS AWS Foundations"],
            ),
        ]
    )
    db.commit()
    scan_id = scan.id
    db.close()

    response = client.get(
        f"/api/v1/scans/{scan_id}/risk-graph",
        headers=auth_headers(user_token),
    )

    assert response.status_code == 200
    data = response.json()

    assert data["graph_type"] == "evidence-derived-risk-graph"
    assert data["evidence_derived"] is True
    assert data["asset_count"] == 1
    assert data["finding_count"] == 2
    assert data["exposed_asset_count"] == 1
    assert data["sensitive_asset_count"] == 1

    asset = data["assets"][0]
    assert asset["resource_id"] == "customer-data"
    assert asset["finding_count"] == 2
    assert asset["max_risk_score"] == 8.5
    assert asset["internet_exposed"] is True
    assert asset["sensitive_data"] is True
    assert asset["asset_criticality"] == 5
    assert asset["exploitability"] == 4

    assert len(data["attack_paths"]) == 1
    path = data["attack_paths"][0]
    assert path["confidence"] == "high"
    assert path["risk_level"] == "critical"
    assert "Sensitive-data signal" in path["steps"]


def test_risk_graph_is_tenant_scoped(environment):
    client, session_factory = environment
    db = session_factory()

    tenant_a, _token_a = create_tenant_user(db, "risk-graph-a")
    tenant_b, token_b = create_tenant_user(db, "risk-graph-b")

    scan = Scan(
        tenant_id=tenant_a.id,
        provider="aws",
        status="completed",
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    scan_id = scan.id
    db.close()

    response = client.get(
        f"/api/v1/scans/{scan_id}/risk-graph",
        headers=auth_headers(user_b),
    )

    assert response.status_code == 404
