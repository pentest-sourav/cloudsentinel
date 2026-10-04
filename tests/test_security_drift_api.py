from datetime import datetime, timedelta, timezone

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
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(bind=engine)


@pytest.fixture(autouse=True)
def setup():
    db = SessionLocal()
    try:
        db.query(Finding).delete()
        db.query(Scan).delete()
        db.query(User).delete()
        db.query(Tenant).delete()
        db.commit()
    finally:
        db.close()

    def override():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    app.state.testing = True
    yield
    app.dependency_overrides.pop(get_db, None)
    app.state.testing = False


@pytest.fixture
def client():
    return TestClient(app)


def user_and_token(client):
    db = SessionLocal()
    tenant = Tenant(
        name="Drift Tenant",
        slug="drift-tenant",
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    db.add(tenant)
    db.flush()
    user = User(
        tenant_id=tenant.id,
        email="drift@example.com",
        password_hash=hash_password("StrongPassword-2026!"),
        full_name="Drift Owner",
        role="owner",
        is_active=True,
    )
    db.add(user)
    db.commit()
    email = user.email
    db.close()

    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "StrongPassword-2026!"},
    )
    assert response.status_code == 200
    return response.json()["access_token"], tenant.id


def add_scan(db, tenant_id, completed_at):
    scan = Scan(
        tenant_id=tenant_id,
        provider="aws",
        status="completed",
        started_at=completed_at - timedelta(minutes=5),
        completed_at=completed_at,
    )
    db.add(scan)
    db.flush()
    return scan


def add_finding(
    db,
    scan_id,
    rule_id,
    resource_id,
    risk,
    *,
    exposed=False,
    sensitive=False,
):
    db.add(
        Finding(
            scan_id=scan_id,
            rule_id=rule_id,
            title=rule_id,
            severity="critical" if risk >= 9 else "high",
            risk_score=risk,
            risk_level="critical" if risk >= 9 else "high",
            provider="aws",
            region="us-east-1",
            resource_type="s3_bucket",
            resource_id=resource_id,
            description="drift test",
            evidence={
                "internet_exposed": exposed,
                "sensitive_data": sensitive,
            },
            remediation="test remediation",
            compliance=["CIS AWS Foundations"],
        )
    )


def seed_three_scans(tenant_id):
    db = SessionLocal()
    base = datetime(2026, 10, 1, tzinfo=timezone.utc)

    first = add_scan(db, tenant_id, base)
    add_finding(db, first.id, "RULE-REOPEN", "bucket-a", 8.0)
    add_finding(db, first.id, "RULE-PERSIST", "bucket-b", 7.0)

    second = add_scan(db, tenant_id, base + timedelta(hours=1))
    add_finding(db, second.id, "RULE-PERSIST", "bucket-b", 7.0)

    third = add_scan(db, tenant_id, base + timedelta(hours=2))
    add_finding(
        db,
        third.id,
        "RULE-REOPEN",
        "bucket-a",
        9.0,
        exposed=True,
    )
    add_finding(
        db,
        third.id,
        "RULE-PERSIST",
        "bucket-b",
        9.0,
        sensitive=True,
    )
    add_finding(db, third.id, "RULE-NEW", "bucket-c", 8.0)

    db.commit()
    ids = (first.id, second.id, third.id)
    db.close()
    return ids


def test_drift_detects_new_resolved_reopened_and_risk_movement(client):
    token, tenant_id = user_and_token(client)
    first, second, third = seed_three_scans(tenant_id)

    response = client.get(
        "/api/v1/scans/drift",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["current_scan_id"] == third
    assert data["previous_scan_id"] == second
    assert data["baseline_available"] is True
    assert data["reopened_count"] == 1
    assert data["new_count"] == 1
    assert data["resolved_count"] == 0
    assert data["persistent_count"] == 1
    assert data["risk_increase_count"] == 1
    assert data["newly_exposed_count"] == 1
    assert data["newly_sensitive_count"] == 1
    assert data["drift_state"] == "worsened"
    assert data["top_regressions"]


def test_drift_has_baseline_state_for_first_scan(client):
    token, tenant_id = user_and_token(client)
    db = SessionLocal()
    scan = add_scan(
        db,
        tenant_id,
        datetime(2026, 10, 2, tzinfo=timezone.utc),
    )
    add_finding(db, scan.id, "RULE-FIRST", "bucket-first", 5.0)
    db.commit()
    db.close()

    response = client.get(
        "/api/v1/scans/drift",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["previous_scan_id"] is None
    assert data["drift_state"] == "baseline"
    assert data["posture_delta"] is None
    assert data["new_count"] == 1


def test_drift_is_tenant_scoped(client):
    token_a, tenant_a = user_and_token(client)
    seed_three_scans(tenant_a)

    token_b, _ = user_and_token(client)
    response = client.get(
        "/api/v1/scans/drift",
        headers={"Authorization": f"Bearer {token_b}"},
    )

    assert response.status_code == 200
    assert response.json()["current_scan_id"] is None
    assert response.json()["drift_state"] == "no_data"
