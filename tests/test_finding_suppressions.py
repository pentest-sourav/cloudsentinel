from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.core.security import hash_password
from backend.app.main import app
from backend.app.models.cloud_account import CloudAccount
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.services.auth_service import create_user_access_token


@pytest.fixture
def test_environment():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)

    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client, SessionLocal

    app.dependency_overrides.clear()
    engine.dispose()


def create_tenant(db, name, slug):
    tenant = Tenant(
        name=name,
        slug=slug,
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def create_user(db, tenant, email, role):
    user = User(
        tenant_id=tenant.id,
        email=email,
        password_hash=hash_password("TestPassword123!"),
        full_name=role.title(),
        role=role,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def headers(user):
    token, _ = create_user_access_token(user)
    return {"Authorization": f"Bearer {token}"}


def create_finding(db, tenant_id, account_id, rule_id="CS-AWS-S3-001"):
    scan = Scan(
        tenant_id=tenant_id,
        cloud_account_id=account_id,
        provider="aws",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    finding = Finding(
        scan_id=scan.id,
        rule_id=rule_id,
        title="Public S3 bucket",
        severity="high",
        risk_score=8.0,
        risk_level="high",
        provider="aws",
        region="us-east-1",
        resource_type="s3_bucket",
        resource_id=f"bucket-{rule_id}",
        description="Test finding",
        evidence={"public": True},
        remediation="Fix it.",
        compliance=["CIS"],
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def create_account(db, tenant):
    account = CloudAccount(
        tenant_id=tenant.id,
        name="Production AWS",
        provider="aws",
        external_account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/CloudSentinel",
        external_id="test-external-id",
        region="us-east-1",
        status="connected",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


def test_suppression_lifecycle_is_persistent_and_audited(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()
    try:
        tenant = create_tenant(db, "Suppression Tenant", "suppression-tenant")
        user = create_user(db, tenant, "operator@example.com", "operator")
        account = create_account(db, tenant)
        finding = create_finding(db, tenant.id, account.id)

        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        response = client.post(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user),
            json={
                "reason": "Approved exception while legacy workload is migrated.",
                "expires_at": expires_at.isoformat(),
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == finding.id
        assert data["suppressed"] is True
        assert data["reason"].startswith("Approved exception")
        assert data["expires_at"] is not None

        response = client.get(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user),
        )
        assert response.status_code == 200
        assert response.json()["suppressed"] is True

        response = client.delete(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user),
        )
        assert response.status_code == 204

        response = client.get(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user),
        )
        assert response.status_code == 200
        assert response.json()["suppressed"] is False

        from backend.app.models.audit_event import AuditEvent

        events = db.query(AuditEvent).filter(
            AuditEvent.tenant_id == tenant.id,
            AuditEvent.resource_id == str(finding.id),
        ).all()
        assert {event.action for event in events} == {
            "finding.suppression.create",
            "finding.suppression.delete",
        }
    finally:
        db.close()


def test_expired_suppression_is_not_active(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()
    try:
        tenant = create_tenant(db, "Expiry Tenant", "expiry-tenant")
        user = create_user(db, tenant, "operator@example.com", "operator")
        account = create_account(db, tenant)
        finding = create_finding(db, tenant.id, account.id)

        suppression = {
            "reason": "Temporary exception",
            "expires_at": (
                datetime.now(timezone.utc) + timedelta(seconds=1)
            ).isoformat(),
        }
        response = client.post(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user),
            json=suppression,
        )
        assert response.status_code == 200

        stored = response.json()
        assert stored["suppressed"] is True

        from backend.app.models.finding_suppression import FindingSuppression

        row = db.query(FindingSuppression).filter(
            FindingSuppression.id == stored["id"],
        ).one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()

        response = client.get(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user),
        )
        assert response.status_code == 200
        assert response.json()["suppressed"] is False
    finally:
        db.close()


def test_viewer_cannot_change_suppression(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()
    try:
        tenant = create_tenant(db, "Viewer Tenant", "viewer-tenant")
        user = create_user(db, tenant, "viewer@example.com", "viewer")
        account = create_account(db, tenant)
        finding = create_finding(db, tenant.id, account.id)

        response = client.post(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user),
            json={"reason": "Should be rejected"},
        )
        assert response.status_code == 403
    finally:
        db.close()


def test_suppression_is_tenant_scoped(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()
    try:
        tenant_a = create_tenant(db, "Tenant A", "tenant-a")
        tenant_b = create_tenant(db, "Tenant B", "tenant-b")
        user_a = create_user(db, tenant_a, "a@example.com", "operator")
        user_b = create_user(db, tenant_b, "b@example.com", "operator")
        account = create_account(db, tenant_a)
        finding = create_finding(db, tenant_a.id, account.id)

        response = client.post(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user_b),
            json={"reason": "Cross-tenant attempt"},
        )
        assert response.status_code == 404

        response = client.post(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user_a),
            json={"reason": "Tenant-local exception"},
        )
        assert response.status_code == 200
    finally:
        db.close()


def test_suppression_rejects_non_future_expiry(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()
    try:
        tenant = create_tenant(db, "Validation Tenant", "validation-tenant")
        user = create_user(db, tenant, "operator@example.com", "operator")
        account = create_account(db, tenant)
        finding = create_finding(db, tenant.id, account.id)

        response = client.post(
            f"/api/v1/findings/{finding.id}/suppression",
            headers=headers(user),
            json={
                "reason": "Invalid expiry",
                "expires_at": (
                    datetime.now(timezone.utc) - timedelta(days=1)
                ).isoformat(),
            },
        )
        assert response.status_code == 400
    finally:
        db.close()
