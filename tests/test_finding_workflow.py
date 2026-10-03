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
    tenant = Tenant(name=name, slug=slug, status="active")
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def create_user(db, tenant, email, role):
    now = datetime.now(timezone.utc)
    user = User(
        tenant_id=tenant.id,
        email=email,
        password_hash=hash_password("TestPassword123!"),
        full_name=role.title(),
        role=role,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def headers(user):
    token, _ = create_user_access_token(user)
    return {"Authorization": f"Bearer {token}"}


def create_account(db, tenant, suffix="1"):
    account = CloudAccount(
        tenant_id=tenant.id,
        name=f"Production AWS {suffix}",
        provider="aws",
        external_account_id=f"12345678901{suffix}",
        role_arn=f"arn:aws:iam::12345678901{suffix}:role/CloudSentinel",
        external_id=f"test-external-id-{suffix}",
        region="us-east-1",
        status="connected",
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


def create_finding(db, tenant_id, account_id, completed_at, rule_id="CS-AWS-S3-001"):
    scan = Scan(
        tenant_id=tenant_id,
        cloud_account_id=account_id,
        provider="aws",
        status="completed",
        started_at=completed_at - timedelta(minutes=1),
        completed_at=completed_at,
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


def test_workflow_persists_by_fingerprint_across_scans(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()
    try:
        tenant = create_tenant(db, "Workflow Tenant", "workflow-tenant")
        operator = create_user(db, tenant, "operator@example.com", "operator")
        assignee = create_user(db, tenant, "assignee@example.com", "operator")
        account = create_account(db, tenant)
        now = datetime.now(timezone.utc)
        first = create_finding(db, tenant.id, account.id, now)
        second = create_finding(
            db,
            tenant.id,
            account.id,
            now + timedelta(minutes=10),
        )

        due_at = now + timedelta(days=2)
        response = client.post(
            f"/api/v1/findings/{first.id}/workflow",
            headers=headers(operator),
            json={
                "status": "acknowledged",
                "assignee_user_id": assignee.id,
                "due_at": due_at.isoformat(),
                "note": "Security team is actively remediating this.",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "acknowledged"
        assert data["assignee_user_id"] == assignee.id
        assert data["note"].startswith("Security team")

        response = client.get(
            f"/api/v1/findings/{second.id}/workflow",
            headers=headers(operator),
        )
        assert response.status_code == 200
        persisted = response.json()
        assert persisted["status"] == "acknowledged"
        assert persisted["assignee_user_id"] == assignee.id
        assert persisted["fingerprint"] == data["fingerprint"]
    finally:
        db.close()


def test_workflow_is_tenant_scoped_and_assignee_must_be_local(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()
    try:
        tenant_a = create_tenant(db, "Tenant A", "workflow-a")
        tenant_b = create_tenant(db, "Tenant B", "workflow-b")
        user_a = create_user(db, tenant_a, "a@example.com", "operator")
        user_b = create_user(db, tenant_b, "b@example.com", "operator")
        account = create_account(db, tenant_a)
        finding = create_finding(
            db,
            tenant_a.id,
            account.id,
            datetime.now(timezone.utc),
        )

        response = client.post(
            f"/api/v1/findings/{finding.id}/workflow",
            headers=headers(user_b),
            json={"status": "acknowledged"},
        )
        assert response.status_code == 404

        response = client.post(
            f"/api/v1/findings/{finding.id}/workflow",
            headers=headers(user_a),
            json={"status": "acknowledged", "assignee_user_id": user_b.id},
        )
        assert response.status_code == 400
        assert "Assignee user not found" in response.json()["detail"]
    finally:
        db.close()


def test_viewer_cannot_change_workflow_but_can_read(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()
    try:
        tenant = create_tenant(db, "Viewer Tenant", "workflow-viewer")
        viewer = create_user(db, tenant, "viewer@example.com", "viewer")
        account = create_account(db, tenant)
        finding = create_finding(
            db,
            tenant.id,
            account.id,
            datetime.now(timezone.utc),
        )

        response = client.post(
            f"/api/v1/findings/{finding.id}/workflow",
            headers=headers(viewer),
            json={"status": "acknowledged"},
        )
        assert response.status_code == 403

        response = client.get(
            f"/api/v1/findings/{finding.id}/workflow",
            headers=headers(viewer),
        )
        assert response.status_code == 200
        assert response.json()["status"] == "open"
    finally:
        db.close()


def test_workflow_validates_due_date_and_clear_is_audited(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()
    try:
        tenant = create_tenant(db, "Validation Tenant", "workflow-validation")
        operator = create_user(db, tenant, "operator@example.com", "operator")
        account = create_account(db, tenant)
        finding = create_finding(
            db,
            tenant.id,
            account.id,
            datetime.now(timezone.utc),
        )

        response = client.post(
            f"/api/v1/findings/{finding.id}/workflow",
            headers=headers(operator),
            json={
                "status": "acknowledged",
                "due_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            },
        )
        assert response.status_code == 400

        response = client.post(
            f"/api/v1/findings/{finding.id}/workflow",
            headers=headers(operator),
            json={"status": "acknowledged", "note": "Track remediation"},
        )
        assert response.status_code == 200

        response = client.delete(
            f"/api/v1/findings/{finding.id}/workflow",
            headers=headers(operator),
        )
        assert response.status_code == 204

        response = client.get(
            f"/api/v1/findings/{finding.id}/workflow",
            headers=headers(operator),
        )
        assert response.status_code == 200
        assert response.json()["status"] == "open"

        from backend.app.models.audit_event import AuditEvent

        actions = {
            event.action
            for event in db.query(AuditEvent).filter(
                AuditEvent.tenant_id == tenant.id,
                AuditEvent.resource_id == str(finding.id),
            ).all()
        }
        assert actions == {"finding.workflow.update", "finding.workflow.delete"}
    finally:
        db.close()
