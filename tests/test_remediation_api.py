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
from backend.app.models.finding_workflow import FindingWorkflow
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.services.auth_service import create_user_access_token
from backend.app.services.finding_lifecycle_service import build_finding_identity


@pytest.fixture
def env():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    with TestClient(app) as client:
        yield client, SessionLocal
    app.dependency_overrides.clear()
    engine.dispose()


def tenant(db, slug):
    value = Tenant(name=slug, slug=slug, status="active", created_at=datetime.now(timezone.utc))
    db.add(value); db.commit(); db.refresh(value)
    return value


def user(db, t, email):
    value = User(
        tenant_id=t.id, email=email, password_hash=hash_password("TestPassword123!"),
        full_name="Owner", role="owner", is_active=True,
        created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
    )
    db.add(value); db.commit(); db.refresh(value)
    return value


def account(db, t):
    value = CloudAccount(
        tenant_id=t.id, name="AWS Production", provider="aws",
        external_account_id="123456789012", status="connected",
        created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
    )
    db.add(value); db.commit(); db.refresh(value)
    return value


def scan(db, t, a):
    value = Scan(
        tenant_id=t.id, cloud_account_id=a.id, provider="aws", status="completed",
        started_at=datetime.now(timezone.utc) - timedelta(hours=2),
        completed_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    db.add(value); db.commit(); db.refresh(value)
    return value


def finding(db, s, rule, severity, risk, resource):
    value = Finding(
        scan_id=s.id, rule_id=rule, title=rule, severity=severity,
        risk_score=risk, risk_level=severity, provider="aws", region="us-east-1",
        resource_type="s3_bucket", resource_id=resource, description="test",
        evidence={"internet_exposed": True, "asset_criticality": 5},
        remediation="fix", compliance=[],
        created_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    db.add(value); db.commit(); db.refresh(value)
    return value


def auth(u):
    token, _ = create_user_access_token(u)
    return {"Authorization": f"Bearer {token}"}


def test_queue_returns_sla_and_workflow_context(env):
    client, SessionLocal = env
    db = SessionLocal()
    try:
        t = tenant(db, "remediation")
        u = user(db, t, "owner@remediation.example")
        a = account(db, t)
        s = scan(db, t, a)
        critical = finding(db, s, "CS-CRITICAL", "critical", 10.0, "critical-bucket")
        high = finding(db, s, "CS-HIGH", "high", 8.0, "high-bucket")
        resolved = finding(db, s, "CS-RESOLVED", "medium", 5.0, "resolved-bucket")

        db.add(FindingWorkflow(
            tenant_id=t.id, cloud_account_id=a.id,
            fingerprint=build_finding_identity(critical).fingerprint,
            status="in_progress", assignee_user_id=u.id,
            due_at=datetime.now(timezone.utc) - timedelta(hours=2),
            updated_by_user_id=u.id,
        ))
        db.add(FindingWorkflow(
            tenant_id=t.id, cloud_account_id=a.id,
            fingerprint=build_finding_identity(resolved).fingerprint,
            status="resolved", assignee_user_id=u.id,
        ))
        db.commit()

        response = client.get("/api/v1/findings/remediation/queue", headers=auth(u))
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == s.id
        assert data["total_items"] == 2
        assert data["overdue_items"] == 1
        assert data["unassigned_items"] == 1
        assert data["items"][0]["finding_id"] == critical.id
        assert data["items"][0]["sla_target_hours"] == 24
        assert data["items"][0]["sla_state"] == "overdue"
        assert data["items"][0]["workflow_status"] == "in_progress"
        assert data["items"][0]["overdue_seconds"] > 0
        assert data["items"][1]["finding_id"] == high.id
        assert data["items"][1]["sla_target_hours"] == 72
        assert data["items"][1]["sla_state"] == "unconfigured"
    finally:
        db.close()


def test_queue_is_tenant_scoped(env):
    client, SessionLocal = env
    db = SessionLocal()
    try:
        ta = tenant(db, "tenant-a")
        ua = user(db, ta, "a@example.com")
        aa = account(db, ta)
        sa = scan(db, ta, aa)
        finding(db, sa, "CS-A", "critical", 10.0, "a-bucket")

        tb = tenant(db, "tenant-b")
        ub = user(db, tb, "b@example.com")
        ab = account(db, tb)
        sb = scan(db, tb, ab)
        finding(db, sb, "CS-B", "critical", 10.0, "b-bucket")

        response = client.get("/api/v1/findings/remediation/queue", headers=auth(ua))
        assert response.status_code == 200
        assert response.json()["scan_id"] == sa.id
        assert all(x["resource_id"] != "b-bucket" for x in response.json()["items"])

        cross = client.get(
            f"/api/v1/findings/remediation/queue?cloud_account_id={ab.id}",
            headers=auth(ua),
        )
        assert cross.status_code == 404
        assert ub.id != ua.id
    finally:
        db.close()


def test_workflow_accepts_remediation_states(env):
    client, SessionLocal = env
    db = SessionLocal()
    try:
        t = tenant(db, "workflow")
        u = user(db, t, "workflow@example.com")
        a = account(db, t)
        s = scan(db, t, a)
        f = finding(db, s, "CS-WORKFLOW", "high", 8.0, "workflow-bucket")

        for state in ("acknowledged", "in_progress", "resolved", "accepted_risk"):
            response = client.post(
                f"/api/v1/findings/{f.id}/workflow",
                headers=auth(u),
                json={
                    "status": state,
                    "assignee_user_id": u.id,
                    "due_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
                },
            )
            assert response.status_code == 200
            assert response.json()["status"] == state
    finally:
        db.close()
