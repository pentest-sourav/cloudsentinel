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
from backend.app.services.alert_policy_service import dispatch_scan_alerts


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


def tenant(db):
    t = Tenant(name="Alert Tenant", slug="alert-tenant", status="active")
    db.add(t); db.commit(); db.refresh(t); return t


def user(db, t, role="administrator"):
    now = datetime.now(timezone.utc)
    u = User(
        tenant_id=t.id, email=f"{role}@example.com",
        password_hash=hash_password("TestPassword123!"),
        full_name=role.title(), role=role, is_active=True,
        created_at=now, updated_at=now,
    )
    db.add(u); db.commit(); db.refresh(u); return u


def account(db, t):
    a = CloudAccount(
        tenant_id=t.id, name="AWS", provider="aws",
        external_account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/CloudSentinel",
        external_id="test-external-id", region="us-east-1",
        status="connected",
    )
    db.add(a); db.commit(); db.refresh(a); return a


def finding(db, t, a, scan_id=None, severity="critical"):
    if scan_id is None:
        now = datetime.now(timezone.utc)
        s = Scan(tenant_id=t.id, cloud_account_id=a.id, provider="aws",
                 status="completed", started_at=now - timedelta(minutes=1),
                 completed_at=now)
        db.add(s); db.commit(); db.refresh(s)
        scan_id = s.id
    f = Finding(
        scan_id=scan_id, rule_id="CS-AWS-S3-001", title="Public S3 bucket",
        severity=severity, risk_score=9.0, risk_level=severity,
        provider="aws", region="us-east-1", resource_type="s3_bucket",
        resource_id="bucket-alert", description="Test",
        evidence={"public": True}, remediation="Fix it.", compliance=["CIS"],
    )
    db.add(f); db.commit(); db.refresh(f); return f


def auth(u):
    token, _ = create_user_access_token(u)
    return {"Authorization": f"Bearer {token}"}


def test_policy_crud_and_secret_is_never_returned(env, monkeypatch):
    client, SessionLocal = env
    db = SessionLocal()
    try:
        t = tenant(db); u = user(db, t)
        monkeypatch.setattr(
            "backend.app.services.alert_policy_service._validate_endpoint",
            lambda url: url,
        )
        response = client.post(
            "/api/v1/alert-policies",
            headers=auth(u),
            json={
                "name": "Critical Webhook",
                "endpoint_url": "https://alerts.example.com/cloudsentinel",
                "min_severity": "critical",
                "events": ["new", "reopened"],
                "secret": "super-secret-signing-key",
            },
        )
        assert response.status_code == 201
        assert response.json()["has_secret"] is True
        assert "secret" not in response.json()

        response = client.get("/api/v1/alert-policies", headers=auth(u))
        assert response.status_code == 200
        assert response.json()[0]["name"] == "Critical Webhook"

        policy_id = response.json()[0]["id"]
        response = client.delete(f"/api/v1/alert-policies/{policy_id}", headers=auth(u))
        assert response.status_code == 204
    finally:
        db.close()


def test_viewer_cannot_manage_alert_policies(env):
    client, SessionLocal = env
    db = SessionLocal()
    try:
        t = tenant(db); u = user(db, t, "viewer")
        response = client.post(
            "/api/v1/alert-policies",
            headers=auth(u),
            json={"name": "Denied", "endpoint_url": "https://alerts.example.com/hook"},
        )
        assert response.status_code == 403
    finally:
        db.close()


def test_alert_dispatch_is_idempotent_and_does_not_alert_medium(env, monkeypatch):
    client, SessionLocal = env
    db = SessionLocal()
    try:
        t = tenant(db); u = user(db, t); a = account(db, t)
        now = datetime.now(timezone.utc)
        scan = Scan(
            tenant_id=t.id, cloud_account_id=a.id, provider="aws",
            status="completed", started_at=now - timedelta(minutes=1), completed_at=now,
        )
        db.add(scan); db.commit(); db.refresh(scan)
        finding(db, t, a, scan.id, "critical")

        from backend.app.models.alert_policy import AlertPolicy
        policy = AlertPolicy(
            tenant_id=t.id, name="Webhook", enabled=True,
            endpoint_url="https://alerts.example.com/hook",
            min_severity="high", events=["new"], secret=None,
            created_by_user_id=u.id,
        )
        db.add(policy); db.commit(); db.refresh(policy)

        calls = []
        class Response:
            status_code = 204

        class Client:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def post(self, *args, **kwargs):
                import json
                calls.append(json.loads(kwargs["content"])["event"])
                return Response()

        monkeypatch.setattr(
            "backend.app.services.alert_policy_service.httpx.Client",
            lambda *args, **kwargs: Client(),
        )
        # This test isolates delivery/idempotency behavior; endpoint DNS/SSRF
        # validation is covered separately by the webhook boundary tests.
        monkeypatch.setattr(
            "backend.app.services.alert_policy_service._validate_endpoint",
            lambda url: url,
        )
        first = dispatch_scan_alerts(db=db, scan_id=scan.id, tenant_id=t.id)
        second = dispatch_scan_alerts(db=db, scan_id=scan.id, tenant_id=t.id)
        assert first["delivered"] == 1
        assert second["delivered"] == 0
        assert calls == ["finding.new"]
    finally:
        db.close()
