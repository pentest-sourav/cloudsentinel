import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.core.security import hash_password
from backend.app.main import app
from backend.app.models.audit_event import AuditEvent
from backend.app.models.tenant import Tenant
from backend.app.models.user import User


PASSWORD = "StrongPassword-2026!"


@pytest.fixture()
def test_context():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.testing = True

    with TestClient(app) as client:
        yield client, TestSession

    app.dependency_overrides.clear()
    app.state.testing = False
    engine.dispose()


def _seed(SessionLocal):
    db = SessionLocal()
    tenant_one = Tenant(
        name="Audit Tenant One",
        slug="audit-tenant-one",
        status="active",
    )
    tenant_two = Tenant(
        name="Audit Tenant Two",
        slug="audit-tenant-two",
        status="active",
    )
    db.add_all([tenant_one, tenant_two])
    db.flush()

    owner = User(
        tenant_id=tenant_one.id,
        email="audit-owner@example.com",
        password_hash=hash_password(PASSWORD),
        full_name="Audit Owner",
        role="owner",
        is_active=True,
    )
    viewer = User(
        tenant_id=tenant_one.id,
        email="audit-viewer@example.com",
        password_hash=hash_password(PASSWORD),
        full_name="Audit Viewer",
        role="viewer",
        is_active=True,
    )
    other_owner = User(
        tenant_id=tenant_two.id,
        email="other-owner@example.com",
        password_hash=hash_password(PASSWORD),
        full_name="Other Owner",
        role="owner",
        is_active=True,
    )
    db.add_all([owner, viewer, other_owner])
    db.flush()

    db.add_all(
        [
            AuditEvent(
                tenant_id=tenant_one.id,
                user_id=owner.id,
                action="scan.create",
                status="success",
                resource_type="scan",
                resource_id="101",
                request_id="req-101",
                ip_address="127.0.0.1",
                metadata={"provider": "aws"},
            ),
            AuditEvent(
                tenant_id=tenant_one.id,
                user_id=owner.id,
                action="auth.login",
                status="failure",
                metadata={"reason": "invalid credentials"},
            ),
            AuditEvent(
                tenant_id=tenant_two.id,
                user_id=other_owner.id,
                action="scan.create",
                status="success",
                resource_type="scan",
                resource_id="202",
                metadata={"provider": "aws"},
            ),
        ]
    )
    db.commit()
    db.refresh(owner)
    db.refresh(viewer)
    db.refresh(other_owner)
    db.close()
    return owner.id, viewer.id, other_owner.id


def _login(client, email, tenant):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": PASSWORD,
            "tenant_name": tenant,
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_audit_events_are_tenant_scoped_and_filterable(test_context):
    client, SessionLocal = test_context
    _seed(SessionLocal)

    token = _login(
        client,
        "audit-owner@example.com",
        "Audit Tenant One",
    )

    response = client.get(
        "/api/v1/audit-events",
        headers={"Authorization": f"Bearer {token}"},
        params={"action": "scan.create"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["resource_id"] == "101"

    response = client.get(
        "/api/v1/audit-events",
        headers={"Authorization": f"Bearer {token}"},
        params={"status": "failure"},
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_audit_events_never_cross_tenant_boundary(test_context):
    client, SessionLocal = test_context
    _seed(SessionLocal)

    token = _login(
        client,
        "audit-owner@example.com",
        "Audit Tenant One",
    )

    response = client.get(
        "/api/v1/audit-events",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert all(
        item["resource_id"] != "202"
        for item in body["items"]
    )


def test_audit_events_are_restricted_to_owner_and_admin(test_context):
    client, SessionLocal = test_context
    _seed(SessionLocal)

    token = _login(
        client,
        "audit-viewer@example.com",
        "Audit Tenant One",
    )

    response = client.get(
        "/api/v1/audit-events",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions."


def test_audit_events_support_pagination(test_context):
    client, SessionLocal = test_context
    _seed(SessionLocal)

    token = _login(
        client,
        "audit-owner@example.com",
        "Audit Tenant One",
    )

    response = client.get(
        "/api/v1/audit-events",
        headers={"Authorization": f"Bearer {token}"},
        params={"limit": 1, "offset": 1},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert len(body["items"]) == 1
    assert body["limit"] == 1
    assert body["offset"] == 1
