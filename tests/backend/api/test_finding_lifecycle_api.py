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


@pytest.fixture()
def test_context():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client, TestSession

    app.dependency_overrides.clear()
    engine.dispose()


def create_tenant(db, slug):
    tenant = Tenant(
        name=slug.replace("-", " ").title(),
        slug=slug,
        status="active",
    )

    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    return tenant


def create_user(db, tenant, email):
    user = User(
        tenant_id=tenant.id,
        email=email,
        password_hash=hash_password(
            "StrongPassword-2026!"
        ),
        full_name="Lifecycle Test User",
        role="owner",
        is_active=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def create_scan(db, tenant, *, status="completed"):
    scan = Scan(
        tenant_id=tenant.id,
        provider="aws",
        status=status,
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


def create_finding(db, scan, rule_id="TEST-001"):
    finding = Finding(
        scan_id=scan.id,
        rule_id=rule_id,
        title=f"Test {rule_id}",
        severity="high",
        risk_score=8.0,
        risk_level="high",
        provider="aws",
        resource_type="test_resource",
        resource_id=f"resource-{rule_id}",
        description="Lifecycle API test finding",
        evidence={},
        remediation="Fix test finding",
        compliance=[],
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding


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


def test_lifecycle_requires_authentication(test_context):
    client, _ = test_context

    response = client.get(
        "/api/v1/findings/scan/1/lifecycle"
    )

    assert response.status_code == 401


def test_same_tenant_user_can_read_lifecycle(test_context):
    client, SessionLocal = test_context

    db = SessionLocal()

    try:
        tenant = create_tenant(
            db,
            "lifecycle-api-tenant",
        )

        user = create_user(
            db,
            tenant,
            "lifecycle-owner@example.com",
        )

        scan = create_scan(
            db,
            tenant,
        )

        create_finding(
            db,
            scan,
            "TEST-001",
        )

        token = login(
            client,
            user.email,
        )

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}/lifecycle",
            headers={
                "Authorization": f"Bearer {token}",
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["scan_id"] == scan.id
        assert data["previous_scan_id"] is None
        assert data["new"] == 1
        assert data["open"] == 0
        assert data["reopened"] == 0
        assert data["resolved"] == 0

        assert len(data["items"]) == 1
        assert data["items"][0]["rule_id"] == "TEST-001"
        assert data["items"][0]["status"] == "new"

    finally:
        db.close()


def test_other_tenant_cannot_read_lifecycle(test_context):
    client, SessionLocal = test_context

    db = SessionLocal()

    try:
        owner_tenant = create_tenant(
            db,
            "lifecycle-owner-tenant",
        )

        attacker_tenant = create_tenant(
            db,
            "lifecycle-other-tenant",
        )

        attacker = create_user(
            db,
            attacker_tenant,
            "attacker@example.com",
        )

        scan = create_scan(
            db,
            owner_tenant,
        )

        create_finding(
            db,
            scan,
            "TEST-001",
        )

        token = login(
            client,
            attacker.email,
        )

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}/lifecycle",
            headers={
                "Authorization": f"Bearer {token}",
            },
        )

        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"

    finally:
        db.close()


def test_non_completed_scan_returns_empty_lifecycle(test_context):
    client, SessionLocal = test_context

    db = SessionLocal()

    try:
        tenant = create_tenant(
            db,
            "lifecycle-running-tenant",
        )

        user = create_user(
            db,
            tenant,
            "running@example.com",
        )

        scan = create_scan(
            db,
            tenant,
            status="running",
        )

        token = login(
            client,
            user.email,
        )

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}/lifecycle",
            headers={
                "Authorization": f"Bearer {token}",
            },
        )

        assert response.status_code == 200

        data = response.json()

        assert data["scan_id"] == scan.id
        assert data["previous_scan_id"] is None
        assert data["items"] == []
        assert data["new"] == 0
        assert data["open"] == 0
        assert data["reopened"] == 0
        assert data["resolved"] == 0

    finally:
        db.close()


def test_missing_scan_returns_404(test_context):
    client, SessionLocal = test_context

    db = SessionLocal()

    try:
        tenant = create_tenant(
            db,
            "lifecycle-missing-tenant",
        )

        user = create_user(
            db,
            tenant,
            "missing@example.com",
        )

        token = login(
            client,
            user.email,
        )

        response = client.get(
            "/api/v1/findings/scan/999999/lifecycle",
            headers={
                "Authorization": f"Bearer {token}",
            },
        )

        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"

    finally:
        db.close()
