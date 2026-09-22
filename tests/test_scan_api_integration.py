from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.core.security import hash_password
from backend.app.main import app
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.services.scan_queue import ScanJob


PASSWORD = "StrongPassword-2026!"


class FakeScanQueue:
    def __init__(self, *args, **kwargs):
        self.jobs: list[ScanJob] = []

    def enqueue(self, job: ScanJob) -> str:
        self.jobs.append(job)
        return "1-0"

    def close(self) -> None:
        pass


def create_test_database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    return engine, sessionmaker(bind=engine)


def create_test_user(db, email="scan-owner@example.com"):
    tenant = Tenant(
        name="Scan API Tenant",
        slug="scan-api-tenant",
        status="active",
    )

    db.add(tenant)
    db.flush()

    user = User(
        tenant_id=tenant.id,
        email=email,
        password_hash=hash_password(PASSWORD),
        full_name="Scan API Owner",
        role="owner",
        is_active=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def get_token(client, email="scan-owner@example.com"):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 200

    return response.json()["access_token"]


def auth_headers(token):
    return {
        "Authorization": f"Bearer {token}",
    }


def test_aws_scan_api_enqueues_scan(monkeypatch):
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    queue = FakeScanQueue()

    monkeypatch.setattr(
        "backend.app.api.routes.scans.ScanQueue",
        lambda: queue,
    )

    client = TestClient(app)

    try:
        db = SessionLocal()
        create_test_user(db)
        db.close()

        token = get_token(client)

        response = client.post(
            "/api/v1/scans",
            headers=auth_headers(token),
            json={"provider": "aws"},
        )

        assert response.status_code == 201

        data = response.json()

        assert data["provider"] == "aws"
        assert data["status"] == "pending"
        assert data["started_at"] is None
        assert data["completed_at"] is None
        assert data["error_message"] is None

        assert len(queue.jobs) == 1

        job = queue.jobs[0]

        assert job.scan_id == data["id"]
        assert job.provider == "aws"

        db = SessionLocal()

        try:
            scan = (
                db.query(Scan)
                .filter(Scan.id == data["id"])
                .first()
            )

            assert scan is not None
            assert scan.status == "pending"
        finally:
            db.close()

    finally:
        app.dependency_overrides.clear()


def test_scan_api_returns_scan_status(monkeypatch):
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    queue = FakeScanQueue()

    monkeypatch.setattr(
        "backend.app.api.routes.scans.ScanQueue",
        lambda: queue,
    )

    client = TestClient(app)

    try:
        db = SessionLocal()
        create_test_user(db)
        db.close()

        token = get_token(client)

        create_response = client.post(
            "/api/v1/scans",
            headers=auth_headers(token),
            json={"provider": "aws"},
        )

        assert create_response.status_code == 201

        scan_id = create_response.json()["id"]

        status_response = client.get(
            f"/api/v1/scans/{scan_id}",
            headers=auth_headers(token),
        )

        assert status_response.status_code == 200

        data = status_response.json()

        assert data["id"] == scan_id
        assert data["provider"] == "aws"
        assert data["status"] == "pending"
        assert data["started_at"] is None
        assert data["completed_at"] is None
        assert data["error_message"] is None

    finally:
        app.dependency_overrides.clear()


def test_scan_api_isolates_scans_between_tenants(monkeypatch):
    from backend.app.core.database import SessionLocal
    from backend.app.models.tenant import Tenant
    from backend.app.models.user import User

    from uuid import uuid4

    db = SessionLocal()

    suffix = uuid4().hex[:12]

    tenant_a = Tenant(
        name="Tenant A",
        slug=f"tenant-a-scan-isolation-{suffix}",
        status="active",
    )
    tenant_b = Tenant(
        name="Tenant B",
        slug=f"tenant-b-scan-isolation-{suffix}",
        status="active",
    )
    db.add_all([tenant_a, tenant_b])
    db.commit()
    db.refresh(tenant_a)
    db.refresh(tenant_b)

    user_a = User(
        tenant_id=tenant_a.id,
        email="tenant-a-scan@example.com",
        password_hash=hash_password(PASSWORD),
        full_name="Tenant A Owner",
        role="owner",
        is_active=True,
    )

    user_b = User(
        tenant_id=tenant_b.id,
        email="tenant-b-scan@example.com",
        password_hash=hash_password(PASSWORD),
        full_name="Tenant B Owner",
        role="owner",
        is_active=True,
    )

    db.add_all([user_a, user_b])
    db.commit()

    db.close()

    client = TestClient(app)

    token_a = get_token(
        client,
        email="tenant-a-scan@example.com",
    )
    token_b = get_token(
        client,
        email="tenant-b-scan@example.com",
    )

    monkeypatch.setattr(
        "backend.app.api.routes.scans.ScanQueue",
        FakeScanQueue,
    )

    response = client.post(
        "/api/v1/scans",
        json={"provider": "aws"},
        headers={"Authorization": f"Bearer {token_a}"},
    )

    assert response.status_code == 201

    scan_id = response.json()["id"]

    owner_response = client.get(
        f"/api/v1/scans/{scan_id}",
        headers={"Authorization": f"Bearer {token_a}"},
    )

    assert owner_response.status_code == 200
    assert owner_response.json()["id"] == scan_id

    other_tenant_response = client.get(
        f"/api/v1/scans/{scan_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )

    assert other_tenant_response.status_code == 404

    other_tenant_summary = client.get(
        f"/api/v1/scans/{scan_id}/summary",
        headers={"Authorization": f"Bearer {token_b}"},
    )

    assert other_tenant_summary.status_code == 404



def test_scan_api_returns_404_for_unknown_scan():
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    try:
        db = SessionLocal()
        create_test_user(db)
        db.close()

        token = get_token(client)

        response = client.get(
            "/api/v1/scans/999999",
            headers=auth_headers(token),
        )

        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"

    finally:
        app.dependency_overrides.clear()


def test_scan_api_rejects_unsupported_provider():
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    try:
        db = SessionLocal()
        create_test_user(db)
        db.close()

        token = get_token(client)

        response = client.post(
            "/api/v1/scans",
            headers=auth_headers(token),
            json={"provider": "azure"},
        )

        assert response.status_code == 501
        assert response.json()["detail"] == (
            "Provider 'azure' is not yet supported for scanning."
        )

    finally:
        app.dependency_overrides.clear()


def test_scan_api_rejects_invalid_provider():
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    try:
        db = SessionLocal()
        create_test_user(db)
        db.close()

        token = get_token(client)

        response = client.post(
            "/api/v1/scans",
            headers=auth_headers(token),
            json={"provider": "gcp"},
        )

        assert response.status_code == 422

    finally:
        app.dependency_overrides.clear()
