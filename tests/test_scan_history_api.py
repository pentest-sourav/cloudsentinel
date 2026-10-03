from datetime import datetime, timezone

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


def create_test_database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    return engine, sessionmaker(bind=engine)


def create_user(db, email, tenant_name, tenant_slug):
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
        full_name=f"{tenant_name} Owner",
        role="owner",
        is_active=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


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


def test_list_scans_returns_scan_history():
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.testing = True

    db = SessionLocal()

    try:
        user = create_user(
            db,
            "history@example.com",
            "History Tenant",
            "history-tenant",
        )

        scan_1 = Scan(
            tenant_id=user.tenant_id,
            provider="aws",
            status="completed",
        )

        scan_2 = Scan(
            tenant_id=user.tenant_id,
            provider="azure",
            status="failed",
            error_message="Azure scan failed",
        )

        db.add_all([scan_1, scan_2])
        db.commit()

        client = TestClient(app)

        token = login(client, "history@example.com")

        response = client.get(
            "/api/v1/scans",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 2
        assert data["limit"] == 50
        assert data["offset"] == 0

        assert isinstance(data["items"], list)
        assert len(data["items"]) == 2

        assert data["items"][0]["id"] == scan_2.id
        assert data["items"][1]["id"] == scan_1.id

        assert data["items"][0]["provider"] == "azure"
        assert data["items"][0]["status"] == "failed"
        assert data["items"][0]["error_message"] == "Azure scan failed"

        assert data["items"][0]["total_findings"] == 0
        assert data["items"][0]["critical_count"] == 0
        assert data["items"][0]["high_count"] == 0
        assert data["items"][0]["medium_count"] == 0
        assert data["items"][0]["low_count"] == 0
        assert data["items"][0]["info_count"] == 0

        assert data["items"][1]["provider"] == "aws"
        assert data["items"][1]["status"] == "completed"

        assert data["items"][1]["total_findings"] == 0
        assert data["items"][1]["critical_count"] == 0
        assert data["items"][1]["high_count"] == 0
        assert data["items"][1]["medium_count"] == 0
        assert data["items"][1]["low_count"] == 0
        assert data["items"][1]["info_count"] == 0

    finally:
        db.close()
        app.dependency_overrides.clear()
        app.state.testing = False
        app.state.testing = False


def test_list_scans_returns_empty_list_when_no_scans():
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.testing = True

    db = SessionLocal()

    try:
        create_user(
            db,
            "empty-history@example.com",
            "Empty History Tenant",
            "empty-history-tenant",
        )

        client = TestClient(app)

        token = login(
            client,
            "empty-history@example.com",
        )

        response = client.get(
            "/api/v1/scans",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

        data = response.json()

        assert data["items"] == []
        assert data["total"] == 0
        assert data["limit"] == 50
        assert data["offset"] == 0

    finally:
        db.close()
        app.dependency_overrides.clear()
        app.state.testing = False


def test_list_scans_supports_pagination():
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.testing = True

    db = SessionLocal()

    try:
        user = create_user(
            db,
            "pagination@example.com",
            "Pagination Tenant",
            "pagination-tenant",
        )

        scans = [
            Scan(
                tenant_id=user.tenant_id,
                provider="aws",
                status="completed",
            ),
            Scan(
                tenant_id=user.tenant_id,
                provider="azure",
                status="completed",
            ),
            Scan(
                tenant_id=user.tenant_id,
                provider="aws",
                status="failed",
            ),
            Scan(
                tenant_id=user.tenant_id,
                provider="azure",
                status="completed",
            ),
            Scan(
                tenant_id=user.tenant_id,
                provider="aws",
                status="completed",
            ),
        ]

        db.add_all(scans)
        db.commit()

        client = TestClient(app)

        token = login(
            client,
            "pagination@example.com",
        )

        response = client.get(
            "/api/v1/scans?limit=2&offset=0",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 5
        assert data["limit"] == 2
        assert data["offset"] == 0

        assert len(data["items"]) == 2

        assert data["items"][0]["id"] == scans[4].id
        assert data["items"][1]["id"] == scans[3].id

    finally:
        db.close()
        app.dependency_overrides.clear()
        app.state.testing = False


def test_list_scans_pagination_offset():
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.testing = True

    db = SessionLocal()

    try:
        user = create_user(
            db,
            "offset@example.com",
            "Offset Tenant",
            "offset-tenant",
        )

        scans = [
            Scan(
                tenant_id=user.tenant_id,
                provider="aws",
                status="completed",
            )
            for _ in range(5)
        ]

        db.add_all(scans)
        db.commit()

        client = TestClient(app)

        token = login(
            client,
            "offset@example.com",
        )

        response = client.get(
            "/api/v1/scans?limit=2&offset=2",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 5
        assert data["limit"] == 2
        assert data["offset"] == 2

        assert len(data["items"]) == 2

        assert data["items"][0]["id"] == scans[2].id
        assert data["items"][1]["id"] == scans[1].id

    finally:
        db.close()
        app.dependency_overrides.clear()
        app.state.testing = False


def test_list_scans_rejects_invalid_limit_zero():
    client = TestClient(app)

    response = client.get(
        "/api/v1/scans?limit=0",
    )

    assert response.status_code == 401


def test_list_scans_rejects_invalid_limit_above_maximum():
    client = TestClient(app)

    response = client.get(
        "/api/v1/scans?limit=101",
    )

    assert response.status_code == 401


def test_list_scans_rejects_negative_offset():
    client = TestClient(app)

    response = client.get(
        "/api/v1/scans?offset=-1",
    )

    assert response.status_code == 401


def test_list_scans_pagination_returns_only_requested_page():
    _, SessionLocal = create_test_database()

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.testing = True

    db = SessionLocal()

    try:
        user = create_user(
            db,
            "page@example.com",
            "Page Tenant",
            "page-tenant",
        )

        scans = [
            Scan(
                tenant_id=user.tenant_id,
                provider="aws",
                status="completed",
            )
            for _ in range(10)
        ]

        db.add_all(scans)
        db.commit()

        from backend.app.services.scan_service import list_scans

        result = list_scans(
            db=db,
            tenant_id=user.tenant_id,
            limit=3,
            offset=4,
        )

        assert result["total"] == 10
        assert result["limit"] == 3
        assert result["offset"] == 4

        assert len(result["items"]) == 3

        assert result["items"][0]["id"] == scans[5].id
        assert result["items"][1]["id"] == scans[4].id
        assert result["items"][2]["id"] == scans[3].id

    finally:
        db.close()
        app.dependency_overrides.clear()
        app.state.testing = False
