from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.scan import Scan


def test_list_scans_returns_scan_history():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    db = SessionLocal()

    try:
        scan_1 = Scan(
            provider="aws",
            status="completed",
        )

        scan_2 = Scan(
            provider="azure",
            status="failed",
            error_message="Azure scan failed",
        )

        db.add_all([scan_1, scan_2])
        db.commit()

        client = TestClient(app)

        response = client.get("/api/v1/scans")

        assert response.status_code == 200

        data = response.json()

        # Pagination metadata
        assert data["total"] == 2
        assert data["limit"] == 50
        assert data["offset"] == 0

        # Items
        assert isinstance(data["items"], list)
        assert len(data["items"]) == 2

        # Latest scan first
        assert data["items"][0]["id"] == scan_2.id
        assert data["items"][1]["id"] == scan_1.id

        # Scan 2
        assert data["items"][0]["provider"] == "azure"
        assert data["items"][0]["status"] == "failed"
        assert data["items"][0]["error_message"] == "Azure scan failed"

        # Finding counts for scan 2
        assert data["items"][0]["total_findings"] == 0
        assert data["items"][0]["critical_count"] == 0
        assert data["items"][0]["high_count"] == 0
        assert data["items"][0]["medium_count"] == 0
        assert data["items"][0]["low_count"] == 0
        assert data["items"][0]["info_count"] == 0

        # Scan 1
        assert data["items"][1]["provider"] == "aws"
        assert data["items"][1]["status"] == "completed"

        # Finding counts for scan 1
        assert data["items"][1]["total_findings"] == 0
        assert data["items"][1]["critical_count"] == 0
        assert data["items"][1]["high_count"] == 0
        assert data["items"][1]["medium_count"] == 0
        assert data["items"][1]["low_count"] == 0
        assert data["items"][1]["info_count"] == 0

    finally:
        db.close()
        app.dependency_overrides.clear()


def test_list_scans_returns_empty_list_when_no_scans():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    client = TestClient(app)

    try:
        response = client.get("/api/v1/scans")

        assert response.status_code == 200

        data = response.json()

        assert data["items"] == []
        assert data["total"] == 0
        assert data["limit"] == 50
        assert data["offset"] == 0

    finally:
        app.dependency_overrides.clear()


def test_list_scans_supports_pagination():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    db = SessionLocal()

    try:
        scans = [
            Scan(provider="aws", status="completed"),
            Scan(provider="azure", status="completed"),
            Scan(provider="aws", status="failed"),
            Scan(provider="azure", status="completed"),
            Scan(provider="aws", status="completed"),
        ]

        db.add_all(scans)
        db.commit()

        client = TestClient(app)

        response = client.get(
            "/api/v1/scans?limit=2&offset=0"
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 5
        assert data["limit"] == 2
        assert data["offset"] == 0

        assert len(data["items"]) == 2

        # Latest scans first
        assert data["items"][0]["id"] == scans[4].id
        assert data["items"][1]["id"] == scans[3].id

    finally:
        db.close()
        app.dependency_overrides.clear()


def test_list_scans_pagination_offset():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    db = SessionLocal()

    try:
        scans = [
            Scan(provider="aws", status="completed"),
            Scan(provider="azure", status="completed"),
            Scan(provider="aws", status="failed"),
            Scan(provider="azure", status="completed"),
            Scan(provider="aws", status="completed"),
        ]

        db.add_all(scans)
        db.commit()

        client = TestClient(app)

        response = client.get(
            "/api/v1/scans?limit=2&offset=2"
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 5
        assert data["limit"] == 2
        assert data["offset"] == 2

        assert len(data["items"]) == 2

        # Offset skips the latest 2 scans
        assert data["items"][0]["id"] == scans[2].id
        assert data["items"][1]["id"] == scans[1].id

    finally:
        db.close()
        app.dependency_overrides.clear()

def test_list_scans_rejects_invalid_limit_zero():
    client = TestClient(app)

    response = client.get(
        "/api/v1/scans?limit=0"
    )

    assert response.status_code == 422


def test_list_scans_rejects_invalid_limit_above_maximum():
    client = TestClient(app)

    response = client.get(
        "/api/v1/scans?limit=101"
    )

    assert response.status_code == 422


def test_list_scans_rejects_negative_offset():
    client = TestClient(app)

    response = client.get(
        "/api/v1/scans?offset=-1"
    )

    assert response.status_code == 422

def test_list_scans_pagination_returns_only_requested_page():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)

    db = SessionLocal()

    try:
        scans = [
            Scan(provider="aws", status="completed")
            for _ in range(10)
        ]

        db.add_all(scans)
        db.commit()

        from backend.app.services.scan_service import list_scans

        result = list_scans(
            db=db,
            limit=3,
            offset=4,
        )

        assert result["total"] == 10
        assert result["limit"] == 3
        assert result["offset"] == 4

        assert len(result["items"]) == 3

        # Scans are returned newest first.
        assert result["items"][0]["id"] == scans[5].id
        assert result["items"][1]["id"] == scans[4].id
        assert result["items"][2]["id"] == scans[3].id

    finally:
        db.close()
