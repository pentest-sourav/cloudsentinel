from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.scan import Scan
from backend.app.services.scan_queue import ScanJob


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
        response = client.post(
            "/api/v1/scans",
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
        create_response = client.post(
            "/api/v1/scans",
            json={"provider": "aws"},
        )

        assert create_response.status_code == 201

        scan_id = create_response.json()["id"]

        status_response = client.get(
            f"/api/v1/scans/{scan_id}",
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
        response = client.get(
            "/api/v1/scans/999999",
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
        response = client.post(
            "/api/v1/scans",
            json={"provider": "azure"},
        )

        assert response.status_code == 501
        assert response.json()["detail"] == (
            "Provider 'azure' is not yet supported for scanning."
        )

    finally:
        app.dependency_overrides.clear()


def test_scan_api_rejects_invalid_provider():
    client = TestClient(app)

    response = client.post(
        "/api/v1/scans",
        json={"provider": "gcp"},
    )

    assert response.status_code == 422
