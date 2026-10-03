from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from backend.app.main import app


def test_readiness_reports_database_and_redis_ready():
    fake_db = Mock()

    class FakeQueue:
        def ping(self):
            return True

        def close(self):
            pass

    with patch(
        "backend.app.main.SessionLocal",
        return_value=fake_db,
    ), patch(
        "backend.app.main.ScanQueue",
        return_value=FakeQueue(),
    ):
        response = TestClient(app).get("/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "checks": {
            "database": "ok",
            "redis": "ok",
        },
    }

    fake_db.execute.assert_called_once()


def test_readiness_returns_503_when_dependency_is_unavailable():
    fake_db = Mock()
    fake_db.execute.side_effect = RuntimeError("database down")

    class FakeQueue:
        def ping(self):
            raise RuntimeError("redis down")

        def close(self):
            pass

    with patch(
        "backend.app.main.SessionLocal",
        return_value=fake_db,
    ), patch(
        "backend.app.main.ScanQueue",
        return_value=FakeQueue(),
    ):
        response = TestClient(app).get("/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {
            "database": "unavailable",
            "redis": "unavailable",
        },
    }
