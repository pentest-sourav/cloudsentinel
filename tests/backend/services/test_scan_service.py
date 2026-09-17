from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.scan import Scan
from backend.app.services.scan_service import (
    complete_scan,
    create_scan,
    fail_scan,
    start_scan,
)


def create_test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    return TestSession()


def test_scan_lifecycle():
    db = create_test_db()

    scan = create_scan(db, "aws")

    assert scan.id is not None
    assert scan.provider == "aws"
    assert scan.status == "pending"

    scan = start_scan(db, scan)

    assert scan.status == "running"
    assert isinstance(scan.started_at, datetime)

    scan = complete_scan(db, scan)

    assert scan.status == "completed"
    assert isinstance(scan.completed_at, datetime)

    db.close()


def test_scan_failure():
    db = create_test_db()

    scan = create_scan(db, "aws")

    scan = start_scan(db, scan)

    scan = fail_scan(
        db,
        scan,
        "AWS credentials are invalid",
    )

    assert scan.status == "failed"
    assert scan.error_message == "AWS credentials are invalid"
    assert isinstance(scan.completed_at, datetime)

    db.close()
