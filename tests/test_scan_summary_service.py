from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.services.scan_summary_service import get_scan_summary


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(bind=engine)

    SessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def create_test_scan(db_session):
    scan = Scan(
        provider="aws",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )

    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    return scan


def create_test_finding(
    db_session,
    scan_id,
    severity,
    rule_id,
):
    finding = Finding(
        scan_id=scan_id,
        rule_id=rule_id,
        title=f"Test {severity} Finding",
        severity=severity,
        risk_score=5.0,
        risk_level=severity,
        provider="aws",
        resource_type="test_resource",
        resource_id=f"resource-{rule_id}",
        description="Test finding",
        evidence={},
        remediation="Test remediation",
        compliance=["Test"],
    )

    db_session.add(finding)
    db_session.commit()

    return finding


def test_scan_summary_counts_findings_by_severity(db_session):
    scan = create_test_scan(db_session)

    create_test_finding(
        db_session,
        scan.id,
        "critical",
        "TEST-001",
    )

    create_test_finding(
        db_session,
        scan.id,
        "high",
        "TEST-002",
    )

    create_test_finding(
        db_session,
        scan.id,
        "medium",
        "TEST-003",
    )

    create_test_finding(
        db_session,
        scan.id,
        "medium",
        "TEST-004",
    )

    create_test_finding(
        db_session,
        scan.id,
        "low",
        "TEST-005",
    )

    create_test_finding(
        db_session,
        scan.id,
        "info",
        "TEST-006",
    )

    summary = get_scan_summary(
        db=db_session,
        scan_id=scan.id,
    )

    assert summary["scan_id"] == scan.id
    assert summary["provider"] == "aws"
    assert summary["status"] == "completed"

    assert summary["total_findings"] == 6
    assert summary["critical_count"] == 1
    assert summary["high_count"] == 1
    assert summary["medium_count"] == 2
    assert summary["low_count"] == 1
    assert summary["info_count"] == 1


def test_scan_summary_returns_zero_counts_when_no_findings(
    db_session,
):
    scan = create_test_scan(db_session)

    summary = get_scan_summary(
        db=db_session,
        scan_id=scan.id,
    )

    assert summary["scan_id"] == scan.id
    assert summary["provider"] == "aws"
    assert summary["status"] == "completed"

    assert summary["total_findings"] == 0
    assert summary["critical_count"] == 0
    assert summary["high_count"] == 0
    assert summary["medium_count"] == 0
    assert summary["low_count"] == 0
    assert summary["info_count"] == 0


def test_scan_summary_returns_none_for_unknown_scan(
    db_session,
):
    summary = get_scan_summary(
        db=db_session,
        scan_id=99999,
    )

    assert summary is None
