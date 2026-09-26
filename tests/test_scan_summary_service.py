from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.services.scan_summary_service import get_scan_summary


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
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


def create_test_tenant(
    db_session,
    name="summary-test-tenant",
    slug=None,
):
    if slug is None:
        slug = name.lower().replace(" ", "-")

    tenant = Tenant(
        name=name,
        slug=slug,
        status="active",
        created_at=datetime.now(timezone.utc),
    )

    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)

    return tenant


def create_test_scan(db_session, tenant_id):
    scan = Scan(
        tenant_id=tenant_id,
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
    tenant = create_test_tenant(db_session)
    scan = create_test_scan(db_session, tenant.id)

    for severity, rule_id in [
        ("critical", "TEST-001"),
        ("high", "TEST-002"),
        ("medium", "TEST-003"),
        ("medium", "TEST-004"),
        ("low", "TEST-005"),
        ("info", "TEST-006"),
    ]:
        create_test_finding(
            db_session,
            scan.id,
            severity,
            rule_id,
        )

    summary = get_scan_summary(
        db=db_session,
        scan_id=scan.id,
        tenant_id=tenant.id,
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
    tenant = create_test_tenant(db_session)
    scan = create_test_scan(db_session, tenant.id)

    summary = get_scan_summary(
        db=db_session,
        scan_id=scan.id,
        tenant_id=tenant.id,
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
    tenant = create_test_tenant(db_session)

    summary = get_scan_summary(
        db=db_session,
        scan_id=99999,
        tenant_id=tenant.id,
    )

    assert summary is None


def test_scan_summary_is_tenant_scoped(db_session):
    tenant_a = create_test_tenant(
        db_session,
        name="tenant-a",
        slug="tenant-a",
    )

    tenant_b = create_test_tenant(
        db_session,
        name="tenant-b",
        slug="tenant-b",
    )

    scan = create_test_scan(
        db_session,
        tenant_a.id,
    )

    summary = get_scan_summary(
        db=db_session,
        scan_id=scan.id,
        tenant_id=tenant_b.id,
    )

    assert summary is None
