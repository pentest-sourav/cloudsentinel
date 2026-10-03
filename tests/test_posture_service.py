from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.scan_execution_error import ScanExecutionError
from backend.app.models.tenant import Tenant
from backend.app.services.posture_service import get_posture_trend


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def create_tenant(db, name, slug):
    tenant = Tenant(
        name=name,
        slug=slug,
        status="active",
        created_at=datetime.now(timezone.utc),
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def create_scan(db, tenant_id, status, completed_at, account_id=None):
    scan = Scan(
        tenant_id=tenant_id,
        cloud_account_id=account_id,
        provider="aws",
        status=status,
        started_at=completed_at - timedelta(minutes=2),
        completed_at=completed_at,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def create_finding(db, scan_id, severity, risk_score):
    finding = Finding(
        scan_id=scan_id,
        rule_id=f"RULE-{scan_id}-{severity}",
        title=f"{severity} finding",
        severity=severity,
        risk_score=risk_score,
        risk_level=severity,
        provider="aws",
        region="us-east-1",
        resource_type="test_resource",
        resource_id=f"resource-{scan_id}-{severity}",
        description="test",
        evidence={"source": "test"},
        remediation="test",
        compliance=["CIS"],
    )
    db.add(finding)
    db.commit()
    return finding


def test_posture_trend_uses_real_terminal_scan_data(db_session):
    tenant = create_tenant(db_session, "Trend Tenant", "trend-tenant")
    now = datetime.now(timezone.utc)

    older = create_scan(
        db_session,
        tenant.id,
        "completed",
        now - timedelta(days=1),
        account_id=10,
    )
    newer = create_scan(
        db_session,
        tenant.id,
        "completed_with_warnings",
        now,
        account_id=10,
    )

    create_finding(db_session, older.id, "critical", 9.0)
    create_finding(db_session, older.id, "medium", 4.0)
    create_finding(db_session, newer.id, "high", 7.0)

    db_session.add(
        ScanExecutionError(
            scan_id=newer.id,
            service="cloudtrail",
            region="us-east-1",
            error_type="AccessDeniedException",
            error_code="AccessDenied",
            message="permission denied",
        )
    )
    db_session.commit()

    result = get_posture_trend(
        db=db_session,
        tenant_id=tenant.id,
        cloud_account_id=10,
        limit=10,
    )

    assert [item["scan_id"] for item in result["items"]] == [
        newer.id,
        older.id,
    ]
    assert result["items"][0]["status"] == "completed_with_warnings"
    assert result["items"][0]["total_findings"] == 1
    assert result["items"][0]["high_count"] == 1
    assert result["items"][0]["critical_count"] == 0
    assert result["items"][0]["risk_score_sum"] == 7.0
    assert result["items"][0]["execution_error_count"] == 1


def test_posture_trend_is_tenant_and_account_scoped(db_session):
    tenant_a = create_tenant(db_session, "Tenant A", "trend-a")
    tenant_b = create_tenant(db_session, "Tenant B", "trend-b")
    now = datetime.now(timezone.utc)

    scan_a = create_scan(
        db_session,
        tenant_a.id,
        "completed",
        now,
        account_id=101,
    )
    scan_b = create_scan(
        db_session,
        tenant_b.id,
        "completed",
        now + timedelta(seconds=1),
        account_id=202,
    )
    create_finding(db_session, scan_a.id, "high", 8.0)
    create_finding(db_session, scan_b.id, "critical", 10.0)

    result = get_posture_trend(
        db=db_session,
        tenant_id=tenant_a.id,
        cloud_account_id=101,
        limit=10,
    )

    assert [item["scan_id"] for item in result["items"]] == [scan_a.id]
    assert result["items"][0]["critical_count"] == 0
