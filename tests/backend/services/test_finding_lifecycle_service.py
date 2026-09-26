from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.services.finding_lifecycle_service import (
    get_scan_lifecycle,
)


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


def create_test_tenant(
    db_session,
    slug="finding-lifecycle-test-tenant",
):
    tenant = Tenant(
        name=f"Finding Lifecycle Test Tenant {slug}",
        slug=slug,
        status="active",
    )

    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)

    return tenant


def create_test_scan(
    db_session,
    tenant_id,
    *,
    status="completed",
    provider="aws",
    cloud_account_id=None,
    completed_at=None,
):
    scan = Scan(
        tenant_id=tenant_id,
        cloud_account_id=cloud_account_id,
        provider=provider,
        status=status,
        started_at=datetime.now(timezone.utc),
        completed_at=completed_at or datetime.now(timezone.utc),
    )

    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    return scan


def create_test_finding(
    db_session,
    scan_id,
    *,
    rule_id="TEST-001",
    resource_type="test_resource",
    resource_id="resource-001",
    provider="aws",
):
    finding = Finding(
        scan_id=scan_id,
        rule_id=rule_id,
        title=f"Test finding {rule_id}",
        severity="high",
        risk_score=7.0,
        risk_level="high",
        provider=provider,
        resource_type=resource_type,
        resource_id=resource_id,
        description="Test finding",
        evidence={},
        remediation="Test remediation",
        compliance=["Test"],
    )

    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    return finding


def get_item(lifecycle, rule_id):
    return next(
        item
        for item in lifecycle["items"]
        if item.rule_id == rule_id
    )


def test_first_completed_scan_marks_findings_as_new(db_session):
    tenant = create_test_tenant(db_session)

    scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc),
    )

    finding = create_test_finding(
        db_session,
        scan.id,
        rule_id="TEST-001",
        resource_id="resource-001",
    )

    lifecycle = get_scan_lifecycle(
        db_session,
        scan.id,
        tenant.id,
    )

    assert lifecycle is not None
    assert lifecycle["scan_id"] == scan.id
    assert lifecycle["previous_scan_id"] is None

    assert lifecycle["new"] == 1
    assert lifecycle["open"] == 0
    assert lifecycle["reopened"] == 0
    assert lifecycle["resolved"] == 0

    assert len(lifecycle["items"]) == 1

    item = lifecycle["items"][0]

    assert item.status == "new"
    assert item.rule_id == "TEST-001"
    assert item.resource_id == "resource-001"
    assert item.current_finding_id == finding.id
    assert item.first_seen_scan_id == scan.id
    assert item.last_seen_scan_id == scan.id


def test_finding_present_in_previous_scan_is_open(db_session):
    tenant = create_test_tenant(db_session)

    previous_scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )

    create_test_finding(
        db_session,
        previous_scan.id,
        rule_id="TEST-001",
        resource_id="resource-001",
    )

    current_scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc),
    )

    current_finding = create_test_finding(
        db_session,
        current_scan.id,
        rule_id="TEST-001",
        resource_id="resource-001",
    )

    lifecycle = get_scan_lifecycle(
        db_session,
        current_scan.id,
        tenant.id,
    )

    assert lifecycle is not None
    assert lifecycle["scan_id"] == current_scan.id
    assert lifecycle["previous_scan_id"] == previous_scan.id

    assert lifecycle["new"] == 0
    assert lifecycle["open"] == 1
    assert lifecycle["reopened"] == 0
    assert lifecycle["resolved"] == 0

    item = get_item(lifecycle, "TEST-001")

    assert item.status == "open"
    assert item.current_finding_id == current_finding.id
    assert item.first_seen_scan_id == previous_scan.id
    assert item.last_seen_scan_id == current_scan.id


def test_finding_absent_from_previous_scan_is_resolved(db_session):
    tenant = create_test_tenant(db_session)

    previous_scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )

    previous_finding = create_test_finding(
        db_session,
        previous_scan.id,
        rule_id="TEST-001",
        resource_id="resource-001",
    )

    current_scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc),
    )

    lifecycle = get_scan_lifecycle(
        db_session,
        current_scan.id,
        tenant.id,
    )

    assert lifecycle is not None

    assert lifecycle["new"] == 0
    assert lifecycle["open"] == 0
    assert lifecycle["reopened"] == 0
    assert lifecycle["resolved"] == 1

    assert len(lifecycle["items"]) == 1

    item = get_item(lifecycle, "TEST-001")

    assert item.status == "resolved"
    assert item.current_finding_id is None
    assert item.first_seen_scan_id == previous_scan.id
    assert item.last_seen_scan_id == previous_scan.id

    assert item.fingerprint


def test_finding_returning_after_being_absent_is_reopened(db_session):
    tenant = create_test_tenant(db_session)

    scan_one = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=3),
    )

    create_test_finding(
        db_session,
        scan_one.id,
        rule_id="TEST-001",
        resource_id="resource-001",
    )

    scan_two = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )

    scan_three = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc),
    )

    current_finding = create_test_finding(
        db_session,
        scan_three.id,
        rule_id="TEST-001",
        resource_id="resource-001",
    )

    lifecycle = get_scan_lifecycle(
        db_session,
        scan_three.id,
        tenant.id,
    )

    assert lifecycle is not None
    assert lifecycle["previous_scan_id"] == scan_two.id

    assert lifecycle["new"] == 0
    assert lifecycle["open"] == 0
    assert lifecycle["reopened"] == 1
    assert lifecycle["resolved"] == 0

    item = get_item(lifecycle, "TEST-001")

    assert item.status == "reopened"
    assert item.current_finding_id == current_finding.id
    assert item.first_seen_scan_id == scan_one.id
    assert item.last_seen_scan_id == scan_three.id


def test_new_and_resolved_findings_are_tracked_together(db_session):
    tenant = create_test_tenant(db_session)

    previous_scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )

    create_test_finding(
        db_session,
        previous_scan.id,
        rule_id="TEST-001",
        resource_id="resource-001",
    )

    current_scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc),
    )

    create_test_finding(
        db_session,
        current_scan.id,
        rule_id="TEST-002",
        resource_id="resource-002",
    )

    lifecycle = get_scan_lifecycle(
        db_session,
        current_scan.id,
        tenant.id,
    )

    assert lifecycle is not None

    assert lifecycle["new"] == 1
    assert lifecycle["open"] == 0
    assert lifecycle["reopened"] == 0
    assert lifecycle["resolved"] == 1

    assert len(lifecycle["items"]) == 2

    statuses = {
        item.rule_id: item.status
        for item in lifecycle["items"]
    }

    assert statuses["TEST-001"] == "resolved"
    assert statuses["TEST-002"] == "new"


def test_lifecycle_is_scoped_to_same_tenant(db_session):
    tenant_one = create_test_tenant(
        db_session,
        slug="finding-lifecycle-tenant-one",
    )

    tenant_two = create_test_tenant(
        db_session,
        slug="finding-lifecycle-tenant-two",
    )

    previous_scan = create_test_scan(
        db_session,
        tenant_one.id,
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=2),
    )

    create_test_finding(
        db_session,
        previous_scan.id,
        rule_id="TEST-001",
        resource_id="resource-001",
    )

    current_scan = create_test_scan(
        db_session,
        tenant_two.id,
        completed_at=datetime.now(timezone.utc),
    )

    lifecycle = get_scan_lifecycle(
        db_session,
        current_scan.id,
        tenant_two.id,
    )

    assert lifecycle is not None
    assert lifecycle["scan_id"] == current_scan.id
    assert lifecycle["previous_scan_id"] is None

    assert lifecycle["new"] == 0
    assert lifecycle["open"] == 0
    assert lifecycle["reopened"] == 0
    assert lifecycle["resolved"] == 0
    assert lifecycle["items"] == []


def test_non_completed_scan_returns_empty_lifecycle(db_session):
    tenant = create_test_tenant(db_session)

    scan = create_test_scan(
        db_session,
        tenant.id,
        status="running",
        completed_at=None,
    )

    lifecycle = get_scan_lifecycle(
        db_session,
        scan.id,
        tenant.id,
    )

    assert lifecycle is not None
    assert lifecycle["scan_id"] == scan.id
    assert lifecycle["previous_scan_id"] is None
    assert lifecycle["items"] == []
    assert lifecycle["new"] == 0
    assert lifecycle["open"] == 0
    assert lifecycle["reopened"] == 0
    assert lifecycle["resolved"] == 0


def test_missing_scan_returns_none(db_session):
    tenant = create_test_tenant(
        db_session,
        slug="missing-scan-test-tenant",
    )

    lifecycle = get_scan_lifecycle(
        db_session,
        999999,
        tenant.id,
    )

    assert lifecycle is None


def test_previous_scan_is_selected_by_completed_at_not_scan_id(
    db_session,
):
    tenant = create_test_tenant(
        db_session,
        slug="finding-lifecycle-completion-order",
    )

    earlier_completion = datetime.now(timezone.utc) - timedelta(minutes=5)
    later_completion = datetime.now(timezone.utc) - timedelta(minutes=1)

    later_id_scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=later_completion,
    )

    earlier_id_scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=earlier_completion,
    )

    current_scan = create_test_scan(
        db_session,
        tenant.id,
        completed_at=datetime.now(timezone.utc),
    )

    create_test_finding(
        db_session,
        earlier_id_scan.id,
        rule_id="TEST-ORDER-001",
        resource_id="resource-order-001",
    )

    create_test_finding(
        db_session,
        later_id_scan.id,
        rule_id="TEST-ORDER-002",
        resource_id="resource-order-002",
    )

    lifecycle = get_scan_lifecycle(
        db_session,
        current_scan.id,
        tenant.id,
    )

    assert lifecycle is not None
    assert lifecycle["previous_scan_id"] == later_id_scan.id
