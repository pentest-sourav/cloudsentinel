from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.cloud_account import CloudAccount
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.services.scan_service import (
    complete_scan,
    create_scan,
    fail_scan,
    retry_scan,
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


def create_test_tenant(
    db,
    name="Scan Test Tenant",
    slug="scan-test-tenant",
):
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


def create_cloud_account(
    db,
    provider="aws",
    status="connected",
):
    tenant = create_test_tenant(db)

    account = CloudAccount(
        tenant_id=tenant.id,
        name="Test AWS Account",
        provider=provider,
        external_account_id="123456789012",
        status=status,
    )

    db.add(account)
    db.commit()
    db.refresh(account)

    return account


def test_scan_lifecycle():
    db = create_test_db()
    account = create_cloud_account(db)

    scan = create_scan(
        db,
        "aws",
        tenant_id=account.tenant_id,
        cloud_account_id=account.id,
    )

    assert scan.id is not None
    assert scan.tenant_id == account.tenant_id
    assert scan.provider == "aws"
    assert scan.status == "pending"
    assert scan.cloud_account_id == account.id

    scan = start_scan(db, scan)

    assert scan.status == "running"
    assert isinstance(scan.started_at, datetime)

    scan = complete_scan(db, scan)

    assert scan.status == "completed"
    assert isinstance(scan.completed_at, datetime)

    db.close()


def test_scan_failure():
    db = create_test_db()
    account = create_cloud_account(db)

    scan = create_scan(
        db,
        "aws",
        tenant_id=account.tenant_id,
        cloud_account_id=account.id,
    )

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


def test_scan_can_be_created_for_valid_cloud_account():
    db = create_test_db()

    account = create_cloud_account(db)

    scan = create_scan(
        db,
        "aws",
        tenant_id=account.tenant_id,
        cloud_account_id=account.id,
    )

    assert scan.id is not None
    assert scan.tenant_id == account.tenant_id
    assert scan.provider == "aws"
    assert scan.cloud_account_id == account.id
    assert scan.status == "pending"

    db.close()


def test_scan_rejects_unknown_cloud_account():
    db = create_test_db()
    tenant = create_test_tenant(db)

    with pytest.raises(
        ValueError,
        match="Cloud account 999999 not found",
    ):
        create_scan(
            db,
            "aws",
            tenant_id=tenant.id,
            cloud_account_id=999999,
        )

    assert db.query(Scan).count() == 0

    db.close()


def test_scan_rejects_cloud_account_from_another_tenant():
    db = create_test_db()

    account = create_cloud_account(db)

    other_tenant = create_test_tenant(
        db,
        name="Other Scan Tenant",
        slug="other-scan-tenant",
    )

    with pytest.raises(
        ValueError,
        match=f"Cloud account {account.id} not found",
    ):
        create_scan(
            db,
            "aws",
            tenant_id=other_tenant.id,
            cloud_account_id=account.id,
        )

    assert db.query(Scan).count() == 0

    db.close()


def test_scan_rejects_inactive_cloud_account():
    db = create_test_db()

    account = create_cloud_account(
        db,
        status="inactive",
    )

    with pytest.raises(
        ValueError,
        match=f"Cloud account {account.id} is not connected",
    ):
        create_scan(
            db,
            "aws",
            tenant_id=account.tenant_id,
            cloud_account_id=account.id,
        )

    assert db.query(Scan).count() == 0

    db.close()


def test_scan_rejects_provider_mismatch():
    db = create_test_db()

    account = create_cloud_account(
        db,
        provider="azure",
    )

    with pytest.raises(
        ValueError,
        match=(
            f"Cloud account {account.id} belongs to provider "
            "'azure', not 'aws'"
        ),
    ):
        create_scan(
            db,
            "aws",
            tenant_id=account.tenant_id,
            cloud_account_id=account.id,
        )

    assert db.query(Scan).count() == 0

    db.close()


def test_get_scan_is_tenant_scoped():
    db = create_test_db()

    tenant_a = create_test_tenant(
        db,
        name="Tenant A",
        slug="tenant-a",
    )

    tenant_b = create_test_tenant(
        db,
        name="Tenant B",
        slug="tenant-b",
    )

    account_a = create_cloud_account(db)
    account_a.tenant_id = tenant_a.id
    db.commit()

    scan = create_scan(
        db,
        "aws",
        tenant_id=tenant_a.id,
        cloud_account_id=account_a.id,
    )

    from backend.app.services.scan_service import get_scan

    assert get_scan(
        db,
        scan.id,
        tenant_a.id,
    ) is not None

    assert get_scan(
        db,
        scan.id,
        tenant_b.id,
    ) is None

    db.close()


def test_failed_scan_can_be_retried():
    db = create_test_db()
    account = create_cloud_account(db)

    scan = create_scan(
        db,
        "aws",
        tenant_id=account.tenant_id,
        cloud_account_id=account.id,
    )

    scan = start_scan(db, scan)

    scan = fail_scan(
        db,
        scan,
        "AWS credentials are invalid",
    )

    scan = retry_scan(db, scan)

    assert scan.status == "pending"
    assert scan.started_at is None
    assert scan.completed_at is None
    assert scan.error_message is None

    db.close()


def test_start_scan_clears_previous_execution_errors():
    from backend.app.models.scan_execution_error import ScanExecutionError

    db = create_test_db()
    account = create_cloud_account(db)

    scan = create_scan(
        db,
        "aws",
        tenant_id=account.tenant_id,
        cloud_account_id=account.id,
    )

    scan = start_scan(db, scan)

    scan = fail_scan(
        db,
        scan,
        "EC2 scanner failed",
    )

    execution_error = ScanExecutionError(
        scan_id=scan.id,
        service="ec2",
        error_type="PermissionError",
        error_code="AccessDenied",
        message="EC2 access denied",
    )

    db.add(execution_error)
    db.commit()

    assert (
        db.query(ScanExecutionError)
        .filter(ScanExecutionError.scan_id == scan.id)
        .count()
        == 1
    )

    scan = retry_scan(db, scan)
    assert scan.status == "pending"

    scan = start_scan(db, scan)

    assert scan.status == "running"
    assert (
        db.query(ScanExecutionError)
        .filter(ScanExecutionError.scan_id == scan.id)
        .count()
        == 0
    )

    db.close()
