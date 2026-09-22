from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.scan import Scan
from backend.app.models.scan_execution_error import ScanExecutionError
from backend.app.models.tenant import Tenant
from backend.app.services.scan_execution_error_service import (
    clear_execution_errors,
    get_execution_errors,
    persist_execution_errors,
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


def create_test_scan(db):
    tenant = Tenant(
        name="Execution Error Test Tenant",
        slug="execution-error-test-tenant",
        status="active",
        created_at=datetime.now(timezone.utc),
    )

    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    scan = Scan(
        tenant_id=tenant.id,
        provider="aws",
        status="running",
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


class ExecutionErrorStub:
    def __init__(
        self,
        service,
        error_type,
        error_code,
        message,
    ):
        self.service = service
        self.error_type = error_type
        self.error_code = error_code
        self.message = message


def test_persist_execution_errors_stores_multiple_errors():
    db = create_test_db()

    try:
        scan = create_test_scan(db)

        errors = [
            ExecutionErrorStub(
                service="ec2",
                error_type="ClientError",
                error_code="AccessDenied",
                message="EC2 access denied",
            ),
            ExecutionErrorStub(
                service="iam",
                error_type="PermissionError",
                error_code=None,
                message="IAM access denied",
            ),
        ]

        result = persist_execution_errors(
            db=db,
            scan_id=scan.id,
            errors=errors,
        )

        assert len(result) == 2
        assert result[0].scan_id == scan.id
        assert result[0].service == "ec2"
        assert result[0].error_type == "ClientError"
        assert result[0].error_code == "AccessDenied"
        assert result[0].message == "EC2 access denied"

        assert result[1].service == "iam"
        assert result[1].error_type == "PermissionError"
        assert result[1].error_code is None
        assert result[1].message == "IAM access denied"

        assert (
            db.query(ScanExecutionError)
            .filter(ScanExecutionError.scan_id == scan.id)
            .count()
            == 2
        )
    finally:
        db.close()


def test_get_execution_errors_returns_errors_in_creation_order():
    db = create_test_db()

    try:
        scan = create_test_scan(db)

        persist_execution_errors(
            db=db,
            scan_id=scan.id,
            errors=[
                ExecutionErrorStub(
                    service="s3",
                    error_type="ClientError",
                    error_code="AccessDenied",
                    message="S3 access denied",
                ),
                ExecutionErrorStub(
                    service="rds",
                    error_type="ClientError",
                    error_code="UnauthorizedOperation",
                    message="RDS access denied",
                ),
            ],
        )

        result = get_execution_errors(
            db=db,
            scan_id=scan.id,
        )

        assert len(result) == 2
        assert result[0].service == "s3"
        assert result[1].service == "rds"
        assert result[0].id < result[1].id
    finally:
        db.close()


def test_clear_execution_errors_removes_all_errors_for_scan():
    db = create_test_db()

    try:
        scan = create_test_scan(db)

        persist_execution_errors(
            db=db,
            scan_id=scan.id,
            errors=[
                ExecutionErrorStub(
                    service="ec2",
                    error_type="ClientError",
                    error_code="AccessDenied",
                    message="EC2 access denied",
                ),
                ExecutionErrorStub(
                    service="iam",
                    error_type="PermissionError",
                    error_code=None,
                    message="IAM access denied",
                ),
            ],
        )

        assert (
            db.query(ScanExecutionError)
            .filter(ScanExecutionError.scan_id == scan.id)
            .count()
            == 2
        )

        clear_execution_errors(
            db=db,
            scan_id=scan.id,
        )

        assert (
            db.query(ScanExecutionError)
            .filter(ScanExecutionError.scan_id == scan.id)
            .count()
            == 0
        )

        assert get_execution_errors(
            db=db,
            scan_id=scan.id,
        ) == []
    finally:
        db.close()
