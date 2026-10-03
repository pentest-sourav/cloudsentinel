from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.scan import Scan
from backend.app.models.scan_execution_error import ScanExecutionError
from backend.app.models.tenant import Tenant
from backend.app.services.report_service import get_scan_report_data


def test_report_data_is_tenant_scoped():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        tenant_a = Tenant(
            name="Report Tenant A",
            slug="report-tenant-a",
            status="active",
            created_at=datetime.now(timezone.utc),
        )
        tenant_b = Tenant(
            name="Report Tenant B",
            slug="report-tenant-b",
            status="active",
            created_at=datetime.now(timezone.utc),
        )
        db.add_all([tenant_a, tenant_b])
        db.commit()
        db.refresh(tenant_a)
        db.refresh(tenant_b)

        scan_a = Scan(
            tenant_id=tenant_a.id,
            provider="aws",
            status="completed",
        )
        db.add(scan_a)
        db.commit()
        db.refresh(scan_a)

        db.add(
            ScanExecutionError(
                scan_id=scan_a.id,
                service="ec2",
                region="us-east-1",
                error_type="ClientError",
                error_code="AccessDenied",
                message="Tenant A report error",
            )
        )
        db.commit()

        own = get_scan_report_data(
            db=db,
            scan_id=scan_a.id,
            tenant_id=tenant_a.id,
        )
        foreign = get_scan_report_data(
            db=db,
            scan_id=scan_a.id,
            tenant_id=tenant_b.id,
        )

        assert own is not None
        assert own.scan.tenant_id == tenant_a.id
        assert [error.message for error in own.execution_errors] == [
            "Tenant A report error"
        ]
        assert foreign is None
    finally:
        db.close()
        engine.dispose()
