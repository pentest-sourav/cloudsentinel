from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.services.finding_service import (
    get_finding,
    get_findings_by_scan,
)


def test_finding_service_reads_are_tenant_scoped():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    db = session_factory()

    tenant_a = Tenant(
        name="Finding Scope A",
        slug="finding-scope-a",
        status="active",
    )
    tenant_b = Tenant(
        name="Finding Scope B",
        slug="finding-scope-b",
        status="active",
    )
    db.add_all([tenant_a, tenant_b])
    db.flush()

    scan_a = Scan(
        tenant_id=tenant_a.id,
        provider="aws",
        status="completed",
    )
    db.add(scan_a)
    db.flush()

    finding_a = Finding(
        scan_id=scan_a.id,
        rule_id="CS-AWS-SCOPE-001",
        title="Tenant scoped finding",
        severity="high",
        risk_score=8.0,
        risk_level="high",
        provider="aws",
        resource_type="test_resource",
        resource_id="tenant-a-resource",
        description="Tenant scope regression fixture.",
        evidence={},
        remediation="Test only.",
        compliance=[],
    )
    db.add(finding_a)
    db.commit()
    db.refresh(finding_a)

    try:
        assert get_finding(
            db=db,
            finding_id=finding_a.id,
            tenant_id=tenant_a.id,
        ) is not None

        assert get_finding(
            db=db,
            finding_id=finding_a.id,
            tenant_id=tenant_b.id,
        ) is None

        own = get_findings_by_scan(
            db=db,
            scan_id=scan_a.id,
            tenant_id=tenant_a.id,
        )
        assert own is not None
        assert own["total"] == 1

        foreign = get_findings_by_scan(
            db=db,
            scan_id=scan_a.id,
            tenant_id=tenant_b.id,
        )
        assert foreign is None
    finally:
        db.close()
        engine.dispose()
