from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.services.compliance_service import get_compliance_posture


def make_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


def test_compliance_posture_aggregates_real_framework_tags():
    engine = make_db()
    with Session(engine) as db:
        tenant = Tenant(name="Compliance", slug="compliance", status="active")
        db.add(tenant)
        db.commit()
        scan = Scan(
            tenant_id=tenant.id,
            cloud_account_id=10,
            provider="aws",
            status="completed_with_warnings",
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        db.add_all([
            Finding(
                scan_id=scan.id, rule_id="R1", title="A", severity="high",
                risk_score=8, risk_level="high", provider="aws", region="global",
                resource_type="s3", resource_id="bucket-a", description="A",
                compliance=["CIS AWS Foundations", "NIST 800-53"],
            ),
            Finding(
                scan_id=scan.id, rule_id="R2", title="B", severity="critical",
                risk_score=10, risk_level="critical", provider="aws", region="us-east-1",
                resource_type="iam", resource_id="user-a", description="B",
                compliance=["CIS AWS Foundations"],
            ),
        ])
        db.commit()

        result = get_compliance_posture(
            db=db, tenant_id=tenant.id, scan_id=scan.id
        )

        assert result["status"] == "completed_with_warnings"
        cis = next(item for item in result["items"] if item["framework"] == "CIS AWS Foundations")
        assert cis["finding_count"] == 2
        assert cis["critical_count"] == 1
        assert cis["high_count"] == 1
        assert cis["affected_rules"] == 2
        assert cis["affected_resources"] == 2


def test_compliance_posture_is_tenant_scoped():
    engine = make_db()
    with Session(engine) as db:
        t1 = Tenant(name="One", slug="one", status="active")
        t2 = Tenant(name="Two", slug="two", status="active")
        db.add_all([t1, t2])
        db.commit()
        scan = Scan(
            tenant_id=t1.id, provider="aws", status="completed",
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()

        assert get_compliance_posture(
            db=db, tenant_id=t2.id, scan_id=scan.id
        ) is None
