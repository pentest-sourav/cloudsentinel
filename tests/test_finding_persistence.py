from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.core.database import Base
from backend.app.models.finding import Finding as FindingModel
from backend.app.models.scan import Scan
from backend.app.services.finding_service import persist_finding, create_finding
from engine.findings.model import Finding, Severity


def test_persist_finding_stores_risk_data():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="test-bucket",
            description="Bucket has a public access signal.",
            evidence={
                "internet_exposed": True,
                "sensitive_data": True,
                "asset_criticality": 4,
                "exploitability": 3,
            },
        )

        db_finding = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=finding,
        )

        assert db_finding.risk_score == 10.0
        assert db_finding.risk_level == "critical"
        assert db_finding.severity == "high"

    finally:
        db.close()

def test_persist_ec2_public_exposure_stores_risk_data():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding = Finding(
            rule_id="CS-AWS-EC2-001",
            title="SSH Port Exposed to the Internet",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="ec2_security_group",
            resource_id="sg-public-ssh",
            description="SSH is publicly exposed.",
            evidence={
                "security_group_id": "sg-public-ssh",
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "source": "0.0.0.0/0",
                "internet_exposed": True,
                "exposure_type": "ssh_port_range",
                "management_service": "SSH",
            },
            remediation="Restrict SSH access to trusted source IP ranges.",
            compliance=["CIS AWS Foundations"],
        )

        db_finding = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=finding,
        )

        assert db_finding.rule_id == "CS-AWS-EC2-001"
        assert db_finding.risk_score == 8.0
        assert db_finding.risk_level == "high"
        assert db_finding.severity == "high"
        assert db_finding.evidence["internet_exposed"] is True

    finally:
        db.close()

def test_create_finding_persists_risk_data():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding = create_finding(
            db=db,
            scan_id=scan.id,
            rule_id="CS-AWS-EC2-001",
            title="SSH Port Exposed to the Internet",
            severity="high",
            provider="aws",
            resource_type="ec2_security_group",
            resource_id="sg-test",
            description="SSH is publicly exposed.",
            evidence={
                "internet_exposed": True,
            },
            remediation="Restrict SSH access to trusted source IP ranges.",
            compliance=["CIS AWS Foundations"],
        )

        assert finding.id is not None
        assert finding.scan_id == scan.id
        assert finding.rule_id == "CS-AWS-EC2-001"
        assert finding.severity == "high"
        assert finding.risk_score == 8.0
        assert finding.risk_level == "high"
        assert finding.provider == "aws"
        assert finding.resource_type == "ec2_security_group"
        assert finding.resource_id == "sg-test"

    finally:
        db.close()


def test_persist_finding_is_idempotent_for_same_logical_finding():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="same-bucket",
            description="Bucket is publicly accessible.",
            evidence={
                "public": True,
            },
        )

        first = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=finding,
        )

        second = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=finding,
        )

        assert second.id == first.id

        total = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .count()
        )

        assert total == 1

    finally:
        db.close()


def test_persist_finding_allows_different_resources():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        first_finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="bucket-one",
            description="Bucket is public.",
        )

        second_finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="bucket-two",
            description="Bucket is public.",
        )

        first = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=first_finding,
        )

        second = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=second_finding,
        )

        assert first.id != second.id

        total = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .count()
        )

        assert total == 2

    finally:
        db.close()


def test_persist_finding_allows_same_resource_for_different_rules():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        first_finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="same-bucket",
            description="Bucket is public.",
        )

        second_finding = Finding(
            rule_id="CS-AWS-S3-002",
            title="S3 Versioning Disabled",
            severity=Severity.MEDIUM,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="same-bucket",
            description="Bucket versioning is disabled.",
        )

        first = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=first_finding,
        )

        second = persist_finding(
            db=db,
            scan_id=scan.id,
            finding=second_finding,
        )

        assert first.id != second.id

    finally:
        db.close()


def test_persist_finding_allows_same_finding_in_different_scans():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        first_scan = Scan(
            provider="aws",
            status="running",
        )

        second_scan = Scan(
            provider="aws",
            status="running",
        )

        db.add_all([first_scan, second_scan])
        db.commit()
        db.refresh(first_scan)
        db.refresh(second_scan)

        finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="same-bucket",
            description="Bucket is public.",
        )

        first = persist_finding(
            db=db,
            scan_id=first_scan.id,
            finding=finding,
        )

        second = persist_finding(
            db=db,
            scan_id=second_scan.id,
            finding=finding,
        )

        assert first.id != second.id
        assert first.scan_id != second.scan_id

    finally:
        db.close()


def test_persist_findings_persists_multiple_findings_in_one_batch():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        findings = [
            Finding(
                rule_id="CS-AWS-S3-001",
                title="S3 Public Access",
                severity=Severity.HIGH,
                provider="aws",
                resource_type="s3_bucket",
                resource_id="bucket-one",
                description="Bucket one is public.",
            ),
            Finding(
                rule_id="CS-AWS-S3-002",
                title="S3 Versioning Disabled",
                severity=Severity.MEDIUM,
                provider="aws",
                resource_type="s3_bucket",
                resource_id="bucket-two",
                description="Bucket two has versioning disabled.",
            ),
        ]

        from backend.app.services.finding_service import persist_findings

        result = persist_findings(
            db=db,
            scan_id=scan.id,
            findings=findings,
        )

        assert len(result) == 2
        assert all(item.id is not None for item in result)

        total = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .count()
        )

        assert total == 2

    finally:
        db.close()


def test_persist_findings_is_idempotent():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        findings = [
            Finding(
                rule_id="CS-AWS-S3-001",
                title="S3 Public Access",
                severity=Severity.HIGH,
                provider="aws",
                resource_type="s3_bucket",
                resource_id="bucket-one",
                description="Bucket one is public.",
            ),
            Finding(
                rule_id="CS-AWS-S3-002",
                title="S3 Versioning Disabled",
                severity=Severity.MEDIUM,
                provider="aws",
                resource_type="s3_bucket",
                resource_id="bucket-two",
                description="Bucket two has versioning disabled.",
            ),
        ]

        from backend.app.services.finding_service import persist_findings

        first = persist_findings(
            db=db,
            scan_id=scan.id,
            findings=findings,
        )

        second = persist_findings(
            db=db,
            scan_id=scan.id,
            findings=findings,
        )

        assert [item.id for item in second] == [
            item.id for item in first
        ]

        total = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .count()
        )

        assert total == 2

    finally:
        db.close()


def test_persist_findings_handles_duplicate_engine_findings_in_same_batch():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    try:
        scan = Scan(
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="bucket-one",
            description="Bucket one is public.",
        )

        from backend.app.services.finding_service import persist_findings

        result = persist_findings(
            db=db,
            scan_id=scan.id,
            findings=[finding, finding],
        )

        assert len(result) == 2
        assert result[0].id == result[1].id

        total = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .count()
        )

        assert total == 1

    finally:
        db.close()
