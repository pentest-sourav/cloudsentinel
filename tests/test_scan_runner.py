from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from backend.app.core.database import Base
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.models.finding import Finding as FindingModel
from backend.app.services.scan_runner import ScanRunner
from engine.findings.model import Finding, Severity


def create_test_tenant(db):
    tenant = Tenant(
        name="Scan Runner Test Tenant",
        slug="scan-runner-test-tenant",
        status="active",
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def test_scan_runner_persists_findings_and_completes_scan():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    tenant = create_test_tenant(db)

    try:
        scan = Scan(
            tenant_id=tenant.id,
            provider="aws",
            status="pending",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        engine_finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access Block Not Fully Enabled",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="test-bucket",
            description="S3 Public Access Block is not fully enabled.",
            evidence={
                "BlockPublicAcls": False,
            },
            remediation="Enable all S3 Public Access Block settings.",
            compliance=["CIS AWS Foundations"],
        )

        runner = ScanRunner(db=db)

        result = runner.run(
            scan=scan,
            scanner=lambda: [engine_finding],
        )

        assert result.id == scan.id
        assert result.status == "completed"
        assert result.started_at is not None
        assert result.completed_at is not None

        findings = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .all()
        )

        assert len(findings) == 1
        assert findings[0].rule_id == "CS-AWS-S3-001"
        assert findings[0].severity == "high"
        assert findings[0].resource_id == "test-bucket"

    finally:
        db.close()

def test_scan_runner_fails_scan_when_finding_persistence_fails():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    tenant = create_test_tenant(db)

    try:
        scan = Scan(
            tenant_id=tenant.id,
            provider="aws",
            status="pending",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        engine_finding = Finding(
            rule_id="CS-AWS-EC2-001",
            title="SSH Port Exposed to the Internet",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="ec2_security_group",
            resource_id="sg-test",
            description="SSH is publicly exposed.",
            evidence={
                "internet_exposed": True,
            },
        )

        runner = ScanRunner(db=db)

        with patch(
            "backend.app.services.scan_runner.persist_findings",
            side_effect=RuntimeError("database persistence failed"),
        ):
            result = runner.run(
                scan=scan,
                scanner=lambda: [engine_finding],
            )

        assert result.id == scan.id
        assert result.status == "failed"
        assert result.error_message == "database persistence failed"
        assert result.started_at is not None
        assert result.completed_at is not None

    finally:
        db.close()


def test_scan_runner_recovers_running_scan():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    tenant = create_test_tenant(db)

    try:
        scan = Scan(
            tenant_id=tenant.id,
            provider="aws",
            status="running",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        engine_finding = Finding(
            rule_id="CS-AWS-EC2-001",
            title="SSH Port Exposed to the Internet",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="ec2_security_group",
            resource_id="sg-recovery-test",
            description="SSH is publicly exposed.",
            evidence={
                "internet_exposed": True,
            },
        )

        runner = ScanRunner(db=db)

        result = runner.run(
            scan=scan,
            scanner=lambda: [engine_finding],
        )

        assert result.id == scan.id
        assert result.status == "completed"
        assert result.completed_at is not None

        findings = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .all()
        )

        assert len(findings) == 1
        assert findings[0].resource_id == "sg-recovery-test"

    finally:
        db.close()


def test_scan_runner_does_not_rerun_completed_scan():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    tenant = create_test_tenant(db)

    try:
        scan = Scan(
            tenant_id=tenant.id,
            provider="aws",
            status="completed",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        runner = ScanRunner(db=db)

        scanner_called = False

        def scanner():
            nonlocal scanner_called
            scanner_called = True
            return []

        with patch(
            "backend.app.services.scan_runner.persist_findings",
        ) as persist_mock:
            try:
                runner.run(
                    scan=scan,
                    scanner=scanner,
                )
            except ValueError as exc:
                assert "already completed" in str(exc)
            else:
                raise AssertionError(
                    "Completed scan should not be executed."
                )

            persist_mock.assert_not_called()

        assert scanner_called is False
        assert scan.status == "completed"

    finally:
        db.close()


def test_scan_runner_does_not_rerun_failed_scan_directly():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    tenant = create_test_tenant(db)

    try:
        scan = Scan(
            tenant_id=tenant.id,
            provider="aws",
            status="failed",
            error_message="previous worker failure",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        runner = ScanRunner(db=db)

        scanner_called = False

        def scanner():
            nonlocal scanner_called
            scanner_called = True
            return []

        with patch(
            "backend.app.services.scan_runner.persist_findings",
        ) as persist_mock:
            try:
                runner.run(
                    scan=scan,
                    scanner=scanner,
                )
            except ValueError as exc:
                assert "failed" in str(exc)
                assert "cannot be executed directly" in str(exc)
            else:
                raise AssertionError(
                    "Failed scan should not be executed directly."
                )

            persist_mock.assert_not_called()

        assert scanner_called is False
        assert scan.status == "failed"

    finally:
        db.close()


def test_scan_runner_persists_execution_errors_and_completes_scan():
    from backend.app.models.scan_execution_error import ScanExecutionError
    from backend.app.services.aws_scan_service import (
        AWSScanResult,
        ScannerExecutionError,
    )

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    tenant = create_test_tenant(db)

    try:
        scan = Scan(
            tenant_id=tenant.id,
            provider="aws",
            status="pending",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        engine_finding = Finding(
            rule_id="CS-AWS-S3-001",
            title="S3 Public Access Block Not Fully Enabled",
            severity=Severity.HIGH,
            provider="aws",
            resource_type="s3_bucket",
            resource_id="test-bucket",
            description="S3 Public Access Block is not fully enabled.",
            evidence={
                "BlockPublicAcls": False,
            },
            remediation="Enable all S3 Public Access Block settings.",
            compliance=["CIS AWS Foundations"],
        )

        execution_error = ScannerExecutionError(
            service="ec2",
            error_type="ClientError",
            error_code="AccessDenied",
            message="EC2 access denied",
        )

        runner = ScanRunner(db=db)

        result = runner.run(
            scan=scan,
            scanner=lambda: AWSScanResult(
                findings=[engine_finding],
                errors=[execution_error],
            ),
        )

        assert result.id == scan.id
        assert result.status == "completed"
        assert result.completed_at is not None

        findings = (
            db.query(FindingModel)
            .filter(FindingModel.scan_id == scan.id)
            .all()
        )

        assert len(findings) == 1
        assert findings[0].rule_id == "CS-AWS-S3-001"

        errors = (
            db.query(ScanExecutionError)
            .filter(ScanExecutionError.scan_id == scan.id)
            .all()
        )

        assert len(errors) == 1
        assert errors[0].service == "ec2"
        assert errors[0].error_type == "ClientError"
        assert errors[0].error_code == "AccessDenied"
        assert errors[0].message == "EC2 access denied"

    finally:
        db.close()


def test_scan_runner_completes_scan_when_only_execution_errors_exist():
    from backend.app.models.scan_execution_error import ScanExecutionError
    from backend.app.services.aws_scan_service import (
        AWSScanResult,
        ScannerExecutionError,
    )

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    tenant = create_test_tenant(db)

    try:
        scan = Scan(
            tenant_id=tenant.id,
            provider="aws",
            status="pending",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        execution_error = ScannerExecutionError(
            service="iam",
            error_type="PermissionError",
            error_code=None,
            message="IAM scanner could not access required API.",
        )

        runner = ScanRunner(db=db)

        result = runner.run(
            scan=scan,
            scanner=lambda: AWSScanResult(
                findings=[],
                errors=[execution_error],
            ),
        )

        assert result.status == "completed"

        errors = (
            db.query(ScanExecutionError)
            .filter(ScanExecutionError.scan_id == scan.id)
            .all()
        )

        assert len(errors) == 1
        assert errors[0].service == "iam"
        assert errors[0].error_type == "PermissionError"
        assert errors[0].error_code is None

    finally:
        db.close()
