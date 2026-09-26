from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.core.security import hash_password
from backend.app.main import app
from backend.app.models.finding import Finding as FindingModel
from backend.app.models.scan import Scan
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.services.auth_service import create_user_access_token


@pytest.fixture
def test_environment():
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

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client, SessionLocal

    app.dependency_overrides.clear()
    engine.dispose()


def create_test_tenant(
    db,
    name="Findings API Test Tenant",
    slug="findings-api-test-tenant",
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


def create_test_user(
    db,
    tenant,
    email="viewer@example.com",
):
    user = User(
        tenant_id=tenant.id,
        email=email,
        password_hash=hash_password("TestPassword123!"),
        full_name="Test Viewer",
        role="viewer",
        is_active=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def auth_headers(user):
    token, _expires_in = create_user_access_token(user)

    return {
        "Authorization": f"Bearer {token}",
    }


def create_scan(
    db,
    tenant_id,
):
    scan = Scan(
        tenant_id=tenant_id,
        provider="aws",
        status="completed",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


def create_finding(
    db,
    scan_id,
    rule_id,
    severity="high",
    risk_level="high",
    resource_id=None,
):
    finding = FindingModel(
        scan_id=scan_id,
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        severity=severity,
        risk_score=8.0,
        risk_level=risk_level,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=resource_id or rule_id,
        description="Test finding",
        evidence={},
        remediation="Fix it.",
        compliance=[],
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding


def test_get_finding_requires_auth(test_environment):
    client, _ = test_environment

    response = client.get("/api/v1/findings/1")

    assert response.status_code == 401


def test_list_findings_requires_auth(test_environment):
    client, _ = test_environment

    response = client.get("/api/v1/findings/scan/1")

    assert response.status_code == 401


def test_get_finding_returns_risk_fields(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
        tenant = create_test_tenant(db)
        user = create_test_user(db, tenant)
        scan = create_scan(db, tenant.id)

        finding = create_finding(
            db=db,
            scan_id=scan.id,
            rule_id="CS-AWS-S3-001",
            severity="high",
            risk_level="critical",
            resource_id="test-bucket",
        )

        response = client.get(
            f"/api/v1/findings/{finding.id}",
            headers=auth_headers(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["id"] == finding.id
        assert data["rule_id"] == "CS-AWS-S3-001"
        assert data["severity"] == "high"
        assert data["risk_score"] == 8.0
        assert data["risk_level"] == "critical"
    finally:
        db.close()


def test_list_findings_returns_paginated_results(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
        tenant = create_test_tenant(db)
        user = create_test_user(db, tenant)
        scan = create_scan(db, tenant.id)

        for i in range(1, 6):
            create_finding(
                db=db,
                scan_id=scan.id,
                rule_id=f"CS-AWS-S3-00{i}",
                resource_id=f"bucket-{i}",
            )

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}?limit=2&offset=1",
            headers=auth_headers(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 5
        assert data["limit"] == 2
        assert data["offset"] == 1
        assert len(data["items"]) == 2
    finally:
        db.close()


def test_list_findings_filters_by_severity(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
        tenant = create_test_tenant(db)
        user = create_test_user(db, tenant)
        scan = create_scan(db, tenant.id)

        create_finding(
            db,
            scan.id,
            "CS-001",
            severity="critical",
            risk_level="critical",
        )
        create_finding(
            db,
            scan.id,
            "CS-002",
            severity="high",
            risk_level="high",
        )
        create_finding(
            db,
            scan.id,
            "CS-003",
            severity="low",
            risk_level="low",
        )

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}?severity=high",
            headers=auth_headers(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["severity"] == "high"
        assert data["items"][0]["rule_id"] == "CS-002"
    finally:
        db.close()


def test_list_findings_filters_by_risk_level(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
        tenant = create_test_tenant(db)
        user = create_test_user(db, tenant)
        scan = create_scan(db, tenant.id)

        create_finding(
            db,
            scan.id,
            "CS-001",
            severity="high",
            risk_level="critical",
        )
        create_finding(
            db,
            scan.id,
            "CS-002",
            severity="high",
            risk_level="high",
        )

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}?risk_level=critical",
            headers=auth_headers(user),
        )

        assert response.status_code == 200

        data = response.json()

        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["risk_level"] == "critical"
        assert data["items"][0]["rule_id"] == "CS-001"
    finally:
        db.close()


def test_list_findings_returns_404_for_missing_scan(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
        tenant = create_test_tenant(db)
        user = create_test_user(db, tenant)

        response = client.get(
            "/api/v1/findings/scan/99999",
            headers=auth_headers(user),
        )

        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"
    finally:
        db.close()


def test_list_findings_rejects_invalid_limit(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
        tenant = create_test_tenant(db)
        user = create_test_user(db, tenant)

        response = client.get(
            "/api/v1/findings/scan/1?limit=0",
            headers=auth_headers(user),
        )

        assert response.status_code == 422
    finally:
        db.close()


def test_list_findings_rejects_negative_offset(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
        tenant = create_test_tenant(db)
        user = create_test_user(db, tenant)

        response = client.get(
            "/api/v1/findings/scan/1?offset=-1",
            headers=auth_headers(user),
        )

        assert response.status_code == 422
    finally:
        db.close()


def test_list_findings_rejects_invalid_severity(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
        tenant = create_test_tenant(db)
        user = create_test_user(db, tenant)

        response = client.get(
            "/api/v1/findings/scan/1?severity=invalid",
            headers=auth_headers(user),
        )

        assert response.status_code == 422
    finally:
        db.close()


def test_list_findings_rejects_invalid_risk_level(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
        tenant = create_test_tenant(db)
        user = create_test_user(db, tenant)

        response = client.get(
            "/api/v1/findings/scan/1?risk_level=invalid",
            headers=auth_headers(user),
        )

        assert response.status_code == 422
    finally:
        db.close()


def test_get_finding_is_tenant_scoped(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
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

        user_a = create_test_user(
            db,
            tenant_a,
            email="user-a@example.com",
        )
        user_b = create_test_user(
            db,
            tenant_b,
            email="user-b@example.com",
        )

        scan = create_scan(db, tenant_a.id)
        finding = create_finding(
            db,
            scan.id,
            "CS-AWS-S3-001",
        )

        response = client.get(
            f"/api/v1/findings/{finding.id}",
            headers=auth_headers(user_b),
        )

        assert response.status_code == 404
        assert response.json()["detail"] == "Finding not found"

        response = client.get(
            f"/api/v1/findings/{finding.id}",
            headers=auth_headers(user_a),
        )

        assert response.status_code == 200
        assert response.json()["id"] == finding.id
    finally:
        db.close()


def test_list_findings_is_tenant_scoped(test_environment):
    client, SessionLocal = test_environment
    db = SessionLocal()

    try:
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

        user_b = create_test_user(
            db,
            tenant_b,
            email="user-b@example.com",
        )

        scan = create_scan(db, tenant_a.id)

        create_finding(
            db,
            scan.id,
            "CS-AWS-S3-001",
        )

        response = client.get(
            f"/api/v1/findings/scan/{scan.id}",
            headers=auth_headers(user_b),
        )

        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"
    finally:
        db.close()
