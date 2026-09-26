import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.user import User


@pytest.fixture()
def test_context():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client, TestSession

    app.dependency_overrides.clear()
    engine.dispose()


def _register_and_login(
    client: TestClient,
    *,
    email: str,
    full_name: str,
    tenant_name: str,
) -> str:
    password = "StrongPassword-2026!"

    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": full_name,
            "tenant_name": tenant_name,
        },
    )

    assert register_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": password,
            "tenant_name": tenant_name,
        },
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    assert token

    return token


def _create_scan_with_finding(TestSession, tenant_id: int) -> int:
    db = TestSession()

    try:
        scan = Scan(
            tenant_id=tenant_id,
            provider="aws",
            status="completed",
        )

        db.add(scan)
        db.flush()

        finding = Finding(
            scan_id=scan.id,
            rule_id="CS-AWS-REPORT-TEST-001",
            title="Report security test finding",
            severity="HIGH",
            risk_score=80.0,
            risk_level="HIGH",
            provider="aws",
            resource_type="test_resource",
            resource_id="test-resource-001",
            description="Synthetic finding used for report API security testing.",
            evidence={
                "test": True,
            },
            remediation="No remediation required for this synthetic test.",
            compliance=[
                "TEST",
            ],
        )

        db.add(finding)
        db.commit()
        db.refresh(scan)

        return scan.id
    finally:
        db.close()


def test_report_routes_require_authentication(test_context):
    client, _ = test_context

    html_response = client.get(
        "/api/v1/reports/scans/1/html"
    )
    pdf_response = client.get(
        "/api/v1/reports/scans/1/pdf"
    )

    assert html_response.status_code == 401
    assert pdf_response.status_code == 401


def test_authenticated_user_can_access_own_tenant_html_report(
    test_context,
):
    client, TestSession = test_context

    token = _register_and_login(
        client,
        email="report-owner@example.com",
        full_name="Report Owner",
        tenant_name="Report Owner Tenant",
    )

    db = TestSession()
    try:
        user = (
            db.query(User)
            .filter(
                User.email == "report-owner@example.com"
            )
            .first()
        )

        assert user is not None
        tenant_id = user.tenant_id
    finally:
        db.close()

    scan_id = _create_scan_with_finding(
        TestSession,
        tenant_id,
    )

    response = client.get(
        f"/api/v1/reports/scans/{scan_id}/html",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 200
    assert "CloudSentinel Security Assessment" in response.text
    assert "CS-AWS-REPORT-TEST-001" in response.text
    assert "Report security test finding" in response.text

    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"

    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "style-src 'unsafe-inline'" in csp
    assert "img-src 'data:'" in csp
    assert "img-src 'data:;'" not in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp

    content_disposition = response.headers["content-disposition"]
    assert f"cloudsentinel-scan-{scan_id}.html" in content_disposition


def test_authenticated_user_can_download_own_tenant_pdf_report(
    test_context,
):
    client, TestSession = test_context

    token = _register_and_login(
        client,
        email="pdf-owner@example.com",
        full_name="PDF Owner",
        tenant_name="PDF Owner Tenant",
    )

    db = TestSession()
    try:
        user = (
            db.query(User)
            .filter(
                User.email == "pdf-owner@example.com"
            )
            .first()
        )

        assert user is not None
        tenant_id = user.tenant_id
    finally:
        db.close()

    scan_id = _create_scan_with_finding(
        TestSession,
        tenant_id,
    )

    response = client.get(
        f"/api/v1/reports/scans/{scan_id}/pdf",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "application/pdf"
    )
    assert response.content.startswith(b"%PDF-")
    assert b"%%EOF" in response.content

    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"

    content_disposition = response.headers["content-disposition"]
    assert (
        f'attachment; filename="cloudsentinel-scan-{scan_id}.pdf"'
        in content_disposition
    )


def test_report_isolated_between_tenants(test_context):
    client, TestSession = test_context

    owner_token = _register_and_login(
        client,
        email="tenant-one@example.com",
        full_name="Tenant One User",
        tenant_name="Tenant One",
    )

    attacker_token = _register_and_login(
        client,
        email="tenant-two@example.com",
        full_name="Tenant Two User",
        tenant_name="Tenant Two",
    )

    db = TestSession()
    try:
        owner = (
            db.query(User)
            .filter(
                User.email == "tenant-one@example.com"
            )
            .first()
        )

        attacker = (
            db.query(User)
            .filter(
                User.email == "tenant-two@example.com"
            )
            .first()
        )

        assert owner is not None
        assert attacker is not None
        assert owner.tenant_id != attacker.tenant_id

        scan_id = _create_scan_with_finding(
            TestSession,
            owner.tenant_id,
        )
    finally:
        db.close()

    owner_html = client.get(
        f"/api/v1/reports/scans/{scan_id}/html",
        headers={
            "Authorization": f"Bearer {owner_token}",
        },
    )

    owner_pdf = client.get(
        f"/api/v1/reports/scans/{scan_id}/pdf",
        headers={
            "Authorization": f"Bearer {owner_token}",
        },
    )

    assert owner_html.status_code == 200
    assert owner_pdf.status_code == 200

    attacker_html = client.get(
        f"/api/v1/reports/scans/{scan_id}/html",
        headers={
            "Authorization": f"Bearer {attacker_token}",
        },
    )

    attacker_pdf = client.get(
        f"/api/v1/reports/scans/{scan_id}/pdf",
        headers={
            "Authorization": f"Bearer {attacker_token}",
        },
    )

    # Do not reveal whether a resource exists in another tenant.
    assert attacker_html.status_code == 404
    assert attacker_html.json()["detail"] == "Scan not found"

    assert attacker_pdf.status_code == 404
    assert attacker_pdf.json()["detail"] == "Scan not found"


def test_report_routes_are_registered():
    openapi_paths = app.openapi()["paths"]

    assert "/api/v1/reports/scans/{scan_id}/html" in openapi_paths
    assert "/api/v1/reports/scans/{scan_id}/pdf" in openapi_paths

    html_operation = openapi_paths[
        "/api/v1/reports/scans/{scan_id}/html"
    ]["get"]

    pdf_operation = openapi_paths[
        "/api/v1/reports/scans/{scan_id}/pdf"
    ]["get"]

    assert html_operation["responses"]
    assert pdf_operation["responses"]


def test_frontend_report_does_not_put_token_in_url():
    from pathlib import Path

    source = Path("frontend/app.js").read_text()

    assert (
        "/reports/scans/${encodeURIComponent(scanId)}/html"
        in source
    )
    assert (
        "/reports/scans/${encodeURIComponent(scanId)}/pdf"
        in source
    )
    assert "Authorization: `Bearer ${state.token}`" in source

    # The old insecure direct-navigation pattern must not return.
    assert 'window.open(url, "_blank", "noopener")' not in source
