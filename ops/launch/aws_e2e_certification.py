#!/usr/bin/env python3
"""Run a real AWS end-to-end CloudSentinel launch certification.

The script talks to the deployed production image over its API and requires
temporary AWS credentials to be available to the API/worker containers. It
never fabricates findings: the scan must execute against the supplied AWS
account and return a real completed scan.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE_URL = os.environ.get("CLOUDSENTINEL_SMOKE_URL", "http://127.0.0.1:18000").rstrip("/")
PASSWORD = os.environ.get("SMOKE_PASSWORD", "LaunchCertification-user-password-0123456789")
ROLE_ARN = os.environ["CERT_AWS_SCAN_ROLE_ARN"]
PARTIAL_ROLE_ARN = os.environ["CERT_AWS_PARTIAL_SCAN_ROLE_ARN"]
EXPECTED_ACCOUNT_ID = os.environ["CERT_AWS_EXPECTED_ACCOUNT_ID"]
REGION = os.environ.get("AWS_REGION", "us-east-1")
REQUIRED_REGIONS = [r.strip() for r in os.environ.get("CERT_AWS_REQUIRED_REGIONS", REGION).split(",") if r.strip()]
TIMEOUT_SECONDS = int(os.environ.get("CERT_AWS_SCAN_TIMEOUT_SECONDS", "3600"))
POLL_SECONDS = int(os.environ.get("CERT_AWS_SCAN_POLL_SECONDS", "10"))
READY_TIMEOUT_SECONDS = int(os.environ.get("CERT_AWS_READY_TIMEOUT_SECONDS", "120"))
READY_POLL_SECONDS = float(os.environ.get("CERT_AWS_READY_POLL_SECONDS", "2"))


def request(
    method: str,
    path: str,
    payload: dict | None = None,
    token: str | None = None,
) -> tuple[int, dict | str]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode("utf-8")
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError:
                return response.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            value = raw
        return exc.code, value


def wait_for_ready() -> None:
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        try:
            status, ready = request("GET", "/ready")
            if status == 200 and isinstance(ready, dict) and ready.get("status") == "ready":
                print("API readiness: PASS")
                return
            last_error = RuntimeError(f"API not ready: {status} {ready}")
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc

        time.sleep(READY_POLL_SECONDS)

    raise RuntimeError(
        f"API did not become ready within {READY_TIMEOUT_SECONDS}s: {last_error}"
    )


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    wait_for_ready()

    unique = uuid.uuid4().hex[:12]
    email = f"aws-cert-{unique}@cloudsentinel.com"
    tenant_name = f"AWS Launch Certification {unique}"

    status, registration = request(
        "POST",
        "/api/v1/auth/register",
        {
            "email": email,
            "password": PASSWORD,
            "full_name": "AWS Launch Certification",
            "tenant_name": tenant_name,
        },
    )
    expect(status == 201, f"registration failed: {status} {registration}")

    status, login = request(
        "POST",
        "/api/v1/auth/login",
        {
            "email": email,
            "password": PASSWORD,
            "tenant_name": tenant_name,
        },
    )
    expect(status == 200, f"login failed: {status} {login}")
    token = login.get("access_token")
    expect(bool(token), "login returned no access token")

    status, account = request(
        "POST",
        "/api/v1/cloud-accounts",
        {
            "name": "Real AWS Launch Certification",
            "provider": "aws",
            "external_account_id": EXPECTED_ACCOUNT_ID,
            "role_arn": ROLE_ARN,
            "region": REGION,
        },
        token=token,
    )
    expect(status == 201, f"cloud-account creation failed: {status} {account}")
    account_id = account["id"]

    status, connection = request(
        "GET",
        f"/api/v1/cloud-accounts/{account_id}/connection",
        token=token,
    )
    expect(status == 200, f"connection configuration failed: {status} {connection}")
    expect(
        str(connection.get("external_id", "")).startswith("cs-"),
        f"CloudSentinel external ID was not generated: {connection}",
    )

    status, tested = request(
        "POST",
        f"/api/v1/cloud-accounts/{account_id}/test",
        token=token,
    )
    expect(status == 200, f"AWS connection test HTTP failure: {status} {tested}")
    expect(tested.get("connected") is True, f"AWS STS connection failed: {tested}")
    expect(
        tested.get("actual_account_id") == EXPECTED_ACCOUNT_ID,
        f"AWS identity mismatch: {tested}",
    )

    status, scan = request(
        "POST",
        "/api/v1/scans",
        {
            "provider": "aws",
            "cloud_account_id": account_id,
        },
        token=token,
    )
    expect(status == 201, f"real AWS scan could not be queued: {status} {scan}")

    scan_id = scan["id"]
    deadline = time.monotonic() + TIMEOUT_SECONDS
    last_scan = scan

    while time.monotonic() < deadline:
        status, last_scan = request(
            "GET",
            f"/api/v1/scans/{scan_id}",
            token=token,
        )
        expect(status == 200, f"scan status request failed: {status} {last_scan}")

        state = last_scan.get("status")
        if state in {"completed", "completed_with_warnings", "failed"}:
            break

        time.sleep(POLL_SECONDS)

    state = last_scan.get("status")
    expect(
        state in {"completed", "completed_with_warnings"},
        f"AWS scan did not complete successfully: {last_scan}",
    )

    status, summary = request(
        "GET",
        f"/api/v1/scans/{scan_id}/summary",
        token=token,
    )
    expect(status == 200, f"scan summary failed: {status} {summary}")
    expect(summary.get("provider") == "aws", f"unexpected summary provider: {summary}")
    expect(summary.get("total_findings", 0) >= 0, f"invalid finding count: {summary}")
    expect("risk_posture" in summary, f"risk posture missing from summary: {summary}")

    execution_errors = summary.get("execution_error_count", 0)
    status, findings_payload = request(
        "GET",
        f"/api/v1/findings/scan/{scan_id}?limit=100&offset=0",
        token=token,
    )
    expect(status == 200, f"finding retrieval failed: {status} {findings_payload}")
    finding_regions = {item.get("region") for item in findings_payload.get("items", []) if item.get("region")}
    missing_regions = [region for region in REQUIRED_REGIONS if region not in finding_regions]
    expect(
        not missing_regions,
        f"real multi-region evidence missing required finding regions: {missing_regions}; observed={sorted(finding_regions)}",
    )
    if execution_errors:
        raise RuntimeError(
            "AWS launch certification found execution errors. "
            f"Scan {scan_id}: {execution_errors}; "
            f"errors={summary.get('execution_errors', [])}"
        )

    status, dashboard = request(
        "GET",
        f"/api/v1/scans/dashboard/overview?cloud_account_id={account_id}",
        token=token,
    )
    expect(status == 200, f"dashboard overview failed: {status} {dashboard}")

    status, graph = request(
        "GET",
        f"/api/v1/scans/{scan_id}/risk-graph",
        token=token,
    )
    expect(status == 200, f"risk graph failed: {status} {graph}")
    expect(
        graph.get("evidence_derived") is True,
        f"risk graph was not marked evidence-derived: {graph}",
    )

    # Partial-permission drill: use a deliberately restricted read-only role.
    # A successful drill must preserve usable findings while recording real AWS
    # permission failures as completed_with_warnings rather than silently passing.
    expect(PARTIAL_ROLE_ARN != ROLE_ARN, "partial-permission role must differ from the full scan role")
    partial_status, partial_account = request(
        "POST",
        "/api/v1/cloud-accounts",
        {
            "name": "Real AWS Partial Permission Certification",
            "provider": "aws",
            "external_account_id": EXPECTED_ACCOUNT_ID,
            "role_arn": PARTIAL_ROLE_ARN,
            "region": REGION,
        },
        token=token,
    )
    expect(partial_status == 201, f"partial cloud-account creation failed: {partial_status} {partial_account}")
    partial_account_id = partial_account["id"]

    partial_status, partial_test = request(
        "POST",
        f"/api/v1/cloud-accounts/{partial_account_id}/test",
        token=token,
    )
    expect(partial_status == 200 and partial_test.get("connected") is True, f"partial AWS role assumption failed: {partial_test}")

    partial_status, partial_scan = request(
        "POST",
        "/api/v1/scans",
        {"provider": "aws", "cloud_account_id": partial_account_id},
        token=token,
    )
    expect(partial_status == 201, f"partial-permission scan could not be queued: {partial_status} {partial_scan}")
    partial_scan_id = partial_scan["id"]
    partial_deadline = time.monotonic() + TIMEOUT_SECONDS
    partial_last = partial_scan
    while time.monotonic() < partial_deadline:
        partial_status, partial_last = request("GET", f"/api/v1/scans/{partial_scan_id}", token=token)
        expect(partial_status == 200, f"partial scan status request failed: {partial_status} {partial_last}")
        if partial_last.get("status") in {"completed", "completed_with_warnings", "failed"}:
            break
        time.sleep(POLL_SECONDS)

    expect(
        partial_last.get("status") == "completed_with_warnings",
        f"partial-permission scan did not preserve warning semantics: {partial_last}",
    )
    partial_status, partial_summary = request("GET", f"/api/v1/scans/{partial_scan_id}/summary", token=token)
    expect(partial_status == 200, f"partial scan summary failed: {partial_status} {partial_summary}")
    expect(partial_summary.get("execution_error_count", 0) > 0, f"partial-permission drill produced no real execution errors: {partial_summary}")
    expect(partial_summary.get("total_findings", 0) > 0, f"partial-permission drill produced no findings: {partial_summary}")

    print("real AWS launch certification: PASS")
    print(f"  AWS account: {EXPECTED_ACCOUNT_ID}")
    print(f"  AWS region: {REGION}")
    print(f"  scan id: {scan_id}")
    print(f"  scan status: {state}")
    print(f"  findings: {summary.get('total_findings')}")
    print(f"  execution errors: {execution_errors}")
    print(f"  risk posture: {summary.get('risk_posture')}")
    print("  STS account identity validation: PASS")
    print("  real scanner execution: PASS")
    print("  risk posture: PASS")
    print("  dashboard aggregation: PASS")
    print("  evidence-derived risk graph: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"real AWS launch certification: FAIL: {exc}", file=sys.stderr)
        raise
