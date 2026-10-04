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
EXPECTED_ACCOUNT_ID = os.environ["CERT_AWS_EXPECTED_ACCOUNT_ID"]
REGION = os.environ.get("AWS_REGION", "us-east-1")
TIMEOUT_SECONDS = int(os.environ.get("CERT_AWS_SCAN_TIMEOUT_SECONDS", "1800"))
POLL_SECONDS = int(os.environ.get("CERT_AWS_SCAN_POLL_SECONDS", "10"))


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


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    status, ready = request("GET", "/ready")
    expect(status == 200 and ready.get("status") == "ready", f"API not ready: {status} {ready}")

    unique = uuid.uuid4().hex[:12]
    email = f"aws-cert-{unique}@example.test"
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
