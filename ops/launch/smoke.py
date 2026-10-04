#!/usr/bin/env python3
"""Authenticated production launch smoke test.

This test deliberately stops before a real AWS scan. A real customer/test AWS
role is environment-specific; this gate proves the deployed release can start,
reach PostgreSQL/Redis, authenticate, persist tenant state, enqueue through the
scan API boundary, and expose live worker telemetry without inventing cloud
findings.
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
METRICS_TOKEN = os.environ["METRICS_AUTH_TOKEN"]
PASSWORD = os.environ.get(
    "SMOKE_PASSWORD",
    "LaunchCertification-password-0123456789!",
)


def request(
    method: str,
    path: str,
    payload: dict | None = None,
    token: str | None = None,
) -> tuple[int, dict | str]:
    body = None
    headers = {"Accept": "application/json"}

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if token:
        headers["Authorization"] = f"Bearer {token}"

    request_obj = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )

    # A container can report healthy while the host-published socket is
    # still transitioning during process/socket replacement. Retry only
    # transport-level startup failures; HTTP responses are never retried.
    last_error: Exception | None = None
    for attempt in range(15):
        try:
            with urllib.request.urlopen(request_obj, timeout=10) as response:
                raw = response.read().decode("utf-8")
                try:
                    return response.status, json.loads(raw)
                except json.JSONDecodeError:
                    return response.status, raw
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            try:
                payload_value = json.loads(raw)
            except json.JSONDecodeError:
                payload_value = raw
            return exc.code, payload_value
        except (ConnectionResetError, ConnectionRefusedError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt == 14:
                raise
            time.sleep(2)

    raise RuntimeError(f"request failed after retries: {last_error}")


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    status, health = request("GET", "/health")
    expect(status == 200, f"/health returned {status}: {health}")
    expect(health.get("status") == "ok", f"unexpected health payload: {health}")

    status, ready = request("GET", "/ready")
    expect(status == 200, f"/ready returned {status}: {ready}")
    expect(
        ready.get("status") == "ready"
        and ready.get("checks", {}).get("database") == "ok"
        and ready.get("checks", {}).get("redis") == "ok",
        f"dependency readiness failed: {ready}",
    )

    metrics = None
    for _ in range(30):
        status, value = request(
            "GET",
            "/metrics",
            token=METRICS_TOKEN,
        )
        if status == 200 and isinstance(value, str):
            metrics = value
            marker = "cloudsentinel_scan_queue_active_workers "
            active = [
                line
                for line in value.splitlines()
                if line.startswith(marker)
            ]
            if active and float(active[0].split()[-1]) >= 1:
                break
        time.sleep(2)

    expect(metrics is not None, "authenticated /metrics did not respond")
    active_lines = [
        line
        for line in metrics.splitlines()
        if line.startswith("cloudsentinel_scan_queue_active_workers ")
    ]
    expect(
        active_lines and float(active_lines[0].split()[-1]) >= 1,
        "no live worker heartbeat was observed",
    )

    unique = uuid.uuid4().hex[:12]
    email = f"launch-{unique}@example.test"
    tenant = f"Launch Certification {unique}"

    status, registration = request(
        "POST",
        "/api/v1/auth/register",
        {
            "email": email,
            "password": PASSWORD,
            "full_name": "Launch Certification",
            "tenant_name": tenant,
        },
    )
    expect(
        status == 201,
        f"registration failed with {status}: {registration}",
    )

    status, login = request(
        "POST",
        "/api/v1/auth/login",
        {
            "email": email,
            "password": PASSWORD,
            "tenant_name": tenant,
        },
    )
    expect(status == 200, f"login failed with {status}: {login}")
    token = login.get("access_token")
    expect(bool(token), "login returned no access token")

    status, me = request("GET", "/api/v1/auth/me", token=token)
    expect(status == 200, f"/auth/me failed with {status}: {me}")
    expect(me.get("email") == email, f"unexpected authenticated identity: {me}")

    status, account = request(
        "POST",
        "/api/v1/cloud-accounts",
        {
            "name": "Launch Certification AWS",
            "provider": "aws",
            "external_account_id": "000000000000",
            "role_arn": "arn:aws:iam::000000000000:role/CloudSentinelLaunchCertification",
        },
        token=token,
    )
    expect(
        status == 201,
        f"cloud-account persistence failed with {status}: {account}",
    )
    expect(
        account.get("status") == "pending_connection",
        f"unexpected cloud-account state: {account}",
    )

    status, accounts = request(
        "GET",
        "/api/v1/cloud-accounts",
        token=token,
    )
    expect(status == 200, f"cloud-account listing failed: {accounts}")
    expect(
        any(item.get("id") == account.get("id") for item in accounts),
        "created cloud account was not returned in the tenant-scoped listing",
    )

    # A pending account must not be scannable. This verifies the production
    # control boundary without calling AWS or fabricating scan findings.
    status, rejected_scan = request(
        "POST",
        "/api/v1/scans",
        {
            "provider": "aws",
            "cloud_account_id": account["id"],
        },
        token=token,
    )
    expect(
        status == 400,
        f"pending account unexpectedly accepted a scan: {status} {rejected_scan}",
    )

    print("launch smoke: PASS")
    print("  health/readiness: PASS")
    print("  live worker heartbeat: PASS")
    print("  registration/login/me: PASS")
    print("  tenant-scoped cloud account persistence: PASS")
    print("  pending-account scan guard: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"launch smoke: FAIL: {exc}", file=sys.stderr)
        raise
