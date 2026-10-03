from urllib.parse import urlparse
import ipaddress
import socket
import time
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from backend.app.models.alert_delivery import AlertDelivery
from backend.app.models.alert_policy import AlertPolicy
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.services.finding_lifecycle_service import build_finding_identity, get_scan_lifecycle


_SEVERITY = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def _validate_endpoint(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Alert endpoints must use HTTPS.")
    host = parsed.hostname
    if host.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Local alert endpoints are not allowed.")

    addresses = []
    try:
        addresses = [info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)]
    except OSError as exc:
        raise ValueError("Alert endpoint hostname could not be resolved.") from exc

    for resolved_host in set(addresses):
        try:
            address = ipaddress.ip_address(resolved_host)
        except ValueError:
            continue
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            raise ValueError("Private or non-routable alert endpoints are not allowed.")
    return url


def list_policies(db: Session, tenant_id: int) -> list[AlertPolicy]:
    return db.query(AlertPolicy).filter(AlertPolicy.tenant_id == tenant_id).order_by(AlertPolicy.id.asc()).all()


def create_policy(db: Session, *, tenant_id: int, user_id: int, name: str, endpoint_url: str, min_severity: str, events: list[str], secret: str | None, enabled: bool) -> AlertPolicy:
    _validate_endpoint(endpoint_url)
    if db.query(AlertPolicy).filter(AlertPolicy.tenant_id == tenant_id, AlertPolicy.name == name).first():
        raise ValueError("An alert policy with this name already exists.")
    policy = AlertPolicy(
        tenant_id=tenant_id, name=name, endpoint_url=endpoint_url,
        min_severity=min_severity, events=events, secret=secret,
        enabled=enabled, created_by_user_id=user_id,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


def delete_policy(db: Session, *, tenant_id: int, policy_id: int) -> bool:
    policy = db.query(AlertPolicy).filter(AlertPolicy.id == policy_id, AlertPolicy.tenant_id == tenant_id).first()
    if policy is None:
        return False
    db.delete(policy)
    db.commit()
    return True


def policy_response(policy: AlertPolicy) -> dict:
    return {
        "id": policy.id, "name": policy.name, "enabled": policy.enabled,
        "endpoint_url": policy.endpoint_url, "min_severity": policy.min_severity,
        "events": policy.events, "has_secret": bool(policy.secret),
        "created_at": policy.created_at, "updated_at": policy.updated_at,
    }


def _event_payload(scan: Scan, finding: Finding, event: str) -> dict:
    return {
        "event": f"finding.{event}",
        "event_version": 1,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": scan.tenant_id,
        "scan_id": scan.id,
        "cloud_account_id": scan.cloud_account_id,
        "finding": {
            "id": finding.id,
            "fingerprint": build_finding_identity(finding).fingerprint,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "provider": finding.provider,
            "region": finding.region,
            "resource_type": finding.resource_type,
            "resource_id": finding.resource_id,
            "remediation": finding.remediation,
        },
    }


def dispatch_scan_alerts(db: Session, *, scan_id: int, tenant_id: int) -> dict:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
    if scan is None or scan.status not in {"completed", "completed_with_warnings"}:
        return {"matched": 0, "delivered": 0, "failed": 0}

    policies = db.query(AlertPolicy).filter(AlertPolicy.tenant_id == tenant_id, AlertPolicy.enabled.is_(True)).all()
    if not policies:
        return {"matched": 0, "delivered": 0, "failed": 0}

    lifecycle = get_scan_lifecycle(db=db, scan_id=scan_id, tenant_id=tenant_id)
    if lifecycle is None:
        return {"matched": 0, "delivered": 0, "failed": 0}

    findings = {f.id: f for f in db.query(Finding).filter(Finding.scan_id == scan_id).all()}
    delivered = failed = matched = 0

    for item in lifecycle["items"]:
        if item.status not in {"new", "reopened"} or item.current_finding_id is None:
            continue
        finding = findings.get(item.current_finding_id)
        if finding is None:
            continue
        for policy in policies:
            if item.status not in policy.events or _SEVERITY.get(finding.severity.lower(), 0) < _SEVERITY.get(policy.min_severity.lower(), 0):
                continue
            matched += 1
            event_key = f"{scan.id}:{item.fingerprint}:{item.status}"
            delivery = db.query(AlertDelivery).filter(AlertDelivery.policy_id == policy.id, AlertDelivery.event_key == event_key).first()
            if delivery is None:
                delivery = AlertDelivery(tenant_id=tenant_id, policy_id=policy.id, event_key=event_key)
                db.add(delivery)
                db.commit()
                db.refresh(delivery)
            if delivery.status == "delivered":
                continue

            payload = _event_payload(scan, finding, item.status)
            headers = {"Content-Type": "application/json", "User-Agent": "CloudSentinel-Alert/1.0"}
            if policy.secret:
                headers["X-CloudSentinel-Signature"] = policy.secret
            last_error = None
            for attempt in range(1, 4):
                try:
                    with httpx.Client(timeout=httpx.Timeout(5.0, connect=2.0), follow_redirects=False) as client:
                        response = client.post(policy.endpoint_url, json=payload, headers=headers)
                    if 200 <= response.status_code < 300:
                        delivery.status = "delivered"
                        delivery.attempts = attempt
                        delivery.last_error = None
                        delivery.delivered_at = datetime.now(timezone.utc)
                        db.commit()
                        delivered += 1
                        break
                    last_error = f"HTTP {response.status_code}"
                except Exception as exc:
                    last_error = str(exc)[:900]
                if attempt < 3:
                    time.sleep(0.25 * (2 ** (attempt - 1)))
            else:
                delivery.status = "failed"
                delivery.attempts = 3
                delivery.last_error = last_error
                db.commit()
                failed += 1

    return {"matched": matched, "delivered": delivered, "failed": failed}
