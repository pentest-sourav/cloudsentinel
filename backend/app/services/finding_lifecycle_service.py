from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import func, select, tuple_
from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.scan import Scan


LIFECYCLE_NEW = "new"
LIFECYCLE_OPEN = "open"
LIFECYCLE_REOPENED = "reopened"
LIFECYCLE_RESOLVED = "resolved"


@dataclass(frozen=True)
class FindingIdentity:
    provider: str
    rule_id: str
    resource_type: str
    resource_id: str

    @property
    def fingerprint(self) -> str:
        value = "\x1f".join(
            (
                self.provider,
                self.rule_id,
                self.resource_type,
                self.resource_id,
            )
        )
        return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FindingLifecycle:
    fingerprint: str
    status: str
    provider: str
    rule_id: str
    resource_type: str
    resource_id: str
    current_finding_id: int | None
    first_seen_scan_id: int
    last_seen_scan_id: int


def build_finding_identity(finding: Finding) -> FindingIdentity:
    return FindingIdentity(
        provider=finding.provider,
        rule_id=finding.rule_id,
        resource_type=finding.resource_type,
        resource_id=finding.resource_id,
    )


def _get_scan(
    db: Session,
    scan_id: int,
    tenant_id: int,
) -> Scan | None:
    return db.scalar(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.tenant_id == tenant_id,
        )
    )


def _scan_history_scope(statement, scan: Scan):
    statement = statement.where(
        Scan.tenant_id == scan.tenant_id,
        Scan.provider == scan.provider,
        Scan.status == "completed",
    )

    if scan.cloud_account_id is None:
        statement = statement.where(
            Scan.cloud_account_id.is_(None),
        )
    else:
        statement = statement.where(
            Scan.cloud_account_id == scan.cloud_account_id,
        )

    return statement


def _historical_order_filter(
    statement,
    scan: Scan,
):
    current_completed_at = scan.completed_at

    if current_completed_at is not None:
        return statement.where(
            (Scan.completed_at < current_completed_at)
            | (
                (Scan.completed_at == current_completed_at)
                & (Scan.id < scan.id)
            )
        )

    return statement.where(
        Scan.id < scan.id,
    )


def _get_previous_completed_scan(
    db: Session,
    scan: Scan,
) -> Scan | None:
    statement = _scan_history_scope(
        select(Scan),
        scan,
    ).where(
        Scan.id != scan.id,
        Scan.completed_at.is_not(None),
    )

    statement = _historical_order_filter(
        statement,
        scan,
    )

    statement = statement.order_by(
        Scan.completed_at.desc(),
        Scan.id.desc(),
    ).limit(1)

    return db.scalar(statement)


def _get_findings_for_scan(
    db: Session,
    scan_id: int,
) -> list[Finding]:
    return list(
        db.scalars(
            select(Finding)
            .where(
                Finding.scan_id == scan_id,
            )
            .order_by(
                Finding.id.asc(),
            )
        ).all()
    )


def _get_first_seen_scan_ids(
    db: Session,
    scan: Scan,
    identities: set[FindingIdentity],
) -> dict[FindingIdentity, int]:
    """
    Resolve the earliest historical scan in which each requested finding
    identity appeared.

    Only requested identities are considered. Historical findings unrelated
    to the current/previous scan are never loaded into Python.

    The window function makes the database select the first occurrence per
    identity before rows are returned to the application.
    """
    if not identities:
        return {}

    identity_tuples = [
        (
            identity.provider,
            identity.rule_id,
            identity.resource_type,
            identity.resource_id,
        )
        for identity in identities
    ]

    row_number = func.row_number().over(
        partition_by=(
            Finding.provider,
            Finding.rule_id,
            Finding.resource_type,
            Finding.resource_id,
        ),
        order_by=(
            Scan.completed_at.asc(),
            Scan.id.asc(),
            Finding.id.asc(),
        ),
    ).label("row_number")

    statement = (
        select(
            Finding.provider.label("provider"),
            Finding.rule_id.label("rule_id"),
            Finding.resource_type.label("resource_type"),
            Finding.resource_id.label("resource_id"),
            Finding.scan_id.label("scan_id"),
            row_number,
        )
        .join(
            Scan,
            Scan.id == Finding.scan_id,
        )
        .where(
            Scan.tenant_id == scan.tenant_id,
            Scan.provider == scan.provider,
            Scan.status == "completed",
            Scan.completed_at.is_not(None),
            tuple_(
                Finding.provider,
                Finding.rule_id,
                Finding.resource_type,
                Finding.resource_id,
            ).in_(identity_tuples),
        )
    )

    if scan.cloud_account_id is None:
        statement = statement.where(
            Scan.cloud_account_id.is_(None),
        )
    else:
        statement = statement.where(
            Scan.cloud_account_id == scan.cloud_account_id,
        )

    statement = _historical_order_filter(
        statement,
        scan,
    )

    historical = statement.subquery()

    first_seen_rows = db.execute(
        select(
            historical.c.provider,
            historical.c.rule_id,
            historical.c.resource_type,
            historical.c.resource_id,
            historical.c.scan_id,
        ).where(
            historical.c.row_number == 1,
        )
    ).all()

    return {
        FindingIdentity(
            provider=row.provider,
            rule_id=row.rule_id,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
        ): row.scan_id
        for row in first_seen_rows
    }


def get_scan_lifecycle(
    db: Session,
    scan_id: int,
    tenant_id: int,
) -> dict | None:
    scan = _get_scan(
        db=db,
        scan_id=scan_id,
        tenant_id=tenant_id,
    )

    if scan is None:
        return None

    if scan.status != "completed":
        return {
            "scan_id": scan.id,
            "previous_scan_id": None,
            "items": [],
            "new": 0,
            "open": 0,
            "reopened": 0,
            "resolved": 0,
        }

    previous_scan = _get_previous_completed_scan(
        db=db,
        scan=scan,
    )

    previous_findings = (
        _get_findings_for_scan(
            db=db,
            scan_id=previous_scan.id,
        )
        if previous_scan is not None
        else []
    )

    current_findings = _get_findings_for_scan(
        db=db,
        scan_id=scan.id,
    )

    previous_by_identity: dict[FindingIdentity, Finding] = {
        build_finding_identity(finding): finding
        for finding in previous_findings
    }

    current_by_identity: dict[FindingIdentity, Finding] = {
        build_finding_identity(finding): finding
        for finding in current_findings
    }

    current_identities = set(current_by_identity)
    previous_identities = set(previous_by_identity)

    historical_candidates = (
        current_identities
        | previous_identities
    )

    historical_first_seen = _get_first_seen_scan_ids(
        db=db,
        scan=scan,
        identities=historical_candidates,
    )

    items: list[FindingLifecycle] = []

    for finding in current_findings:
        identity = build_finding_identity(finding)

        if identity in previous_by_identity:
            lifecycle_status = LIFECYCLE_OPEN
        elif identity in historical_first_seen:
            lifecycle_status = LIFECYCLE_REOPENED
        else:
            lifecycle_status = LIFECYCLE_NEW

        first_seen_scan_id = historical_first_seen.get(
            identity,
            scan.id,
        )

        if lifecycle_status == LIFECYCLE_NEW:
            first_seen_scan_id = scan.id

        items.append(
            FindingLifecycle(
                fingerprint=identity.fingerprint,
                status=lifecycle_status,
                provider=identity.provider,
                rule_id=identity.rule_id,
                resource_type=identity.resource_type,
                resource_id=identity.resource_id,
                current_finding_id=finding.id,
                first_seen_scan_id=first_seen_scan_id,
                last_seen_scan_id=scan.id,
            )
        )

    if previous_scan is not None:
        for finding in previous_findings:
            identity = build_finding_identity(finding)

            if identity in current_by_identity:
                continue

            first_seen_scan_id = historical_first_seen.get(
                identity,
                previous_scan.id,
            )

            items.append(
                FindingLifecycle(
                    fingerprint=identity.fingerprint,
                    status=LIFECYCLE_RESOLVED,
                    provider=identity.provider,
                    rule_id=identity.rule_id,
                    resource_type=identity.resource_type,
                    resource_id=identity.resource_id,
                    current_finding_id=None,
                    first_seen_scan_id=first_seen_scan_id,
                    last_seen_scan_id=previous_scan.id,
                )
            )

    new_count = sum(
        item.status == LIFECYCLE_NEW
        for item in items
    )
    open_count = sum(
        item.status == LIFECYCLE_OPEN
        for item in items
    )
    reopened_count = sum(
        item.status == LIFECYCLE_REOPENED
        for item in items
    )
    resolved_count = sum(
        item.status == LIFECYCLE_RESOLVED
        for item in items
    )

    return {
        "scan_id": scan.id,
        "previous_scan_id": (
            previous_scan.id
            if previous_scan is not None
            else None
        ),
        "items": items,
        "new": new_count,
        "open": open_count,
        "reopened": reopened_count,
        "resolved": resolved_count,
    }
