from collections.abc import Callable

from sqlalchemy.orm import Session

from backend.app.models.scan import Scan
from backend.app.services.finding_service import persist_finding
from backend.app.services.scan_service import (
    complete_scan,
    fail_scan,
    start_scan,
)


class ScanRunner:
    """
    Orchestrates a CloudSentinel security scan.

    The runner is responsible for scan lifecycle management,
    scanner execution, and persistence of scanner findings.
    """

    def __init__(self, db: Session):
        self.db = db

    def run(
        self,
        scan: Scan,
        scanner: Callable[[], list],
    ) -> Scan:
        try:
            start_scan(
                db=self.db,
                scan=scan,
            )

            findings = scanner()

            for finding in findings:
                persist_finding(
                    db=self.db,
                    scan_id=scan.id,
                    finding=finding,
                )

            return complete_scan(
                db=self.db,
                scan=scan,
            )

        except Exception as exc:
            return fail_scan(
                db=self.db,
                scan=scan,
                error_message=str(exc),
            )
