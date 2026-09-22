from collections.abc import Callable

from sqlalchemy.orm import Session

from backend.app.models.scan import Scan
from backend.app.services.finding_service import persist_findings
from backend.app.services.scan_execution_error_service import (
    persist_execution_errors,
)
from backend.app.services.scan_service import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    complete_scan,
    fail_scan,
    start_scan,
)


class ScanRunner:
    def __init__(self, db: Session):
        self.db = db

    def run(self, scan: Scan, scanner: Callable[[], object]) -> Scan:
        try:
            if scan.status == SCAN_STATUS_COMPLETED:
                raise ValueError(
                    f"Scan {scan.id} is already completed and cannot be executed again."
                )

            if scan.status == SCAN_STATUS_FAILED:
                raise ValueError(
                    f"Scan {scan.id} is failed and cannot be executed directly."
                )

            if scan.status == SCAN_STATUS_PENDING:
                start_scan(db=self.db, scan=scan)
            elif scan.status != SCAN_STATUS_RUNNING:
                raise ValueError(
                    f"Scan {scan.id} has unsupported status '{scan.status}'."
                )

            result = scanner()

            if hasattr(result, "findings") and hasattr(result, "errors"):
                findings = result.findings
                execution_errors = result.errors
            else:
                findings = result
                execution_errors = []

            persist_findings(
                db=self.db,
                scan_id=scan.id,
                findings=findings,
            )

            persist_execution_errors(
                db=self.db,
                scan_id=scan.id,
                errors=execution_errors,
            )

            return complete_scan(db=self.db, scan=scan)

        except ValueError:
            self.db.rollback()
            raise

        except Exception as exc:
            self.db.rollback()

            try:
                return fail_scan(
                    db=self.db,
                    scan=scan,
                    error_message=str(exc),
                )
            except Exception:
                self.db.rollback()
                raise
