import logging
import signal
import threading
from functools import partial
from collections.abc import Callable

from backend.app.core.database import SessionLocal
from backend.app.core.config import settings
from backend.app.core.logging import configure_logging
from backend.app.models.cloud_account import CloudAccount
from backend.app.services.aws_scan_service import run_aws_scan
from backend.app.services.cloud_account_service import get_cloud_account
from backend.app.services.cloud_account_status import SCAN_ELIGIBLE_ACCOUNT_STATUSES
from backend.app.services.scan_queue import ScanJob, ScanQueue
from backend.app.services.scan_runner import ScanRunner
from backend.app.services.scan_service import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    fail_scan,
    get_scan_for_worker,
    recover_stale_running_scan,
    retry_scan,
    touch_scan_heartbeat,
)


configure_logging(
    service="worker",
    level=settings.log_level,
    log_format=settings.log_format,
)

logger = logging.getLogger("cloudsentinel.worker")


def get_scan(db, scan_id: int):
    return get_scan_for_worker(
        db=db,
        scan_id=scan_id,
    )


ScannerFactory = Callable[[CloudAccount, int], Callable[[], list]]


def _default_aws_scanner(account: CloudAccount, scan_id: int):
    return lambda: run_aws_scan(
        role_arn=account.role_arn,
        external_id=account.external_id,
        region_name=account.region,
        expected_account_id=account.external_account_id,
        scan_id=scan_id,
    )


SCANNERS: dict[str, ScannerFactory] = {
    "aws": _default_aws_scanner,
}


class ScanWorker:
    """
    Long-running worker that consumes scan jobs from Redis Streams.

    A Redis message is acknowledged only after successful processing.
    Failed scanner executions remain pending so Redis recovery can
    reclaim and retry them.
    """

    def __init__(
        self,
        queue: ScanQueue | None = None,
    ):
        self.queue = queue or ScanQueue(
            max_retries=settings.scan_queue_max_retries,
            dead_letter_max_length=settings.scan_queue_dead_letter_max_length,
        )
        self.running = True

    def _run_aws_scan(self, account: CloudAccount, scan_id: int):
        return run_aws_scan(
            role_arn=account.role_arn,
            external_id=account.external_id,
            region_name=account.region,
            expected_account_id=account.external_account_id,
            scan_id=scan_id,
            progress_callback=lambda **data: self.queue.set_progress(scan_id, **data),
        )

    def stop(self, *_args) -> None:
        logger.info("Shutdown signal received")
        self.running = False

    def _scan_heartbeat(
        self,
        scan_id: int,
        stop_event: threading.Event,
    ) -> None:
        interval_seconds = min(
            max(1.0, settings.scan_queue_stale_scan_seconds / 3),
            max(1.0, settings.scan_queue_recovery_idle_ms / 2000),
        )

        while not stop_event.wait(interval_seconds):
            heartbeat_db = SessionLocal()
            try:
                touch_scan_heartbeat(
                    db=heartbeat_db,
                    scan_id=scan_id,
                )
            except Exception:
                heartbeat_db.rollback()
                logger.exception(
                    "Failed to update scan heartbeat scan_id=%s",
                    scan_id,
                )
            finally:
                heartbeat_db.close()

    def _fail_scan(
        self,
        db,
        scan,
        message: str,
    ) -> None:
        fail_scan(
            db=db,
            scan=scan,
            error_message=message,
        )

    def process_job(
        self,
        message_id: str,
        job: ScanJob,
        recovered: bool = False,
    ) -> None:
        db = SessionLocal()

        try:
            scan = get_scan(
                db=db,
                scan_id=job.scan_id,
            )

            if scan is None:
                logger.error(
                    "Scan %s does not exist; acknowledging job %s",
                    job.scan_id,
                    message_id,
                )
                self.queue.acknowledge(message_id)
                return

            if scan.provider != job.provider:
                logger.error(
                    "Provider mismatch for scan %s: scan=%s job=%s",
                    scan.id,
                    scan.provider,
                    job.provider,
                )

                self._fail_scan(
                    db=db,
                    scan=scan,
                    message=(
                        "Scan provider does not match "
                        "the queued job provider."
                    ),
                )
                self.queue.acknowledge(message_id)
                return

            if recovered:
                if scan.status == SCAN_STATUS_COMPLETED:
                    self.queue.acknowledge(message_id)
                    return

                if scan.status == SCAN_STATUS_FAILED:
                    logger.warning(
                        "Retrying failed scan_id=%s message_id=%s",
                        job.scan_id,
                        message_id,
                    )
                    scan = retry_scan(
                        db=db,
                        scan=scan,
                    )

                elif scan.status == SCAN_STATUS_RUNNING:
                    scan = recover_stale_running_scan(
                        db=db,
                        scan=scan,
                        stale_after_seconds=(
                            settings.scan_queue_stale_scan_seconds
                        ),
                    )

                    if scan.status == SCAN_STATUS_RUNNING:
                        # A healthy worker may legitimately run longer than
                        # Redis' reclaim interval. Do not duplicate it or
                        # consume retry budget; the original worker can still
                        # acknowledge the stream entry after completion.
                        self.queue.defer_recovery(message_id)
                        logger.info(
                            "Deferring recovery for live scan_id=%s message_id=%s",
                            scan.id,
                            message_id,
                        )
                        return

                elif scan.status != SCAN_STATUS_PENDING:
                    self.queue.acknowledge(message_id)
                    logger.error(
                        "Acknowledging recovered scan_id=%s with unexpected status=%s",
                        scan.id,
                        scan.status,
                    )
                    return

            scanner_factory = SCANNERS.get(job.provider)

            if scanner_factory is None:
                logger.error(
                    "Unsupported provider '%s' for scan %s",
                    job.provider,
                    job.scan_id,
                )

                self._fail_scan(
                    db=db,
                    scan=scan,
                    message=(
                        f"Provider '{job.provider}' "
                        "is not supported."
                    ),
                )
                self.queue.acknowledge(message_id)
                return

            if scan.cloud_account_id is None:
                logger.error(
                    "Scan %s has no cloud account configured",
                    scan.id,
                )

                self._fail_scan(
                    db=db,
                    scan=scan,
                    message="AWS scan requires a cloud account.",
                )
                self.queue.acknowledge(message_id)
                return

            cloud_account = get_cloud_account(
                db=db,
                account_id=scan.cloud_account_id,
                tenant_id=scan.tenant_id,
            )

            if cloud_account is None:
                logger.error(
                    "Cloud account %s for scan %s was not found "
                    "within tenant %s",
                    scan.cloud_account_id,
                    scan.id,
                    scan.tenant_id,
                )

                self._fail_scan(
                    db=db,
                    scan=scan,
                    message=(
                        "Cloud account configured for this "
                        "scan was not found."
                    ),
                )
                self.queue.acknowledge(message_id)
                return

            if cloud_account.status not in SCAN_ELIGIBLE_ACCOUNT_STATUSES:
                logger.error(
                    "Cloud account %s is not active",
                    cloud_account.id,
                )

                self._fail_scan(
                    db=db,
                    scan=scan,
                    message="Cloud account is not connected.",
                )
                self.queue.acknowledge(message_id)
                return

            if cloud_account.provider != job.provider:
                logger.error(
                    "Cloud account provider mismatch for scan %s: "
                    "account=%s job=%s",
                    scan.id,
                    cloud_account.provider,
                    job.provider,
                )

                self._fail_scan(
                    db=db,
                    scan=scan,
                    message=(
                        "Cloud account provider does not "
                        "match the scan provider."
                    ),
                )
                self.queue.acknowledge(message_id)
                return

            if scanner_factory is _default_aws_scanner:
                scanner = partial(
                    self._run_aws_scan,
                    cloud_account,
                    scan.id,
                )
            else:
                scanner = scanner_factory(
                    cloud_account,
                    scan.id,
                )

            logger.info(
                "Starting scan",
                extra={
                    "scan_id": scan.id,
                    "provider": job.provider,
                    "cloud_account_id": cloud_account.id,
                    "message_id": message_id,
                    "recovered": recovered,
                },
            )

            heartbeat_stop = threading.Event()
            heartbeat = threading.Thread(
                target=self._scan_heartbeat,
                args=(scan.id, heartbeat_stop),
                name=f"scan-heartbeat-{scan.id}",
                daemon=True,
            )
            heartbeat.start()

            try:
                result = ScanRunner(db=db).run(
                    scan=scan,
                    scanner=scanner,
                )
            finally:
                heartbeat_stop.set()
                heartbeat.join(timeout=2)

            if result.status == SCAN_STATUS_COMPLETED:
                self.queue.acknowledge(message_id)

                logger.info(
                    "Finished scan",
                    extra={"scan_id": scan.id, "message_id": message_id},
                )
                return

            if result.status == SCAN_STATUS_FAILED:
                logger.warning(
                    "Scan failed scan_id=%s message_id=%s; "
                    "leaving Redis message pending for recovery",
                    scan.id,
                    message_id,
                )
                return

            raise RuntimeError(
                f"Scan {scan.id} ended in unexpected "
                f"status '{result.status}'."
            )

        except Exception:
            db.rollback()

            logger.exception(
                "Worker failed processing scan_id=%s "
                "message_id=%s; leaving message pending",
                job.scan_id,
                message_id,
            )

        finally:
            db.close()

    def run(self) -> None:
        self.queue.ensure_group()

        logger.info(
            "CloudSentinel worker started "
            "stream=%s group=%s consumer=%s",
            self.queue.stream_name,
            self.queue.group_name,
            self.queue.consumer_name,
        )

        while self.running:
            recovered_jobs = self.queue.recover_pending(
                min_idle_ms=settings.scan_queue_recovery_idle_ms,
                count=settings.scan_queue_recovery_batch_size,
            )

            for recovered in recovered_jobs:
                if not self.running:
                    break

                self.process_job(
                    message_id=recovered.message_id,
                    job=recovered.job,
                    recovered=True,
                )

            if not self.running:
                break

            jobs = self.queue.read(block_ms=settings.scan_queue_read_block_ms)

            for message_id, job in jobs:
                if not self.running:
                    break

                self.process_job(
                    message_id=message_id,
                    job=job,
                )

        self.queue.close()

        logger.info("CloudSentinel worker stopped")


def main() -> None:
    worker = ScanWorker()

    signal.signal(
        signal.SIGINT,
        worker.stop,
    )

    signal.signal(
        signal.SIGTERM,
        worker.stop,
    )

    worker.run()


if __name__ == "__main__":
    main()
