import logging
import signal
from collections.abc import Callable

from backend.app.core.database import SessionLocal
from backend.app.services.aws_scan_service import run_aws_scan
from backend.app.services.scan_queue import ScanJob, ScanQueue
from backend.app.services.scan_runner import ScanRunner
from backend.app.services.scan_service import (
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    get_scan,
    retry_scan,
)


logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s %(levelname)s "
        "%(name)s %(message)s"
    ),
)

logger = logging.getLogger("cloudsentinel.worker")


SCANNERS: dict[str, Callable[[], list]] = {
    "aws": run_aws_scan,
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
        self.queue = queue or ScanQueue()
        self.running = True

    def stop(self, *_args) -> None:
        logger.info("Shutdown signal received")
        self.running = False

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

            if recovered and scan.status == SCAN_STATUS_FAILED:
                logger.warning(
                    "Retrying failed scan_id=%s message_id=%s",
                    job.scan_id,
                    message_id,
                )

                scan = retry_scan(
                    db=db,
                    scan=scan,
                )

            scanner = SCANNERS.get(job.provider)

            if scanner is None:
                logger.error(
                    "Unsupported provider '%s' for scan %s",
                    job.provider,
                    job.scan_id,
                )

                ScanRunner(db=db).run(
                    scan=scan,
                    scanner=lambda: (
                        (_ for _ in ()).throw(
                            ValueError(
                                f"Provider '{job.provider}' "
                                "is not supported."
                            )
                        )
                    ),
                )

                self.queue.acknowledge(message_id)
                return

            logger.info(
                "Starting scan_id=%s provider=%s "
                "message_id=%s recovered=%s",
                job.scan_id,
                job.provider,
                message_id,
                recovered,
            )

            result = ScanRunner(db=db).run(
                scan=scan,
                scanner=scanner,
            )

            if result.status == SCAN_STATUS_COMPLETED:
                self.queue.acknowledge(message_id)

                logger.info(
                    "Finished scan_id=%s message_id=%s",
                    job.scan_id,
                    message_id,
                )
                return

            if result.status == SCAN_STATUS_FAILED:
                logger.warning(
                    "Scan failed scan_id=%s message_id=%s; "
                    "leaving Redis message pending for recovery",
                    job.scan_id,
                    message_id,
                )
                return

            raise RuntimeError(
                f"Scan {job.scan_id} ended in unexpected "
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
                min_idle_ms=30000,
                count=10,
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

            jobs = self.queue.read(block_ms=5000)

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
