import os
import socket
import time
from dataclasses import dataclass

import redis
from redis.exceptions import ResponseError

from backend.app.core.config import settings


@dataclass(frozen=True)
class ScanJob:
    scan_id: int
    provider: str


@dataclass(frozen=True)
class RecoveredScanJob:
    message_id: str
    job: ScanJob
    retry_count: int


class ScanQueue:
    """
    Redis Streams based scan queue.

    Jobs remain pending in the consumer group's PEL until the worker
    acknowledges successful processing. Pending jobs can be reclaimed
    after they have remained idle for the configured recovery period.

    Retry counts are stored separately in Redis so a reclaimed message
    keeps its original stream identity. Jobs exceeding the retry limit
    are moved to the dead-letter stream before the original message is
    acknowledged.
    """

    RETRY_KEY_PREFIX = "cloudsentinel:scan_retry:"
    WORKER_HEARTBEAT_PREFIX = "cloudsentinel:worker_heartbeat:"
    DLQ_SUFFIX = ":dlq"

    def __init__(
        self,
        redis_url: str | None = None,
        stream_name: str | None = None,
        group_name: str | None = None,
        consumer_name: str | None = None,
        max_retries: int | None = None,
        dead_letter_max_length: int | None = None,
    ):
        resolved_max_retries = (
            settings.scan_queue_max_retries
            if max_retries is None
            else max_retries
        )
        if resolved_max_retries < 0:
            raise ValueError("max_retries must be >= 0")

        resolved_dlq_max_length = (
            settings.scan_queue_dead_letter_max_length
            if dead_letter_max_length is None
            else dead_letter_max_length
        )
        if resolved_dlq_max_length <= 0:
            raise ValueError("dead_letter_max_length must be > 0")

        self.stream_name = (
            stream_name or settings.scan_queue_stream
        )
        self.group_name = (
            group_name or settings.scan_queue_group
        )
        self.consumer_name = (
            consumer_name
            or f"{socket.gethostname()}-{os.getpid()}"
        )
        self.max_retries = resolved_max_retries
        self.dead_letter_max_length = resolved_dlq_max_length
        self.retry_key_prefix = self.RETRY_KEY_PREFIX
        self.dead_letter_stream = (
            f"{self.stream_name}{self.DLQ_SUFFIX}"
        )

        self.client = redis.Redis.from_url(
            redis_url or settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=10,
            health_check_interval=30,
        )

    def ensure_group(self) -> None:
        try:
            self.client.xgroup_create(
                name=self.stream_name,
                groupname=self.group_name,
                id="0",
                mkstream=True,
            )
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def enqueue(self, job: ScanJob) -> str:
        self.ensure_group()

        return self.client.xadd(
            self.stream_name,
            {
                "scan_id": str(job.scan_id),
                "provider": job.provider,
            },
        )

    def read(
        self,
        block_ms: int = 5000,
    ) -> list[tuple[str, ScanJob]]:
        self.ensure_group()

        response = self.client.xreadgroup(
            groupname=self.group_name,
            consumername=self.consumer_name,
            streams={self.stream_name: ">"},
            count=1,
            block=block_ms,
        )

        jobs: list[tuple[str, ScanJob]] = []

        for _, entries in response:
            for message_id, fields in entries:
                jobs.append(
                    (
                        message_id,
                        ScanJob(
                            scan_id=int(fields["scan_id"]),
                            provider=fields["provider"],
                        ),
                    )
                )

        return jobs

    def recover_pending(
        self,
        min_idle_ms: int = 30_000,
        count: int = 10,
    ) -> list[RecoveredScanJob]:
        """
        Reclaim pending jobs that have been idle long enough.

        The reclaimed messages become owned by this worker. Retry
        accounting is persisted independently from the stream entry.
        """
        if min_idle_ms < 0:
            raise ValueError("min_idle_ms must be >= 0")

        if count <= 0:
            raise ValueError("count must be > 0")

        self.ensure_group()

        start_id = "0-0"
        recovered: list[RecoveredScanJob] = []

        while len(recovered) < count:
            batch_count = min(
                count - len(recovered),
                100,
            )

            result = self.client.xautoclaim(
                self.stream_name,
                self.group_name,
                self.consumer_name,
                min_idle_time=min_idle_ms,
                start_id=start_id,
                count=batch_count,
            )

            next_start_id, entries, deleted_ids = result

            for deleted_id in deleted_ids:
                self._delete_retry_count(deleted_id)

            for message_id, fields in entries:
                retry_count = self._increment_retry_count(
                    message_id
                )

                job = ScanJob(
                    scan_id=int(fields["scan_id"]),
                    provider=fields["provider"],
                )

                if retry_count > self.max_retries:
                    self._move_to_dead_letter(
                        message_id=message_id,
                        job=job,
                        retry_count=retry_count,
                    )
                    self.acknowledge(message_id)
                    continue

                recovered.append(
                    RecoveredScanJob(
                        message_id=message_id,
                        job=job,
                        retry_count=retry_count,
                    )
                )

            if next_start_id == "0-0":
                break

            if next_start_id == start_id:
                break

            start_id = next_start_id

            if not entries:
                break

        return recovered

    def acknowledge(self, message_id: str) -> None:
        self.client.xack(
            self.stream_name,
            self.group_name,
            message_id,
        )
        self._delete_retry_count(message_id)

    def defer_recovery(self, message_id: str) -> None:
        """Clear transient recovery accounting when a live worker still owns the scan."""
        self._delete_retry_count(message_id)

    def retry_count(self, message_id: str) -> int:
        value = self.client.get(
            self._retry_key(message_id)
        )

        if value is None:
            return 0

        return int(value)

    def heartbeat_worker(self, ttl_seconds: int | None = None) -> None:
        """Publish this worker's liveness with an expiring Redis key."""
        ttl = (
            max(1, int(ttl_seconds))
            if ttl_seconds is not None
            else max(1, settings.scan_queue_worker_stale_seconds)
        )
        self.client.set(
            self._worker_heartbeat_key(),
            str(time.time()),
            ex=ttl,
        )

    def worker_health(self) -> dict[str, int]:
        """Return the number of currently live and stale worker heartbeats."""
        live = 0
        for _ in self.client.scan_iter(
            match=f"{self.WORKER_HEARTBEAT_PREFIX}*",
            count=100,
        ):
            live += 1
        return {"active_workers": live}

    def metrics(self) -> dict[str, int]:
        """Return bounded queue health metrics for operational monitoring."""
        pending = self.client.xpending(
            self.stream_name,
            self.group_name,
        )

        if isinstance(pending, dict):
            pending_count = int(pending.get("pending", 0))
        elif pending:
            pending_count = int(pending[0])
        else:
            pending_count = 0

        worker_health = self.worker_health()

        return {
            "stream_length": int(self.client.xlen(self.stream_name)),
            "pending_count": pending_count,
            "dead_letter_length": int(
                self.client.xlen(self.dead_letter_stream)
            ),
            "active_workers": worker_health["active_workers"],
        }

    def set_progress(self, scan_id: int, *, completed: int, total: int, service: str, region: str) -> None:
        total = max(1, int(total))
        completed = max(0, min(int(completed), total))
        self.client.hset(self._progress_key(scan_id), mapping={
            "completed": str(completed), "total": str(total),
            "service": service[:100], "region": region[:100],
        })
        self.client.expire(self._progress_key(scan_id), 86_400)

    def get_progress(self, scan_id: int) -> dict[str, object] | None:
        values = self.client.hgetall(self._progress_key(scan_id))
        if not values:
            return None
        completed = int(values.get("completed", 0))
        total = max(1, int(values.get("total", 1)))
        return {"completed": completed, "total": total,
                "percent": round((completed / total) * 100, 1),
                "service": values.get("service", ""), "region": values.get("region", "")}

    def clear_progress(self, scan_id: int) -> None:
        self.client.delete(self._progress_key(scan_id))

    def _progress_key(self, scan_id: int) -> str:
        return f"cloudsentinel:scan_progress:{scan_id}"

    def ping(self) -> bool:
        return bool(self.client.ping())

    def close(self) -> None:
        self.client.close()

    def _worker_heartbeat_key(self) -> str:
        return f"{self.WORKER_HEARTBEAT_PREFIX}{self.consumer_name}"

    def _retry_key(self, message_id: str) -> str:
        return f"{self.retry_key_prefix}{message_id}"

    def _increment_retry_count(self, message_id: str) -> int:
        return int(
            self.client.incr(
                self._retry_key(message_id)
            )
        )

    def _delete_retry_count(self, message_id: str) -> None:
        self.client.delete(
            self._retry_key(message_id)
        )

    def _move_to_dead_letter(
        self,
        message_id: str,
        job: ScanJob,
        retry_count: int,
    ) -> str:
        return self.client.xadd(
            self.dead_letter_stream,
            {
                "original_message_id": message_id,
                "scan_id": str(job.scan_id),
                "provider": job.provider,
                "retry_count": str(retry_count),
                "reason": "max_retries_exceeded",
            },
            maxlen=self.dead_letter_max_length,
            approximate=True,
        )
