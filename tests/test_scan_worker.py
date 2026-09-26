from dataclasses import dataclass

from backend.worker import ScanWorker
from backend.app.services.scan_queue import (
    RecoveredScanJob,
    ScanJob,
)


@dataclass
class FakeScan:
    id: int
    provider: str
    cloud_account_id: int | None = 1
    tenant_id: int = 1
    status: str = "pending"
    error_message: str | None = None


class FakeDB:
    def __init__(self):
        self.rollback_called = False
        self.closed = False

    def rollback(self):
        self.rollback_called = True

    def close(self):
        self.closed = True


class FakeQueue:
    def __init__(self):
        self.acknowledged = []
        self.closed = False
        self.recovered = []
        self.read_jobs = []
        self.stream_name = "test-stream"
        self.group_name = "test-group"
        self.consumer_name = "test-consumer"

    def ensure_group(self):
        pass

    def acknowledge(self, message_id):
        self.acknowledged.append(message_id)

    def recover_pending(self, min_idle_ms, count):
        return self.recovered

    def read(self, block_ms):
        return self.read_jobs

    def close(self):
        self.closed = True


def fake_cloud_account(account_id, tenant_id):
    return type(
        "FakeCloudAccount",
        (),
        {
            "id": account_id,
            "tenant_id": tenant_id,
            "provider": "aws",
            "status": "active",
            "role_arn": "arn:aws:iam::123456789012:role/AuditRole",
            "external_id": "test-external-id",
            "region": "ap-south-1",
            "external_account_id": "123456789012",
        },
    )()


def patch_cloud_account(monkeypatch):
    monkeypatch.setattr(
        "backend.worker.get_cloud_account",
        lambda db, account_id, tenant_id: fake_cloud_account(
            account_id,
            tenant_id,
        ),
    )


def test_worker_acknowledges_successful_scan(monkeypatch):
    queue = FakeQueue()
    db = FakeDB()
    scan = FakeScan(id=1, provider="aws")

    monkeypatch.setattr(
        "backend.worker.SessionLocal",
        lambda: db,
    )

    monkeypatch.setattr(
        "backend.worker.get_scan",
        lambda db, scan_id: scan,
    )

    patch_cloud_account(monkeypatch)

    executed = []

    monkeypatch.setitem(
        __import__("backend.worker", fromlist=["SCANNERS"]).SCANNERS,
        "aws",
        lambda account: lambda: executed.append(True) or [],
    )

    worker = ScanWorker(queue=queue)

    def fake_run(self, scan, scanner):
        scanner()
        scan.status = "completed"
        return scan

    monkeypatch.setattr(
        "backend.worker.ScanRunner.run",
        fake_run,
    )

    worker.process_job(
        message_id="1-0",
        job=ScanJob(scan_id=1, provider="aws"),
    )

    assert executed == [True]
    assert queue.acknowledged == ["1-0"]
    assert db.closed is True


def test_worker_does_not_acknowledge_when_runner_fails(monkeypatch):
    queue = FakeQueue()
    db = FakeDB()
    scan = FakeScan(id=2, provider="aws")

    monkeypatch.setattr(
        "backend.worker.SessionLocal",
        lambda: db,
    )

    monkeypatch.setattr(
        "backend.worker.get_scan",
        lambda db, scan_id: scan,
    )

    patch_cloud_account(monkeypatch)

    def failing_run(self, scan, scanner):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(
        "backend.worker.ScanRunner.run",
        failing_run,
    )

    worker = ScanWorker(queue=queue)

    worker.process_job(
        message_id="2-0",
        job=ScanJob(scan_id=2, provider="aws"),
    )

    assert queue.acknowledged == []
    assert db.rollback_called is True
    assert db.closed is True


def test_worker_leaves_failed_scan_pending_for_recovery(monkeypatch):
    queue = FakeQueue()
    db = FakeDB()
    scan = FakeScan(
        id=3,
        provider="aws",
        status="pending",
    )

    monkeypatch.setattr(
        "backend.worker.SessionLocal",
        lambda: db,
    )

    monkeypatch.setattr(
        "backend.worker.get_scan",
        lambda db, scan_id: scan,
    )

    patch_cloud_account(monkeypatch)

    def fake_run(self, scan, scanner):
        scan.status = "failed"
        scan.error_message = "AWS API unavailable"
        return scan

    monkeypatch.setattr(
        "backend.worker.ScanRunner.run",
        fake_run,
    )

    monkeypatch.setitem(
        __import__("backend.worker", fromlist=["SCANNERS"]).SCANNERS,
        "aws",
        lambda account: lambda: [],
    )

    worker = ScanWorker(queue=queue)

    worker.process_job(
        message_id="3-0",
        job=ScanJob(scan_id=3, provider="aws"),
    )

    assert scan.status == "failed"
    assert queue.acknowledged == []
    assert db.closed is True


def test_worker_retries_recovered_failed_scan(monkeypatch):
    queue = FakeQueue()
    db = FakeDB()
    scan = FakeScan(
        id=4,
        provider="aws",
        status="failed",
        error_message="previous failure",
    )

    monkeypatch.setattr(
        "backend.worker.SessionLocal",
        lambda: db,
    )

    monkeypatch.setattr(
        "backend.worker.get_scan",
        lambda db, scan_id: scan,
    )

    patch_cloud_account(monkeypatch)

    retry_calls = []

    def fake_retry_scan(db, scan):
        retry_calls.append(scan.id)
        scan.status = "pending"
        scan.error_message = None
        return scan

    monkeypatch.setattr(
        "backend.worker.retry_scan",
        fake_retry_scan,
    )

    executed = []

    monkeypatch.setitem(
        __import__("backend.worker", fromlist=["SCANNERS"]).SCANNERS,
        "aws",
        lambda account: lambda: executed.append(True) or [],
    )

    def fake_run(self, scan, scanner):
        assert scan.status == "pending"
        scanner()
        scan.status = "completed"
        return scan

    monkeypatch.setattr(
        "backend.worker.ScanRunner.run",
        fake_run,
    )

    worker = ScanWorker(queue=queue)

    worker.process_job(
        message_id="4-0",
        job=ScanJob(scan_id=4, provider="aws"),
        recovered=True,
    )

    assert retry_calls == [4]
    assert executed == [True]
    assert scan.status == "completed"
    assert queue.acknowledged == ["4-0"]
    assert db.closed is True


def test_worker_acknowledges_missing_scan(monkeypatch):
    queue = FakeQueue()
    db = FakeDB()

    monkeypatch.setattr(
        "backend.worker.SessionLocal",
        lambda: db,
    )

    monkeypatch.setattr(
        "backend.worker.get_scan",
        lambda db, scan_id: None,
    )

    worker = ScanWorker(queue=queue)

    worker.process_job(
        message_id="5-0",
        job=ScanJob(scan_id=999, provider="aws"),
    )

    assert queue.acknowledged == ["5-0"]
    assert db.closed is True


def test_worker_acknowledges_unsupported_provider(monkeypatch):
    queue = FakeQueue()
    db = FakeDB()
    scan = FakeScan(
        id=6,
        provider="azure",
    )

    monkeypatch.setattr(
        "backend.worker.SessionLocal",
        lambda: db,
    )

    monkeypatch.setattr(
        "backend.worker.get_scan",
        lambda db, scan_id: scan,
    )

    fail_calls = []

    def fake_fail_scan(db, scan, error_message):
        fail_calls.append((scan.id, error_message))
        scan.status = "failed"
        scan.error_message = error_message
        return scan

    monkeypatch.setattr(
        "backend.worker.fail_scan",
        fake_fail_scan,
    )

    runner_calls = []

    def fake_run(self, scan, scanner):
        runner_calls.append(scan.id)
        return scan

    monkeypatch.setattr(
        "backend.worker.ScanRunner.run",
        fake_run,
    )

    worker = ScanWorker(queue=queue)

    worker.process_job(
        message_id="6-0",
        job=ScanJob(
            scan_id=6,
            provider="azure",
        ),
    )

    assert runner_calls == []
    assert scan.status == "failed"
    assert len(fail_calls) == 1
    assert "not supported" in fail_calls[0][1]
    assert queue.acknowledged == ["6-0"]
    assert db.closed is True


def test_worker_run_recovers_pending_jobs_before_new_jobs(monkeypatch):
    queue = FakeQueue()

    queue.recovered = [
        RecoveredScanJob(
            message_id="7-0",
            job=ScanJob(
                scan_id=7,
                provider="aws",
            ),
            retry_count=1,
        )
    ]

    queue.read_jobs = [
        (
            "8-0",
            ScanJob(
                scan_id=8,
                provider="aws",
            ),
        )
    ]

    db = FakeDB()

    monkeypatch.setattr(
        "backend.worker.SessionLocal",
        lambda: db,
    )

    scans = {
        7: FakeScan(
            id=7,
            provider="aws",
            status="failed",
        ),
        8: FakeScan(
            id=8,
            provider="aws",
            status="pending",
        ),
    }

    monkeypatch.setattr(
        "backend.worker.get_scan",
        lambda db, scan_id: scans[scan_id],
    )

    patch_cloud_account(monkeypatch)

    retry_calls = []

    def fake_retry_scan(db, scan):
        retry_calls.append(scan.id)
        scan.status = "pending"
        return scan

    monkeypatch.setattr(
        "backend.worker.retry_scan",
        fake_retry_scan,
    )

    execution_order = []

    def fake_run(self, scan, scanner):
        execution_order.append(scan.id)
        scan.status = "completed"
        return scan

    monkeypatch.setattr(
        "backend.worker.ScanRunner.run",
        fake_run,
    )

    monkeypatch.setitem(
        __import__("backend.worker", fromlist=["SCANNERS"]).SCANNERS,
        "aws",
        lambda account: lambda: [],
    )

    worker = ScanWorker(queue=queue)

    calls = {"count": 0}

    def stop_after_first_cycle(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] >= 1:
            worker.running = False

    original_process = worker.process_job

    def wrapped_process(*args, **kwargs):
        original_process(*args, **kwargs)
        stop_after_first_cycle()

    worker.process_job = wrapped_process

    worker.run()

    assert retry_calls == [7]
    assert execution_order == [7]
    assert queue.acknowledged == ["7-0"]
    assert queue.closed is True
