from backend.app.services.scan_queue import ScanJob, ScanQueue


class FakeRedis:
    def __init__(self):
        self.groups = []
        self.messages = []
        self.acks = []
        self.deleted_keys = []

    def xgroup_create(
        self,
        name,
        groupname,
        id,
        mkstream,
    ):
        self.groups.append(
            (name, groupname, id, mkstream)
        )

    def xadd(self, stream, fields):
        self.messages.append(
            (stream, fields)
        )
        return "1-0"

    def xreadgroup(
        self,
        groupname,
        consumername,
        streams,
        count,
        block,
    ):
        return [
            (
                next(iter(streams)),
                [
                    (
                        "1-0",
                        {
                            "scan_id": "42",
                            "provider": "aws",
                        },
                    )
                ],
            )
        ]

    def xack(
        self,
        stream,
        group,
        message_id,
    ):
        self.acks.append(
            (stream, group, message_id)
        )

    def delete(self, key):
        self.deleted_keys.append(key)

    def ping(self):
        return True

    def close(self):
        pass


def test_scan_queue_enqueue():
    client = FakeRedis()

    queue = ScanQueue(
        redis_url="redis://unused",
    )

    queue.client = client

    message_id = queue.enqueue(
        ScanJob(
            scan_id=42,
            provider="aws",
        )
    )

    assert message_id == "1-0"
    assert len(client.messages) == 1

    stream, fields = client.messages[0]

    assert stream == queue.stream_name
    assert fields == {
        "scan_id": "42",
        "provider": "aws",
    }


def test_scan_queue_read():
    client = FakeRedis()

    queue = ScanQueue(
        redis_url="redis://unused",
    )

    queue.client = client

    jobs = queue.read(block_ms=1)

    assert len(jobs) == 1

    message_id, job = jobs[0]

    assert message_id == "1-0"
    assert job.scan_id == 42
    assert job.provider == "aws"


def test_scan_queue_acknowledge():
    client = FakeRedis()

    queue = ScanQueue(
        redis_url="redis://unused",
    )

    queue.client = client

    queue.acknowledge("1-0")

    assert client.acks == [
        (
            queue.stream_name,
            queue.group_name,
            "1-0",
        )
    ]


def test_scan_queue_ping():
    client = FakeRedis()

    queue = ScanQueue(
        redis_url="redis://unused",
    )

    queue.client = client

    assert queue.ping() is True


def test_recover_pending_reclaims_idle_job():
    from backend.app.services.scan_queue import (
        ScanJob,
        ScanQueue,
    )

    class FakeRedis:
        def __init__(self):
            self.retry_values = {}

        def xgroup_create(self, **_kwargs):
            return True

        def xautoclaim(self, *args, **kwargs):
            return (
                "0-0",
                [
                    (
                        "10-0",
                        {
                            "scan_id": "42",
                            "provider": "aws",
                        },
                    )
                ],
                [],
            )

        def incr(self, key):
            self.retry_values[key] = (
                self.retry_values.get(key, 0) + 1
            )
            return self.retry_values[key]

        def delete(self, key):
            self.retry_values.pop(key, None)

        def xack(self, *args):
            return 1

        def xadd(self, *args, **kwargs):
            return "20-0"

    queue = ScanQueue(
        max_retries=3,
    )
    queue.client = FakeRedis()

    recovered = queue.recover_pending(
        min_idle_ms=30_000,
        count=10,
    )

    assert len(recovered) == 1
    assert recovered[0].message_id == "10-0"
    assert recovered[0].job == ScanJob(
        scan_id=42,
        provider="aws",
    )
    assert recovered[0].retry_count == 1


def test_recover_pending_moves_job_to_dead_letter_after_max_retries():
    from backend.app.services.scan_queue import ScanQueue

    class FakeRedis:
        def __init__(self):
            self.retry_values = {
                "cloudsentinel:scan_retry:10-0": 3,
            }
            self.acked = []
            self.dead_letter = []

        def xgroup_create(self, **_kwargs):
            return True

        def xautoclaim(self, *args, **kwargs):
            return (
                "0-0",
                [
                    (
                        "10-0",
                        {
                            "scan_id": "42",
                            "provider": "aws",
                        },
                    )
                ],
                [],
            )

        def incr(self, key):
            self.retry_values[key] = (
                self.retry_values.get(key, 0) + 1
            )
            return self.retry_values[key]

        def delete(self, key):
            self.retry_values.pop(key, None)

        def xack(self, stream, group, message_id):
            self.acked.append(
                (stream, group, message_id)
            )
            return 1

        def xadd(self, stream, fields):
            self.dead_letter.append(
                (stream, fields)
            )
            return "20-0"

    queue = ScanQueue(
        max_retries=3,
    )
    queue.client = FakeRedis()

    recovered = queue.recover_pending(
        min_idle_ms=30_000,
        count=10,
    )

    assert recovered == []

    assert queue.client.acked == [
        (
            queue.stream_name,
            queue.group_name,
            "10-0",
        )
    ]

    assert len(queue.client.dead_letter) == 1

    stream, fields = queue.client.dead_letter[0]

    assert stream == queue.dead_letter_stream
    assert fields["original_message_id"] == "10-0"
    assert fields["scan_id"] == "42"
    assert fields["provider"] == "aws"
    assert fields["retry_count"] == "4"
    assert fields["reason"] == "max_retries_exceeded"


def test_retry_count_starts_at_zero_for_unknown_message():
    from backend.app.services.scan_queue import ScanQueue

    class FakeRedis:
        def get(self, key):
            return None

    queue = ScanQueue()
    queue.client = FakeRedis()

    assert queue.retry_count("unknown-message") == 0
