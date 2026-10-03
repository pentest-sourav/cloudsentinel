from backend.app.services.scan_queue import ScanQueue


class FakeRedis:
    def xpending(self, stream, group):
        assert stream
        assert group
        return {"pending": 7}

    def xlen(self, stream):
        if stream.endswith(":dlq"):
            return 2
        return 11


def test_scan_queue_metrics():
    queue = ScanQueue(redis_url="redis://unused")
    queue.client = FakeRedis()

    assert queue.metrics() == {
        "stream_length": 11,
        "pending_count": 7,
        "dead_letter_length": 2,
    }
