from backend.app.core.metrics import MetricsRegistry


def test_queue_metrics_are_rendered_as_prometheus_gauges():
    registry = MetricsRegistry()

    registry.observe_queue_metrics(
        stream_length=11,
        pending_count=7,
        dead_letter_length=2,
    )

    rendered = registry.render()

    assert "cloudsentinel_scan_queue_stream_length 11" in rendered
    assert "cloudsentinel_scan_queue_pending_count 7" in rendered
    assert "cloudsentinel_scan_queue_dead_letter_length 2" in rendered
    assert "cloudsentinel_scan_queue_metrics_fresh 1" in rendered
    assert "cloudsentinel_scan_queue_metrics_age_seconds" in rendered
