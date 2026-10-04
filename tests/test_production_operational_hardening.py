from backend.app.core.health import HealthTracker
from backend.app.core.metrics import MetricsRegistry


def test_metrics_registry_bounds_series_cardinality():
    registry = MetricsRegistry()
    registry.MAX_REQUEST_SERIES = 2

    registry.observe_request(
        method="GET",
        path="/one",
        status_code=200,
        duration_seconds=0.1,
    )
    registry.observe_request(
        method="GET",
        path="/two",
        status_code=200,
        duration_seconds=0.1,
    )
    registry.observe_request(
        method="GET",
        path="/three",
        status_code=200,
        duration_seconds=0.1,
    )

    rendered = registry.render()

    assert '/one' in rendered
    assert '/two' in rendered
    assert '/three' not in rendered


def test_health_tracker_recovers_after_dependency_success():
    tracker = HealthTracker(failure_threshold=2)

    tracker.record_failure()
    assert tracker.degraded is False

    tracker.record_failure()
    assert tracker.degraded is True
    assert tracker.consecutive_failures == 2

    tracker.record_success()
    assert tracker.degraded is False
    assert tracker.consecutive_failures == 0
