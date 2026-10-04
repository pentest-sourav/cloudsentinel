from __future__ import annotations

from time import monotonic


class HealthTracker:
    """Tracks process-level readiness degradation without external state."""

    def __init__(self, failure_threshold: int = 3):
        if failure_threshold <= 0:
            raise ValueError("failure_threshold must be positive")
        self.failure_threshold = failure_threshold
        self._consecutive_failures = 0
        self._last_failure_at: float | None = None

    def record_success(self) -> None:
        self._consecutive_failures = 0

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        self._last_failure_at = monotonic()

    @property
    def degraded(self) -> bool:
        return self._consecutive_failures >= self.failure_threshold

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def last_failure_age_seconds(self) -> float | None:
        if self._last_failure_at is None:
            return None
        return max(0.0, monotonic() - self._last_failure_at)


health_tracker = HealthTracker()
