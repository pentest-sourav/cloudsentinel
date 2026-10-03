from __future__ import annotations

from collections import defaultdict
from threading import Lock
from time import perf_counter, time


class MetricsRegistry:
    """Small dependency-free Prometheus text registry for API instances."""

    def __init__(self):
        self._lock = Lock()
        self._started_at = time()
        self._request_count: dict[tuple[str, str, str], int] = defaultdict(int)
        self._request_duration: dict[tuple[str, str], tuple[float, int]] = defaultdict(
            lambda: (0.0, 0)
        )

    @staticmethod
    def metric_path(request) -> str:
        route = request.scope.get("route")
        route_path = getattr(route, "path", None)
        return route_path or request.url.path

    def observe_request(
        self,
        *,
        method: str,
        path: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        status = str(status_code)
        key = (method, path, status)
        duration_key = (method, path)

        with self._lock:
            self._request_count[key] += 1
            total, count = self._request_duration[duration_key]
            self._request_duration[duration_key] = (
                total + duration_seconds,
                count + 1,
            )

    def render(self) -> str:
        lines = [
            "# HELP cloudsentinel_process_uptime_seconds Process uptime.",
            "# TYPE cloudsentinel_process_uptime_seconds gauge",
            f"cloudsentinel_process_uptime_seconds {max(time() - self._started_at, 0.0):.3f}",
            "# HELP cloudsentinel_http_requests_total Total HTTP requests.",
            "# TYPE cloudsentinel_http_requests_total counter",
        ]

        with self._lock:
            for (method, path, status), count in sorted(
                self._request_count.items()
            ):
                lines.append(
                    "cloudsentinel_http_requests_total"
                    f'{{method="{_escape(method)}",path="{_escape(path)}",status="{status}"}} {count}'
                )

            lines.extend(
                [
                    "# HELP cloudsentinel_http_request_duration_seconds_sum "
                    "Total HTTP request duration.",
                    "# TYPE cloudsentinel_http_request_duration_seconds_sum counter",
                ]
            )

            for (method, path), (total, _) in sorted(
                self._request_duration.items()
            ):
                lines.append(
                    "cloudsentinel_http_request_duration_seconds_sum"
                    f'{{method="{_escape(method)}",path="{_escape(path)}"}} {total:.6f}'
                )

            lines.extend(
                [
                    "# HELP cloudsentinel_http_request_duration_seconds_count "
                    "HTTP request count used for duration metrics.",
                    "# TYPE cloudsentinel_http_request_duration_seconds_count counter",
                ]
            )

            for (method, path), (_, count) in sorted(
                self._request_duration.items()
            ):
                lines.append(
                    "cloudsentinel_http_request_duration_seconds_count"
                    f'{{method="{_escape(method)}",path="{_escape(path)}"}} {count}'
                )

        return "\n".join(lines) + "\n"


def _escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


metrics_registry = MetricsRegistry()
