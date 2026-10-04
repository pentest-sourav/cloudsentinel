from contextlib import asynccontextmanager
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.app.api.routes.alert_policies import router as alert_policies_router
from backend.app.api.routes.audit import router as audit_router
from backend.app.api.routes.auth import router as auth_router
from backend.app.api.routes.cloud_accounts import router as cloud_accounts_router
from backend.app.api.routes.findings import router as findings_router
from backend.app.api.routes.reports import router as reports_router
from backend.app.api.routes.scans import router as scans_router
from backend.app.core.config import settings
from backend.app.core.metrics import metrics_registry
from backend.app.core.logging import configure_logging, reset_request_id, set_request_id
from backend.app.core.rate_limit import rate_limiter
from backend.app.core.database import SessionLocal
from backend.app.core.health import health_tracker
from backend.app.services.audit_service import purge_expired_audit_events
from backend.app.services.scan_queue import ScanQueue


configure_logging(
    service="api",
    level=settings.log_level,
    log_format=settings.log_format,
)
from sqlalchemy import text


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Best-effort retention cleanup. Operational startup must not fail solely
    # because historical audit cleanup is unavailable.
    db = SessionLocal()
    try:
        purge_expired_audit_events(
            db=db,
            retention_days=settings.audit_retention_days,
        )
    except Exception:
        db.rollback()
    finally:
        db.close()

    yield


def _is_test_request(request: Request) -> bool:
    return (
        settings.app_environment == "test"
        or getattr(request.app.state, "testing", False)
    )


app = FastAPI(
    title="CloudSentinel",
    description="Multi-Cloud Security Posture & Compliance Auditor",
    version=settings.app_version,
    lifespan=lifespan,
)

cors_origins = [
    origin.strip()
    for origin in settings.cors_allowed_origins.split(",")
    if origin.strip()
]

if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def request_context(
    request: Request,
    call_next,
) -> Response:
    request_id = uuid4().hex
    request.state.request_id = request_id
    token = set_request_id(request_id)
    try:
        response = await call_next(request)
        response.headers.setdefault("X-Request-ID", request_id)
        return response
    finally:
        reset_request_id(token)
    return response


@app.middleware("http")
async def api_rate_limit(
    request: Request,
    call_next,
) -> Response:
    path = request.url.path

    if _is_test_request(request):
        return await call_next(request)

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if path == "/api/v1/auth/login":
            scope = "auth-login"
            limit = settings.rate_limit_auth_max_requests
        elif path == "/api/v1/auth/register":
            scope = "auth-register"
            limit = settings.rate_limit_auth_max_requests
        elif path == "/api/v1/scans":
            scope = "scan-create"
            limit = settings.rate_limit_scan_max_requests
        else:
            scope = "global"
            limit = settings.rate_limit_global_max_requests

        decision = rate_limiter.check(
            request,
            scope=scope,
            limit=limit,
            window_seconds=settings.rate_limit_window_seconds,
        )

        if not decision.allowed:
            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Please retry later.",
                },
                headers={
                    "Retry-After": str(decision.retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )
            response.headers["X-Request-ID"] = getattr(
                request.state,
                "request_id",
                uuid4().hex,
            )
            return response

        response = await call_next(request)
        response.headers.setdefault(
            "X-RateLimit-Limit",
            str(limit),
        )
        response.headers.setdefault(
            "X-RateLimit-Remaining",
            str(decision.remaining),
        )
        return response

    return await call_next(request)


@app.middleware("http")
async def security_headers(
    request: Request,
    call_next,
) -> Response:
    response = await call_next(request)

    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff",
    )
    response.headers.setdefault(
        "X-Frame-Options",
        "DENY",
    )
    response.headers.setdefault(
        "Referrer-Policy",
        "no-referrer",
    )
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    )

    if settings.security_headers_hsts_enabled:
        response.headers.setdefault(
            "Strict-Transport-Security",
            f"max-age={settings.security_headers_hsts_max_age_seconds}",
        )

    # The bundled web console is same-origin and intentionally has no
    # third-party JavaScript, fonts, frames, forms, or network endpoints.
    # Keep the API/docs behavior unchanged while giving the public console
    # a strict browser execution boundary.
    frontend_path = request.url.path
    if (
        frontend_path in {"/", "/index.html"}
        or frontend_path.endswith(".css")
        or frontend_path.endswith(".js")
    ):
        response.headers.setdefault(
            "Content-Security-Policy",
            (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "object-src 'none'"
            ),
        )
        response.headers.setdefault(
            "Cross-Origin-Opener-Policy",
            "same-origin",
        )
        response.headers.setdefault(
            "Cross-Origin-Resource-Policy",
            "same-origin",
        )

    if frontend_path in {"/", "/index.html"}:
        response.headers.setdefault(
            "Cache-Control",
            "no-cache, no-store, must-revalidate",
        )
        response.headers.setdefault(
            "Pragma",
            "no-cache",
        )

    if request.url.path.startswith("/api/v1/auth/"):
        response.headers.setdefault(
            "Cache-Control",
            "no-store",
        )
        response.headers.setdefault(
            "Pragma",
            "no-cache",
        )

    return response


app.include_router(alert_policies_router)
app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(cloud_accounts_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(reports_router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "CloudSentinel",
        "version": settings.app_version,
    }


@app.get("/ready")
def readiness_check():
    checks = {
        "database": "unavailable",
        "redis": "unavailable",
    }

    try:
        db = SessionLocal()

        try:
            db.execute(text("SELECT 1"))
            checks["database"] = "ok"
            health_tracker.record_success()
        finally:
            db.close()
    except Exception:
        health_tracker.record_failure()

    queue = None

    try:
        queue = ScanQueue()
        if queue.ping():
            checks["redis"] = "ok"
    except Exception:
        pass
    finally:
        if queue is not None:
            queue.close()

    ready = all(
        status == "ok"
        for status in checks.values()
    )

    if not ready:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "checks": checks,
            },
        )

    return {
        "status": "ready",
        "checks": checks,
    }


@app.middleware("http")
async def request_metrics(
    request: Request,
    call_next,
) -> Response:
    started = perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        metrics_registry.observe_request(
            method=request.method,
            path=request.url.path,
            status_code=500,
            duration_seconds=perf_counter() - started,
        )
        raise

    metrics_registry.observe_request(
        method=request.method,
        path=metrics_registry.metric_path(request),
        status_code=response.status_code,
        duration_seconds=perf_counter() - started,
    )
    return response


@app.middleware("http")
async def request_body_limit(
    request: Request,
    call_next,
) -> Response:
    content_length = request.headers.get("content-length")

    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            declared_length = -1

        if declared_length < 0:
            response = JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Invalid Content-Length header."},
            )
            response.headers["X-Request-ID"] = getattr(
                request.state,
                "request_id",
                uuid4().hex,
            )
            return response

        if declared_length > settings.max_request_body_bytes:
            response = JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={"detail": "Request body is too large."},
            )
            response.headers["X-Request-ID"] = getattr(
                request.state,
                "request_id",
                uuid4().hex,
            )
            return response

    return await call_next(request)


@app.get(
    "/metrics",
    include_in_schema=False,
)
def metrics(request: Request):
    if not settings.metrics_enabled:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "Not found"},
        )

    if settings.metrics_auth_token:
        authorization = request.headers.get("authorization", "")
        expected = f"Bearer {settings.metrics_auth_token}"
        if authorization != expected:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Metrics authentication required."},
                headers={"WWW-Authenticate": "Bearer"},
            )

    queue = None
    try:
        queue = ScanQueue()
        queue_metrics = queue.metrics()
        metrics_registry.observe_queue_metrics(**queue_metrics)
    except Exception:
        # Metrics must remain available even when Redis is temporarily down.
        pass
    finally:
        if queue is not None:
            queue.close()

    return Response(
        content=metrics_registry.render(max_queue_age_seconds=settings.metrics_queue_refresh_seconds),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )



_FRONTEND_DIR = (
    Path(__file__).resolve().parents[2] / "frontend"
)

if _FRONTEND_DIR.exists():
    app.mount(
        "/",
        StaticFiles(
            directory=str(_FRONTEND_DIR),
            html=True,
        ),
        name="frontend",
    )
