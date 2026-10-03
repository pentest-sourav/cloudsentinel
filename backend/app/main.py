from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, Response

from backend.app.api.routes.auth import router as auth_router
from backend.app.api.routes.cloud_accounts import router as cloud_accounts_router
from backend.app.api.routes.findings import router as findings_router
from backend.app.api.routes.reports import router as reports_router
from backend.app.api.routes.scans import router as scans_router
from backend.app.core.config import settings
from backend.app.core.rate_limit import rate_limiter
from backend.app.core.database import SessionLocal
from backend.app.services.scan_queue import ScanQueue
from sqlalchemy import text


def _is_test_request(request: Request) -> bool:
    return bool(getattr(request.app.state, "testing", False))


app = FastAPI(
    title="CloudSentinel",
    description="Multi-Cloud Security Posture & Compliance Auditor",
    version=settings.app_version,
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
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


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
            return JSONResponse(
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

    return response


app.include_router(auth_router)
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
        finally:
            db.close()
    except Exception:
        pass

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
