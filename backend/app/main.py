from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response

from backend.app.api.routes.auth import router as auth_router
from backend.app.api.routes.cloud_accounts import router as cloud_accounts_router
from backend.app.api.routes.findings import router as findings_router
from backend.app.api.routes.reports import router as reports_router
from backend.app.api.routes.scans import router as scans_router
from backend.app.core.config import settings


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
