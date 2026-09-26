from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from backend.app.api.routes.auth import router as auth_router
from backend.app.api.routes.cloud_accounts import router as cloud_accounts_router
from backend.app.api.routes.findings import router as findings_router
from backend.app.api.routes.reports import router as reports_router
from backend.app.api.routes.scans import router as scans_router


app = FastAPI(
    title="CloudSentinel",
    description="Multi-Cloud Security Posture & Compliance Auditor",
    version="0.1.0",
)


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
        "version": "0.1.0",
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
