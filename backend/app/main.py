from fastapi import FastAPI

from backend.app.api.routes.cloud_accounts import router as cloud_accounts_router
from backend.app.api.routes.scans import router as scans_router
from backend.app.api.routes.findings import router as findings_router


app = FastAPI(
    title="CloudSentinel",
    description="Multi-Cloud Security Posture & Compliance Auditor",
    version="0.1.0",
)


app.include_router(cloud_accounts_router)
app.include_router(scans_router)
app.include_router(findings_router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "CloudSentinel",
        "version": "0.1.0",
    }
