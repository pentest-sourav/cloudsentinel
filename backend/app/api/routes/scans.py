from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.services.aws_scan_service import run_aws_scan
from backend.app.services.scan_runner import ScanRunner
from backend.app.services.scan_service import create_scan

router = APIRouter(
    prefix="/api/v1/scans",
    tags=["Scans"],
)


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_new_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
):
    scan = create_scan(
        db=db,
        provider=scan_data.provider,
    )

    if scan_data.provider == "aws":
        findings = run_aws_scan()
    else:
        findings = []

    runner = ScanRunner(db=db)

    return runner.run(
        scan=scan,
        findings=findings,
    )
