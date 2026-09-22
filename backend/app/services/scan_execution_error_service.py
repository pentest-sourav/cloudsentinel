from collections.abc import Iterable

from sqlalchemy.orm import Session

from backend.app.models.scan_execution_error import ScanExecutionError


def _normalise_message(message: str) -> str:
    return message[:10000]


def persist_execution_errors(
    db: Session,
    scan_id: int,
    errors: Iterable,
) -> list[ScanExecutionError]:
    persisted: list[ScanExecutionError] = []

    for error in errors:
        execution_error = ScanExecutionError(
            scan_id=scan_id,
            service=error.service,
            error_type=error.error_type,
            error_code=error.error_code,
            message=_normalise_message(error.message),
        )
        db.add(execution_error)
        persisted.append(execution_error)

    if persisted:
        db.commit()

        for error in persisted:
            db.refresh(error)

    return persisted


def get_execution_errors(
    db: Session,
    scan_id: int,
) -> list[ScanExecutionError]:
    return (
        db.query(ScanExecutionError)
        .filter(ScanExecutionError.scan_id == scan_id)
        .order_by(ScanExecutionError.id.asc())
        .all()
    )


def clear_execution_errors(
    db: Session,
    scan_id: int,
) -> None:
    db.query(ScanExecutionError).filter(
        ScanExecutionError.scan_id == scan_id
    ).delete(synchronize_session=False)

    db.commit()
