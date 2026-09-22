from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base

if TYPE_CHECKING:
    from backend.app.models.scan import Scan


class ScanExecutionError(Base):
    __tablename__ = "scan_execution_errors"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    service: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    error_type: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    error_code: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="execution_errors",
    )
