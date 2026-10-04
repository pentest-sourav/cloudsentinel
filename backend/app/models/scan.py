from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Historical scans created before cloud-account onboarding may not have
    # an account. New scans are enforced by the scan service/API.
    cloud_account_id: Mapped[int | None] = mapped_column(
        ForeignKey("cloud_accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    provider: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    # Keep lifecycle states comfortably bounded while allowing explicit
    # warning states such as ``completed_with_warnings``.
    status: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="pending",
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Durable execution accounting. Redis retry state protects the
    # queue; these fields protect the database-side scan lifecycle.
    attempt_count: Mapped[int] = mapped_column(
        nullable=False,
        default=0,
    )

    max_attempts: Mapped[int] = mapped_column(
        nullable=False,
        default=4,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    execution_errors: Mapped[list["ScanExecutionError"]] = relationship(
        "ScanExecutionError",
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ScanExecutionError.id",
    )
