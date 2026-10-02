from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base


class CloudAccount(Base):
    __tablename__ = "cloud_accounts"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    provider: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    external_account_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    role_arn: Mapped[str | None] = mapped_column(
        String(2048),
        nullable=True,
    )

    external_id: Mapped[str | None] = mapped_column(
        String(1024),
        nullable=True,
    )

    region: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    # New accounts are deliberately not scan-eligible until the
    # customer trust relationship has been verified.
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending_connection",
    )

    last_connection_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_connection_error: Mapped[str | None] = mapped_column(
        String(4000),
        nullable=True,
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
