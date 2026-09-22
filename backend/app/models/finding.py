from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, JSON, Float, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "provider",
            "rule_id",
            "resource_type",
            "resource_id",
            name="uq_findings_scan_identity",
        ),
    )

    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    provider: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    resource_id: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    evidence: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    remediation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )

    compliance: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
