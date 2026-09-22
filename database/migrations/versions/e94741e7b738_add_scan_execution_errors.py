"""add scan execution errors

Revision ID: e94741e7b738
Revises: aws_connection_001
Create Date: 2026-09-22 17:58:23.143573

"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "e94741e7b738"
down_revision: str | None = "aws_connection_001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_execution_errors",
        sa.Column(
            "id",
            sa.Integer(),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "service",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "error_type",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "error_code",
            sa.String(length=100),
            nullable=True,
        ),
        sa.Column(
            "message",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "ix_scan_execution_errors_scan_id",
        "scan_execution_errors",
        ["scan_id"],
    )

    op.create_index(
        "ix_scan_execution_errors_service",
        "scan_execution_errors",
        ["service"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_scan_execution_errors_service",
        table_name="scan_execution_errors",
    )
    op.drop_index(
        "ix_scan_execution_errors_scan_id",
        table_name="scan_execution_errors",
    )
    op.drop_table("scan_execution_errors")
