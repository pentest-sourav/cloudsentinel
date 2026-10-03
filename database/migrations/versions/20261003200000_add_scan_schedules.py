"""add persistent scan schedules

Revision ID: 20261003200000
Revises: 20261003170000
Create Date: 2026-10-03 20:00:00
"""

from typing import Sequence
from alembic import op
import sqlalchemy as sa

revision: str = "20261003200000"
down_revision: str | None = "20261003170000"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("cloud_account_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["cloud_account_id"], ["cloud_accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_schedules_tenant_id", "scan_schedules", ["tenant_id"])
    op.create_index("ix_scan_schedules_cloud_account_id", "scan_schedules", ["cloud_account_id"])
    op.create_index("ix_scan_schedules_enabled", "scan_schedules", ["enabled"])
    op.create_index("ix_scan_schedules_next_run_at", "scan_schedules", ["next_run_at"])


def downgrade() -> None:
    for name in ("ix_scan_schedules_next_run_at", "ix_scan_schedules_enabled", "ix_scan_schedules_cloud_account_id", "ix_scan_schedules_tenant_id"):
        op.drop_index(name, table_name="scan_schedules")
    op.drop_table("scan_schedules")
