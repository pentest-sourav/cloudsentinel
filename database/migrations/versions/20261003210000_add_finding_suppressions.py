"""add persistent finding suppressions

Revision ID: 20261003210000
Revises: 20261003200000
Create Date: 2026-10-03 21:00:00
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261003210000"
down_revision: str | None = "20261003200000"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_suppressions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("cloud_account_id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["cloud_account_id"], ["cloud_accounts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "cloud_account_id", "fingerprint", name="uq_finding_suppressions_scope"),
    )
    op.create_index("ix_finding_suppressions_tenant_id", "finding_suppressions", ["tenant_id"])
    op.create_index("ix_finding_suppressions_cloud_account_id", "finding_suppressions", ["cloud_account_id"])
    op.create_index("ix_finding_suppressions_fingerprint", "finding_suppressions", ["fingerprint"])
    op.create_index("ix_finding_suppressions_expires_at", "finding_suppressions", ["expires_at"])
    op.create_index("ix_finding_suppressions_created_by_user_id", "finding_suppressions", ["created_by_user_id"])


def downgrade() -> None:
    for name in (
        "ix_finding_suppressions_created_by_user_id",
        "ix_finding_suppressions_expires_at",
        "ix_finding_suppressions_fingerprint",
        "ix_finding_suppressions_cloud_account_id",
        "ix_finding_suppressions_tenant_id",
    ):
        op.drop_index(name, table_name="finding_suppressions")
    op.drop_table("finding_suppressions")
