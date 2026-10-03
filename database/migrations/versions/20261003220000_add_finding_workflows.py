"""add persistent finding workflow state

Revision ID: 20261003220000
Revises: 20261003210000
Create Date: 2026-10-03 22:00:00
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261003220000"
down_revision: str | None = "20261003210000"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_workflows",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("cloud_account_id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="open"),
        sa.Column("assignee_user_id", sa.Integer(), nullable=True),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["cloud_account_id"], ["cloud_accounts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assignee_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["updated_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "cloud_account_id", "fingerprint", name="uq_finding_workflows_scope"),
    )
    for name, column in (
        ("ix_finding_workflows_tenant_id", "tenant_id"),
        ("ix_finding_workflows_cloud_account_id", "cloud_account_id"),
        ("ix_finding_workflows_fingerprint", "fingerprint"),
        ("ix_finding_workflows_status", "status"),
        ("ix_finding_workflows_assignee_user_id", "assignee_user_id"),
        ("ix_finding_workflows_due_at", "due_at"),
    ):
        op.create_index(name, "finding_workflows", [column])


def downgrade() -> None:
    for name in (
        "ix_finding_workflows_due_at",
        "ix_finding_workflows_assignee_user_id",
        "ix_finding_workflows_status",
        "ix_finding_workflows_fingerprint",
        "ix_finding_workflows_cloud_account_id",
        "ix_finding_workflows_tenant_id",
    ):
        op.drop_index(name, table_name="finding_workflows")
    op.drop_table("finding_workflows")
