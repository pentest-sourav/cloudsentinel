"""add SaaS audit events

Revision ID: 20261003170000
Revises: b62e73b475fd
Create Date: 2026-10-03 17:00:00
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261003170000"
down_revision: str | None = "b62e73b475fd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("resource_type", sa.String(length=50), nullable=True),
        sa.Column("resource_id", sa.String(length=255), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    for name, column in (
        ("ix_audit_events_tenant_id", "tenant_id"),
        ("ix_audit_events_user_id", "user_id"),
        ("ix_audit_events_action", "action"),
        ("ix_audit_events_created_at", "created_at"),
        ("ix_audit_events_request_id", "request_id"),
    ):
        op.create_index(
            name,
            "audit_events",
            [column],
            unique=False,
        )


def downgrade() -> None:
    for name in (
        "ix_audit_events_request_id",
        "ix_audit_events_created_at",
        "ix_audit_events_action",
        "ix_audit_events_user_id",
        "ix_audit_events_tenant_id",
    ):
        op.drop_index(name, table_name="audit_events")

    op.drop_table("audit_events")
