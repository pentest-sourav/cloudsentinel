"""add durable alert policies and delivery idempotency

Revision ID: 20261003230000
Revises: 20261003220000
Create Date: 2026-10-03 23:00:00
"""

from typing import Sequence
from alembic import op
import sqlalchemy as sa

revision: str = "20261003230000"
down_revision: str | None = "20261003220000"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alert_policies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("endpoint_url", sa.String(2048), nullable=False),
        sa.Column("min_severity", sa.String(20), nullable=False, server_default="high"),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("secret", sa.String(512), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_alert_policies_tenant_name"),
    )
    op.create_index("ix_alert_policies_tenant_id", "alert_policies", ["tenant_id"])
    op.create_index("ix_alert_policies_enabled", "alert_policies", ["enabled"])

    op.create_table(
        "alert_deliveries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=False),
        sa.Column("event_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(1000), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_id"], ["alert_policies.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_id", "event_key", name="uq_alert_deliveries_policy_event"),
    )
    op.create_index("ix_alert_deliveries_tenant_id", "alert_deliveries", ["tenant_id"])
    op.create_index("ix_alert_deliveries_policy_id", "alert_deliveries", ["policy_id"])
    op.create_index("ix_alert_deliveries_status", "alert_deliveries", ["status"])


def downgrade() -> None:
    for name in ("ix_alert_deliveries_status","ix_alert_deliveries_policy_id","ix_alert_deliveries_tenant_id"):
        op.drop_index(name, table_name="alert_deliveries")
    op.drop_table("alert_deliveries")
    for name in ("ix_alert_policies_enabled","ix_alert_policies_tenant_id"):
        op.drop_index(name, table_name="alert_policies")
    op.drop_table("alert_policies")
