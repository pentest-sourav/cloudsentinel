"""link scans to tenant

Revision ID: link_scans_tenant_001
Revises: link_scans_account_001
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "link_scans_tenant_001"
down_revision: str | None = "link_scans_account_001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("tenant_id", sa.Integer(), nullable=True),
    )

    op.create_index(
        "ix_scans_tenant_id",
        "scans",
        ["tenant_id"],
        unique=False,
    )

    op.create_foreign_key(
        "fk_scans_tenant_id",
        "scans",
        "tenants",
        ["tenant_id"],
        ["id"],
        ondelete="CASCADE",
    )

    # Account-linked scans inherit the CloudAccount tenant.
    op.execute(
        sa.text(
            """
            UPDATE scans
            SET tenant_id = cloud_accounts.tenant_id
            FROM cloud_accounts
            WHERE scans.cloud_account_id = cloud_accounts.id
              AND scans.tenant_id IS NULL
            """
        )
    )

    # Account-less legacy scans belong to the bootstrap tenant.
    # Existing production data was verified before this migration.
    op.execute(
        sa.text(
            """
            UPDATE scans
            SET tenant_id = 1
            WHERE tenant_id IS NULL
            """
        )
    )

    op.alter_column(
        "scans",
        "tenant_id",
        existing_type=sa.Integer(),
        nullable=False,
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_scans_tenant_id",
        "scans",
        type_="foreignkey",
    )

    op.drop_index(
        "ix_scans_tenant_id",
        table_name="scans",
    )

    op.drop_column("scans", "tenant_id")
