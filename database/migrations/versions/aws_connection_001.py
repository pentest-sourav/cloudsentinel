"""add AWS role connection fields to cloud accounts

Revision ID: aws_connection_001
Revises: link_scans_tenant_001
Create Date: 2026-09-22
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "aws_connection_001"
down_revision: str | None = "link_scans_tenant_001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "cloud_accounts",
        sa.Column(
            "role_arn",
            sa.String(length=2048),
            nullable=True,
        ),
    )

    op.add_column(
        "cloud_accounts",
        sa.Column(
            "external_id",
            sa.String(length=1024),
            nullable=True,
        ),
    )

    op.add_column(
        "cloud_accounts",
        sa.Column(
            "region",
            sa.String(length=100),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("cloud_accounts", "region")
    op.drop_column("cloud_accounts", "external_id")
    op.drop_column("cloud_accounts", "role_arn")
