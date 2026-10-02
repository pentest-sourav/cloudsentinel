"""add region to findings and scan execution errors

Revision ID: 20261002145500
Revises: 94a267acb7bf
Create Date: 2026-10-02
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20261002145500"
down_revision: str | None = "94a267acb7bf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Findings previously had no region dimension. Existing rows are
    # preserved with an explicit legacy value so the new identity remains
    # deterministic and the column can safely become NOT NULL.
    op.add_column(
        "findings",
        sa.Column(
            "region",
            sa.String(length=100),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE findings
        SET region = 'unknown'
        WHERE region IS NULL
        """
    )

    op.alter_column(
        "findings",
        "region",
        existing_type=sa.String(length=100),
        nullable=False,
    )

    # Replace the previous identity constraint with a region-aware identity.
    op.drop_constraint(
        "uq_findings_scan_identity",
        "findings",
        type_="unique",
    )

    op.create_unique_constraint(
        "uq_findings_scan_identity",
        "findings",
        [
            "scan_id",
            "provider",
            "region",
            "rule_id",
            "resource_type",
            "resource_id",
        ],
    )

    op.create_index(
        "ix_findings_region",
        "findings",
        ["region"],
        unique=False,
    )

    op.add_column(
        "scan_execution_errors",
        sa.Column(
            "region",
            sa.String(length=100),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE scan_execution_errors
        SET region = 'unknown'
        WHERE region IS NULL
        """
    )

    op.alter_column(
        "scan_execution_errors",
        "region",
        existing_type=sa.String(length=100),
        nullable=False,
    )

    op.create_index(
        "ix_scan_execution_errors_region",
        "scan_execution_errors",
        ["region"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_scan_execution_errors_region",
        table_name="scan_execution_errors",
    )

    op.drop_column(
        "scan_execution_errors",
        "region",
    )

    op.drop_index(
        "ix_findings_region",
        table_name="findings",
    )

    op.drop_constraint(
        "uq_findings_scan_identity",
        "findings",
        type_="unique",
    )

    op.create_unique_constraint(
        "uq_findings_scan_identity",
        "findings",
        [
            "scan_id",
            "provider",
            "rule_id",
            "resource_type",
            "resource_id",
        ],
    )

    op.drop_column(
        "findings",
        "region",
    )
