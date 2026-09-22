"""add finding identity constraint

Revision ID: finding_identity_001
Revises: 2a3a1147608e
Create Date: 2026-09-22

"""
from typing import Sequence, Union

from alembic import op


revision: str = "finding_identity_001"
down_revision: Union[str, Sequence[str], None] = "2a3a1147608e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add database-level uniqueness for logical scan findings."""
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


def downgrade() -> None:
    """Remove database-level uniqueness for logical scan findings."""
    op.drop_constraint(
        "uq_findings_scan_identity",
        "findings",
        type_="unique",
    )
