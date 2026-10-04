"""Expand scan status storage for warning lifecycle states.

The production scan lifecycle includes completed_with_warnings which is
23 characters long. The original VARCHAR(20) truncated the lifecycle state at
the database boundary and caused otherwise successful warning-bearing scans to
fail during finalization.
"""

from alembic import op
import sqlalchemy as sa


revision = "20261004130000"
down_revision = "20261003230000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "scans",
        "status",
        existing_type=sa.String(length=20),
        type_=sa.String(length=64),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "scans",
        "status",
        existing_type=sa.String(length=64),
        type_=sa.String(length=20),
        existing_nullable=False,
    )
