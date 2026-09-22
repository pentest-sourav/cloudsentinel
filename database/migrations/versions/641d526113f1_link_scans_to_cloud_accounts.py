"""link scans to cloud accounts

Revision ID: link_scans_account_001
Revises: ed87bc279b63
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "link_scans_account_001"
down_revision: Union[str, Sequence[str], None] = "ed87bc279b63"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "cloud_account_id",
            sa.Integer(),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_scans_cloud_account_id",
        "scans",
        ["cloud_account_id"],
        unique=False,
    )

    op.create_foreign_key(
        "fk_scans_cloud_account_id",
        "scans",
        "cloud_accounts",
        ["cloud_account_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_scans_cloud_account_id",
        "scans",
        type_="foreignkey",
    )

    op.drop_index(
        "ix_scans_cloud_account_id",
        table_name="scans",
    )

    op.drop_column(
        "scans",
        "cloud_account_id",
    )
