"""add cloud account connection timestamps and scan execution state

Revision ID: 94a267acb7bf
Revises: e94741e7b738
"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "94a267acb7bf"
down_revision: str | None = "e94741e7b738"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing production rows must remain valid.  New columns that are
    # required by the ORM are therefore added nullable, backfilled, and only
    # then constrained where it is safe to do so.

    op.add_column(
        "cloud_accounts",
        sa.Column(
            "last_connection_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.add_column(
        "cloud_accounts",
        sa.Column(
            "last_connection_error",
            sa.String(length=4000),
            nullable=True,
        ),
    )

    op.add_column(
        "cloud_accounts",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE cloud_accounts
        SET updated_at = created_at
        WHERE updated_at IS NULL
        """
    )

    op.alter_column(
        "cloud_accounts",
        "updated_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )

    op.alter_column(
        "cloud_accounts",
        "status",
        existing_type=sa.VARCHAR(length=20),
        type_=sa.String(length=30),
        existing_nullable=False,
    )

    op.add_column(
        "scans",
        sa.Column(
            "attempt_count",
            sa.Integer(),
            nullable=True,
        ),
    )

    op.add_column(
        "scans",
        sa.Column(
            "max_attempts",
            sa.Integer(),
            nullable=True,
        ),
    )

    op.add_column(
        "scans",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE scans
        SET attempt_count = 0
        WHERE attempt_count IS NULL
        """
    )

    op.execute(
        """
        UPDATE scans
        SET max_attempts = 4
        WHERE max_attempts IS NULL
        """
    )

    op.execute(
        """
        UPDATE scans
        SET updated_at = COALESCE(completed_at, started_at, created_at)
        WHERE updated_at IS NULL
        """
    )

    op.alter_column(
        "scans",
        "attempt_count",
        existing_type=sa.Integer(),
        nullable=False,
    )

    op.alter_column(
        "scans",
        "max_attempts",
        existing_type=sa.Integer(),
        nullable=False,
    )

    op.alter_column(
        "scans",
        "updated_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )

    # IMPORTANT:
    # Historical scans created before cloud-account onboarding may have
    # cloud_account_id=NULL. They must remain readable for audit/history.
    # New scans are enforced at the service/API layer.
    #
    # Do NOT make scans.cloud_account_id NOT NULL here.

    # Alembic detected this as model/index noise. Preserve the existing
    # tenant uniqueness semantics and do not rewrite unrelated constraints.


def downgrade() -> None:
    op.drop_column("scans", "updated_at")
    op.drop_column("scans", "max_attempts")
    op.drop_column("scans", "attempt_count")

    op.alter_column(
        "cloud_accounts",
        "status",
        existing_type=sa.String(length=30),
        type_=sa.VARCHAR(length=20),
        existing_nullable=False,
    )

    op.drop_column("cloud_accounts", "updated_at")
    op.drop_column("cloud_accounts", "last_connection_error")
    op.drop_column("cloud_accounts", "last_connection_at")
