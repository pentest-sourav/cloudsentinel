"""align scan cloud-account foreign key with historical retention policy

Revision ID: b7c4d2e91f63
Revises: 94a267acb7bf
Create Date: 2026-10-01

"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "b7c4d2e91f63"
down_revision: str | None = "94a267acb7bf"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Scan history must survive deletion of a cloud-account configuration.
    # The application already clears cloud_account_id before deleting the
    # account; this DB constraint makes the retention policy authoritative
    # even if an account is deleted through another database path.
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for fk in inspector.get_foreign_keys("scans"):
        if (
            fk["constrained_columns"] == ["cloud_account_id"]
            and fk["referred_table"] == "cloud_accounts"
        ):
            constraint_name = fk["name"]
            if constraint_name:
                op.drop_constraint(
                    constraint_name,
                    "scans",
                    type_="foreignkey",
                )

                op.create_foreign_key(
                    constraint_name,
                    "scans",
                    "cloud_accounts",
                    ["cloud_account_id"],
                    ["id"],
                    ondelete="SET NULL",
                )
            break
    else:
        raise RuntimeError(
            "Could not find scans.cloud_account_id -> cloud_accounts.id "
            "foreign key"
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for fk in inspector.get_foreign_keys("scans"):
        if (
            fk["constrained_columns"] == ["cloud_account_id"]
            and fk["referred_table"] == "cloud_accounts"
        ):
            constraint_name = fk["name"]
            if constraint_name:
                op.drop_constraint(
                    constraint_name,
                    "scans",
                    type_="foreignkey",
                )

                op.create_foreign_key(
                    constraint_name,
                    "scans",
                    "cloud_accounts",
                    ["cloud_account_id"],
                    ["id"],
                    ondelete="CASCADE",
                )
            break
