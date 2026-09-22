"""add tenant and user identity

Revision ID: ed87bc279b63
Revises: finding_identity_001
Create Date: 2026-09-22 12:53:30.056826

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "ed87bc279b63"
down_revision: Union[str, Sequence[str], None] = "finding_identity_001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


BOOTSTRAP_TENANT_SLUG = "cloudsentinel-bootstrap"
BOOTSTRAP_TENANT_NAME = "CloudSentinel Bootstrap Tenant"


def upgrade() -> None:
    """Create tenant/user identity and backfill existing cloud accounts."""

    op.create_table(
        "tenants",
        sa.Column(
            "id",
            sa.Integer(),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "name",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "slug",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="active",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )

    op.create_index(
        "ix_tenants_slug",
        "tenants",
        ["slug"],
        unique=False,
    )

    op.create_table(
        "users",
        sa.Column(
            "id",
            sa.Integer(),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "email",
            sa.String(length=320),
            nullable=False,
        ),
        sa.Column(
            "password_hash",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "full_name",
            sa.String(length=150),
            nullable=False,
        ),
        sa.Column(
            "role",
            sa.String(length=30),
            nullable=False,
            server_default="viewer",
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "email",
            name="uq_users_tenant_email",
        ),
    )

    op.create_index(
        "ix_users_tenant_id",
        "users",
        ["tenant_id"],
        unique=False,
    )

    # Existing cloud accounts must belong to a tenant before the new
    # ownership column can become NOT NULL.
    connection = op.get_bind()

    connection.execute(
        sa.text(
            """
            INSERT INTO tenants (name, slug, status)
            VALUES (:name, :slug, 'active')
            """
        ),
        {
            "name": BOOTSTRAP_TENANT_NAME,
            "slug": BOOTSTRAP_TENANT_SLUG,
        },
    )

    tenant_id = connection.execute(
        sa.text(
            """
            SELECT id
            FROM tenants
            WHERE slug = :slug
            """
        ),
        {"slug": BOOTSTRAP_TENANT_SLUG},
    ).scalar_one()

    op.add_column(
        "cloud_accounts",
        sa.Column(
            "tenant_id",
            sa.Integer(),
            nullable=True,
        ),
    )

    connection.execute(
        sa.text(
            """
            UPDATE cloud_accounts
            SET tenant_id = :tenant_id
            WHERE tenant_id IS NULL
            """
        ),
        {"tenant_id": tenant_id},
    )

    op.alter_column(
        "cloud_accounts",
        "tenant_id",
        existing_type=sa.Integer(),
        nullable=False,
    )

    op.create_foreign_key(
        "fk_cloud_accounts_tenant_id",
        "cloud_accounts",
        "tenants",
        ["tenant_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.create_index(
        "ix_cloud_accounts_tenant_id",
        "cloud_accounts",
        ["tenant_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove tenant/user identity structures."""

    op.drop_index(
        "ix_cloud_accounts_tenant_id",
        table_name="cloud_accounts",
    )

    op.drop_constraint(
        "fk_cloud_accounts_tenant_id",
        "cloud_accounts",
        type_="foreignkey",
    )

    op.drop_column(
        "cloud_accounts",
        "tenant_id",
    )

    op.drop_index(
        "ix_users_tenant_id",
        table_name="users",
    )

    op.drop_table("users")

    op.drop_index(
        "ix_tenants_slug",
        table_name="tenants",
    )

    op.drop_table("tenants")
