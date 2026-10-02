"""merge scan account and finding region migration heads

Revision ID: b62e73b475fd
Revises: b7c4d2e91f63, 20261002145500
Create Date: 2026-10-02 09:38:56.914234

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b62e73b475fd'
down_revision: Union[str, Sequence[str], None] = ('b7c4d2e91f63', '20261002145500')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
