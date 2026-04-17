"""Add api key metadata.

Revision ID: 0003_api_keys_metadata
Revises: 0002_policies
Create Date: 2026-01-29 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "0003_api_keys_metadata"
down_revision = "0002_policies"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("api_keys", sa.Column("name", sa.String(length=200), nullable=True))
    op.add_column("api_keys", sa.Column("key_preview", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column("api_keys", "key_preview")
    op.drop_column("api_keys", "name")
