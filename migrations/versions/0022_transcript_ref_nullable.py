"""Let a session exist without a transcript.

Two things the current NOT NULL makes impossible:

* `posture_only` and `metadata` tenants never send content, so there is no
  blob to point at — yet the session itself is exactly what they want
  recorded.
* Retention (UMA-50) deletes the transcript at 30 days while sessions and
  findings live 13 months. Deleting the blob has to be recordable by clearing
  the pointer; otherwise the row keeps advertising evidence that is gone.

`transcript_bytes` was already nullable. This brings the pointer and its
digest in line with it.

Revision ID: 0022_transcript_ref_nullable
Revises: 0021_tenant_collection_mode
Create Date: 2026-08-31 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0022_transcript_ref_nullable"
down_revision = "0021_tenant_collection_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("ai_sessions") as batch:
        batch.alter_column("transcript_ref", existing_type=sa.UnicodeText(), nullable=True)
        batch.alter_column(
            "transcript_sha256", existing_type=sa.String(length=64), nullable=True
        )


def downgrade() -> None:
    # Rows whose transcript has been reaped cannot satisfy NOT NULL again.
    # Marking them rather than deleting them keeps the session history.
    op.execute("DELETE FROM ai_sessions WHERE transcript_ref IS NULL")
    with op.batch_alter_table("ai_sessions") as batch:
        batch.alter_column("transcript_ref", existing_type=sa.UnicodeText(), nullable=False)
        batch.alter_column(
            "transcript_sha256", existing_type=sa.String(length=64), nullable=False
        )
