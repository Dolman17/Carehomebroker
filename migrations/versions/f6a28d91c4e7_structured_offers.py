"""structured offers and negotiation

Revision ID: f6a28d91c4e7
Revises: e51f02c8ad74
Create Date: 2026-07-19
"""

from alembic import op
import sqlalchemy as sa


revision = "f6a28d91c4e7"
down_revision = "e51f02c8ad74"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "structured_offer",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("introduction_id", sa.Integer(), nullable=False),
        sa.Column("parent_offer_id", sa.Integer(), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("recipient_id", sa.Integer(), nullable=False),
        sa.Column("amount_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, server_default="GBP"),
        sa.Column("terms", sa.Text(), nullable=True),
        sa.Column("conditions", sa.Text(), nullable=True),
        sa.Column("expires_on", sa.Date(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="submitted"),
        sa.Column("responded_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["created_by_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["introduction_id"], ["introductions.id"]),
        sa.ForeignKeyConstraint(["parent_offer_id"], ["structured_offer.id"]),
        sa.ForeignKeyConstraint(["recipient_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("introduction_id", "sequence", name="uq_structured_offer_sequence"),
    )
    for column in (
        "introduction_id", "parent_offer_id", "recipient_id", "expires_on", "status", "created_at"
    ):
        op.create_index(
            op.f(f"ix_structured_offer_{column}"), "structured_offer", [column], unique=False
        )


def downgrade():
    op.drop_table("structured_offer")
