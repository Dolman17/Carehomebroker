"""add persistent buyer discovery tools

Revision ID: a91c47de20f8
Revises: 7e8c29e1b4a2
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa


revision = "a91c47de20f8"
down_revision = "7e8c29e1b4a2"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "saved_search",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("buyer_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("search_term", sa.String(length=120), nullable=True),
        sa.Column("region", sa.String(length=100), nullable=True),
        sa.Column("care_type", sa.String(length=100), nullable=True),
        sa.Column("email_alerts", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["buyer_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("buyer_id", "name", name="uq_saved_search_buyer_name"),
    )
    op.create_index(
        op.f("ix_saved_search_buyer_id"),
        "saved_search",
        ["buyer_id"],
        unique=False,
    )

    op.create_table(
        "shortlist_item",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("buyer_id", sa.Integer(), nullable=False),
        sa.Column("listing_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["buyer_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["listing_id"], ["listing.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "buyer_id", "listing_id", name="uq_shortlist_item_buyer_listing"
        ),
    )
    op.create_index(
        op.f("ix_shortlist_item_buyer_id"),
        "shortlist_item",
        ["buyer_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_shortlist_item_listing_id"),
        "shortlist_item",
        ["listing_id"],
        unique=False,
    )


def downgrade():
    op.drop_index(op.f("ix_shortlist_item_listing_id"), table_name="shortlist_item")
    op.drop_index(op.f("ix_shortlist_item_buyer_id"), table_name="shortlist_item")
    op.drop_table("shortlist_item")
    op.drop_index(op.f("ix_saved_search_buyer_id"), table_name="saved_search")
    op.drop_table("saved_search")
