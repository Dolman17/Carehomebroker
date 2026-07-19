"""seller analytics

Revision ID: a4e9c7b2d610
Revises: f6a28d91c4e7
Create Date: 2026-07-19
"""

from alembic import op
import sqlalchemy as sa


revision = "a4e9c7b2d610"
down_revision = "f6a28d91c4e7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "listing_analytics_event",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("listing_id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=30), nullable=False),
        sa.Column("visitor_hash", sa.String(length=64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["listing_id"], ["listing.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_listing_analytics_listing_event_time",
        "listing_analytics_event", ["listing_id", "event_type", "occurred_at"],
        unique=False,
    )
    for column in ("listing_id", "event_type", "occurred_at"):
        op.create_index(
            op.f(f"ix_listing_analytics_event_{column}"),
            "listing_analytics_event", [column], unique=False,
        )


def downgrade():
    op.drop_table("listing_analytics_event")
