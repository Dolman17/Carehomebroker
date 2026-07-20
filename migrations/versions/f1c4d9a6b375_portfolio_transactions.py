"""portfolio and multi-listing transactions

Revision ID: f1c4d9a6b375
Revises: e0b3c8f5a264
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "f1c4d9a6b375"
down_revision = "e0b3c8f5a264"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "portfolio",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("seller_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("team_id", sa.Integer(), sa.ForeignKey("team.id")),
        sa.Column("portfolio_code", sa.String(20), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("sale_mode", sa.String(20), nullable=False, server_default="whole"),
        sa.Column("asking_price_minor", sa.BigInteger()),
        sa.Column("currency", sa.String(3), nullable=False, server_default="GBP"),
        sa.Column("is_confidential", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    for column in ("seller_id", "team_id", "sale_mode", "status"):
        op.create_index(f"ix_portfolio_{column}", "portfolio", [column])
    op.create_index("ix_portfolio_portfolio_code", "portfolio", ["portfolio_code"], unique=True)
    op.create_table(
        "portfolio_lot",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("portfolio_id", sa.Integer(), sa.ForeignKey("portfolio.id"), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("asking_price_minor", sa.BigInteger()),
        sa.Column("currency", sa.String(3), nullable=False, server_default="GBP"),
        sa.Column("is_available", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_portfolio_lot_portfolio_id", "portfolio_lot", ["portfolio_id"])
    op.create_index("ix_portfolio_lot_is_available", "portfolio_lot", ["is_available"])
    op.create_table(
        "portfolio_lot_listing",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("portfolio_id", sa.Integer(), sa.ForeignKey("portfolio.id"), nullable=False),
        sa.Column("lot_id", sa.Integer(), sa.ForeignKey("portfolio_lot.id"), nullable=False),
        sa.Column("listing_id", sa.Integer(), sa.ForeignKey("listing.id"), nullable=False),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("portfolio_id", "listing_id", name="uq_portfolio_listing"),
    )
    for column in ("portfolio_id", "lot_id", "listing_id"):
        op.create_index(f"ix_portfolio_lot_listing_{column}", "portfolio_lot_listing", [column])
    op.create_table(
        "portfolio_enquiry",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("portfolio_id", sa.Integer(), sa.ForeignKey("portfolio.id"), nullable=False),
        sa.Column("lot_id", sa.Integer(), sa.ForeignKey("portfolio_lot.id")),
        sa.Column("buyer_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("nda_accepted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(20), nullable=False, server_default="new"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    for column in ("portfolio_id", "lot_id", "buyer_id", "status"):
        op.create_index(f"ix_portfolio_enquiry_{column}", "portfolio_enquiry", [column])


def downgrade():
    op.drop_table("portfolio_enquiry")
    op.drop_table("portfolio_lot_listing")
    op.drop_table("portfolio_lot")
    op.drop_table("portfolio")
