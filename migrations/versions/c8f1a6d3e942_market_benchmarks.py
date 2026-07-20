"""permissioned market benchmarks

Revision ID: c8f1a6d3e942
Revises: b7d4e2f9a831
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "c8f1a6d3e942"
down_revision = "b7d4e2f9a831"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "benchmark_consent",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("deal_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="granted"),
        sa.Column("granted_at", sa.DateTime()),
        sa.Column("revoked_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["deal_id"], ["deals.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("deal_id", "user_id", name="uq_benchmark_consent_party"),
    )
    for column in ("deal_id", "user_id", "status"):
        op.create_index(f"ix_benchmark_consent_{column}", "benchmark_consent", [column])
    op.create_table(
        "benchmark_record",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_deal_id", sa.Integer(), nullable=False),
        sa.Column("sector_id", sa.Integer(), nullable=False),
        sa.Column("region", sa.String(100)),
        sa.Column("completed_on", sa.Date(), nullable=False),
        sa.Column("price_minor", sa.BigInteger(), nullable=False),
        sa.Column("revenue_minor", sa.BigInteger()),
        sa.Column("ebitda_minor", sa.BigInteger()),
        sa.Column("currency", sa.String(3), nullable=False, server_default="GBP"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("published_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("published_by_id", sa.Integer(), nullable=False),
        sa.Column("withdrawn_at", sa.DateTime()),
        sa.ForeignKeyConstraint(["source_deal_id"], ["deals.id"]),
        sa.ForeignKeyConstraint(["sector_id"], ["sector.id"]),
        sa.ForeignKeyConstraint(["published_by_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("source_deal_id"),
    )
    for column in ("source_deal_id", "sector_id", "region", "completed_on", "currency", "is_active"):
        op.create_index(f"ix_benchmark_record_{column}", "benchmark_record", [column])
    op.create_table(
        "benchmark_report",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("listing_id", sa.Integer(), nullable=False),
        sa.Column("seller_id", sa.Integer(), nullable=False),
        sa.Column("sector_id", sa.Integer(), nullable=False),
        sa.Column("region", sa.String(100)),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("sample_size", sa.Integer(), nullable=False),
        sa.Column("input_revenue_minor", sa.BigInteger()),
        sa.Column("input_ebitda_minor", sa.BigInteger()),
        sa.Column("estimated_low_minor", sa.BigInteger(), nullable=False),
        sa.Column("estimated_mid_minor", sa.BigInteger(), nullable=False),
        sa.Column("estimated_high_minor", sa.BigInteger(), nullable=False),
        sa.Column("method", sa.String(50), nullable=False),
        sa.Column("median_revenue_multiple", sa.Float()),
        sa.Column("median_ebitda_multiple", sa.Float()),
        sa.Column("filters", sa.JSON(), nullable=False),
        sa.Column("generated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["listing_id"], ["listing.id"]),
        sa.ForeignKeyConstraint(["seller_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["sector_id"], ["sector.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("listing_id", "seller_id", "generated_at"):
        op.create_index(f"ix_benchmark_report_{column}", "benchmark_report", [column])


def downgrade():
    op.drop_table("benchmark_report")
    op.drop_table("benchmark_record")
    op.drop_table("benchmark_consent")
