"""adviser marketplace

Revision ID: b7d4e2f9a831
Revises: a4e9c7b2d610
Create Date: 2026-07-19
"""

from alembic import op
import sqlalchemy as sa


revision = "b7d4e2f9a831"
down_revision = "a4e9c7b2d610"
branch_labels = None
depends_on = None


CATEGORIES = (
    ("business-valuation", "Business valuation", "Independent valuations and valuation reviews."),
    ("legal-transaction", "Legal & transaction", "Heads of terms, due diligence and transaction documents."),
    ("tax-accounting", "Tax & accounting", "Transaction tax, financial diligence and accounting support."),
    ("deal-finance", "Deal finance", "Acquisition finance, refinancing and funding advice."),
    ("due-diligence", "Due diligence", "Commercial, financial and operational diligence."),
    ("commercial-property", "Commercial property", "Property, lease, survey and real-estate advice."),
    ("regulatory-compliance", "Regulatory & compliance", "Licensing, regulatory and compliance support."),
)


def upgrade():
    with op.batch_alter_table("valuer_profiles") as batch:
        batch.add_column(sa.Column("verification_status", sa.String(20), nullable=False, server_default="unverified"))
        batch.add_column(sa.Column("availability_status", sa.String(20), nullable=False, server_default="available"))
        batch.add_column(sa.Column("next_available_date", sa.Date(), nullable=True))
        batch.add_column(sa.Column("remote_service", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch.add_column(sa.Column("verification_requested_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("verified_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("verified_by_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()))
        batch.create_foreign_key("fk_valuer_profiles_verified_by", "user", ["verified_by_id"], ["id"])
        batch.create_index("ix_valuer_profiles_verification_status", ["verification_status"])
        batch.create_index("ix_valuer_profiles_availability_status", ["availability_status"])

    op.create_table(
        "adviser_category",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("name"), sa.UniqueConstraint("slug"),
    )
    op.create_index("ix_adviser_category_slug", "adviser_category", ["slug"], unique=True)
    op.create_table(
        "adviser_service",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("profile_id", sa.Integer(), nullable=False),
        sa.Column("category_id", sa.Integer(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["category_id"], ["adviser_category.id"]),
        sa.ForeignKeyConstraint(["profile_id"], ["valuer_profiles.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("profile_id", "category_id", name="uq_adviser_service_category"),
    )
    op.create_index("ix_adviser_service_profile_id", "adviser_service", ["profile_id"])
    op.create_index("ix_adviser_service_category_id", "adviser_service", ["category_id"])
    op.create_table(
        "adviser_request",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("requester_id", sa.Integer(), nullable=False),
        sa.Column("adviser_id", sa.Integer(), nullable=False),
        sa.Column("category_id", sa.Integer(), nullable=False),
        sa.Column("listing_id", sa.Integer(), nullable=True),
        sa.Column("introduction_id", sa.Integer(), nullable=True),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("target_date", sa.Date(), nullable=True),
        sa.Column("budget_minor", sa.BigInteger(), nullable=True),
        sa.Column("currency", sa.String(3), nullable=False, server_default="GBP"),
        sa.Column("status", sa.String(20), nullable=False, server_default="requested"),
        sa.Column("declined_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("accepted_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["adviser_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["category_id"], ["adviser_category.id"]),
        sa.ForeignKeyConstraint(["introduction_id"], ["introductions.id"]),
        sa.ForeignKeyConstraint(["listing_id"], ["listing.id"]),
        sa.ForeignKeyConstraint(["requester_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("requester_id", "adviser_id", "category_id", "listing_id", "introduction_id", "status", "created_at"):
        op.create_index(f"ix_adviser_request_{column}", "adviser_request", [column])
    op.create_table(
        "adviser_quote",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.Integer(), nullable=False),
        sa.Column("adviser_id", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("fee_minor", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False, server_default="GBP"),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("terms", sa.Text(), nullable=True),
        sa.Column("valid_until", sa.Date(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="submitted"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("responded_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["adviser_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["request_id"], ["adviser_request.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id", "revision", name="uq_adviser_quote_revision"),
    )
    for column in ("request_id", "valid_until", "status"):
        op.create_index(f"ix_adviser_quote_{column}", "adviser_quote", [column])
    op.create_table(
        "adviser_review",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.Integer(), nullable=False),
        sa.Column("reviewer_id", sa.Integer(), nullable=False),
        sa.Column("adviser_id", sa.Integer(), nullable=False),
        sa.Column("rating", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(160), nullable=True),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["adviser_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["request_id"], ["adviser_request.id"]),
        sa.ForeignKeyConstraint(["reviewer_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("request_id", name="uq_adviser_review_request"),
    )
    for column in ("reviewer_id", "adviser_id", "created_at"):
        op.create_index(f"ix_adviser_review_{column}", "adviser_review", [column])

    category_table = sa.table(
        "adviser_category", sa.column("slug"), sa.column("name"),
        sa.column("description"), sa.column("sort_order")
    )
    op.bulk_insert(category_table, [
        {"slug": slug, "name": name, "description": description, "sort_order": index}
        for index, (slug, name, description) in enumerate(CATEGORIES)
    ])
    bind = op.get_bind()
    valuation_id = bind.execute(sa.text(
        "SELECT id FROM adviser_category WHERE slug = 'business-valuation'"
    )).scalar()
    profile_ids = [row[0] for row in bind.execute(sa.text("SELECT id FROM valuer_profiles"))]
    if valuation_id and profile_ids:
        service_table = sa.table(
            "adviser_service", sa.column("profile_id"), sa.column("category_id")
        )
        op.bulk_insert(service_table, [
            {"profile_id": profile_id, "category_id": valuation_id}
            for profile_id in profile_ids
        ])
        bind.execute(sa.text(
            "UPDATE valuer_profiles SET verification_status = 'pending', verification_requested_at = CURRENT_TIMESTAMP"
        ))


def downgrade():
    op.drop_table("adviser_review")
    op.drop_table("adviser_quote")
    op.drop_table("adviser_request")
    op.drop_table("adviser_service")
    op.drop_table("adviser_category")
    with op.batch_alter_table("valuer_profiles") as batch:
        batch.drop_index("ix_valuer_profiles_availability_status")
        batch.drop_index("ix_valuer_profiles_verification_status")
        batch.drop_constraint("fk_valuer_profiles_verified_by", type_="foreignkey")
        for column in (
            "updated_at", "verified_by_id", "verified_at", "verification_requested_at",
            "remote_service", "next_available_date", "availability_status", "verification_status",
        ):
            batch.drop_column(column)
