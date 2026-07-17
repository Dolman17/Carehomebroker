"""normalise sectors and listing money

Revision ID: b4d29f6a13c0
Revises: a91c47de20f8
Create Date: 2026-07-17
"""

import re
from decimal import Decimal, InvalidOperation

from alembic import op
import sqlalchemy as sa


revision = "b4d29f6a13c0"
down_revision = "a91c47de20f8"
branch_labels = None
depends_on = None


SECTORS = (
    ("healthcare-social-care", "Healthcare & Social Care", [
        {"key": "unit_count", "label": "Beds / registered places", "type": "integer"},
        {"key": "capacity_utilisation", "label": "Occupancy / utilisation (%)", "type": "percent"},
        {"key": "regulatory_rating", "label": "Regulatory rating", "type": "text"},
    ]),
    ("hospitality-leisure", "Hospitality & Leisure", [
        {"key": "unit_count", "label": "Rooms / trading units", "type": "integer"},
        {"key": "capacity_utilisation", "label": "Occupancy / utilisation (%)", "type": "percent"},
        {"key": "location_count", "label": "Number of locations", "type": "integer"},
    ]),
    ("professional-services", "Professional Services", [
        {"key": "employee_count", "label": "Employees", "type": "integer"},
        {"key": "location_count", "label": "Number of offices", "type": "integer"},
        {"key": "recurring_revenue_percent", "label": "Recurring revenue (%)", "type": "percent"},
    ]),
    ("retail-ecommerce", "Retail & E-commerce", []),
    ("technology-software", "Technology & Software", []),
    ("manufacturing", "Manufacturing", []),
    ("construction-property", "Construction & Property", []),
    ("recruitment", "Recruitment", []),
    ("other", "Other", []),
)


def _minor_units(value):
    text = (value or "").strip().lower().replace(",", "").replace("£", "")
    if not text or any(token in text for token in ("request", "<", ">", "+", "–", "-")):
        return None
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([km]?)\s*", text)
    if not match:
        return None
    try:
        amount = Decimal(match.group(1))
    except InvalidOperation:
        return None
    multiplier = {"": 1, "k": 1_000, "m": 1_000_000}[match.group(2)]
    return int(amount * multiplier * 100)


def _slug(value):
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:100] or "other"


def upgrade():
    op.create_table(
        "sector",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("attribute_schema", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("slug"),
    )
    op.create_index(op.f("ix_sector_slug"), "sector", ["slug"], unique=True)

    with op.batch_alter_table("listing") as batch_op:
        batch_op.add_column(sa.Column("sector_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("attributes", sa.JSON(), nullable=False, server_default="{}"))
        batch_op.add_column(sa.Column("asking_price_minor", sa.BigInteger(), nullable=True))
        batch_op.add_column(sa.Column("revenue_minor", sa.BigInteger(), nullable=True))
        batch_op.add_column(sa.Column("ebitda_minor", sa.BigInteger(), nullable=True))
        batch_op.add_column(sa.Column("currency", sa.String(length=3), nullable=False, server_default="GBP"))
        batch_op.create_foreign_key("fk_listing_sector_id", "sector", ["sector_id"], ["id"])
        batch_op.create_index(op.f("ix_listing_sector_id"), ["sector_id"], unique=False)

    connection = op.get_bind()
    sector_table = sa.table(
        "sector",
        sa.column("id", sa.Integer()),
        sa.column("slug", sa.String()),
        sa.column("name", sa.String()),
        sa.column("attribute_schema", sa.JSON()),
        sa.column("is_active", sa.Boolean()),
        sa.column("sort_order", sa.Integer()),
    )
    listing_table = sa.table(
        "listing",
        sa.column("id", sa.Integer()),
        sa.column("sector_id", sa.Integer()),
        sa.column("attributes", sa.JSON()),
        sa.column("asking_price_minor", sa.BigInteger()),
        sa.column("revenue_minor", sa.BigInteger()),
        sa.column("ebitda_minor", sa.BigInteger()),
        sa.column("currency", sa.String()),
    )
    for order, (slug, name, schema) in enumerate(SECTORS):
        connection.execute(
            sector_table.insert().values(
                slug=slug,
                name=name,
                attribute_schema=schema,
                is_active=True,
                sort_order=order,
            )
        )
    sector_ids = dict(connection.execute(sa.text("SELECT name, id FROM sector")).all())

    generic_names = {name.lower(): name for _, name, _ in SECTORS}
    care_markers = ("care", "residential", "nursing", "dementia", "supported living")
    rows = connection.execute(
        sa.text(
            "SELECT id, care_type, beds, occupancy_percent, cqc_rating, "
            "guide_price_band, revenue_band, ebitda_band FROM listing"
        )
    ).mappings()
    for row in rows:
        legacy = (row["care_type"] or "").strip()
        lower = legacy.lower()
        if lower in generic_names:
            sector_name = generic_names[lower]
        elif any(marker in lower for marker in care_markers):
            sector_name = "Healthcare & Social Care"
        elif legacy:
            sector_name = legacy
        else:
            sector_name = "Other"

        if sector_name not in sector_ids:
            slug = _slug(sector_name)
            suffix = 2
            existing_slugs = {item[0] for item in connection.execute(sa.text("SELECT slug FROM sector")).all()}
            base_slug = slug
            while slug in existing_slugs:
                slug = f"{base_slug[:95]}-{suffix}"
                suffix += 1
            connection.execute(
                sector_table.insert().values(
                    slug=slug,
                    name=sector_name,
                    attribute_schema=[],
                    is_active=True,
                    sort_order=99,
                )
            )
            sector_ids[sector_name] = connection.execute(
                sa.select(sector_table.c.id).where(sector_table.c.name == sector_name)
            ).scalar_one()

        attributes = {}
        if sector_name == "Healthcare & Social Care":
            if row["beds"] is not None:
                attributes["unit_count"] = row["beds"]
            if row["occupancy_percent"] is not None:
                attributes["capacity_utilisation"] = row["occupancy_percent"]
            if row["cqc_rating"]:
                attributes["regulatory_rating"] = row["cqc_rating"]

        connection.execute(
            listing_table.update().where(listing_table.c.id == row["id"]).values(
                sector_id=sector_ids[sector_name],
                attributes=attributes,
                asking_price_minor=_minor_units(row["guide_price_band"]),
                revenue_minor=_minor_units(row["revenue_band"]),
                ebitda_minor=_minor_units(row["ebitda_band"]),
                currency="GBP",
            )
        )


def downgrade():
    with op.batch_alter_table("listing") as batch_op:
        batch_op.drop_index(op.f("ix_listing_sector_id"))
        batch_op.drop_constraint("fk_listing_sector_id", type_="foreignkey")
        batch_op.drop_column("currency")
        batch_op.drop_column("ebitda_minor")
        batch_op.drop_column("revenue_minor")
        batch_op.drop_column("asking_price_minor")
        batch_op.drop_column("attributes")
        batch_op.drop_column("sector_id")
    op.drop_index(op.f("ix_sector_slug"), table_name="sector")
    op.drop_table("sector")
