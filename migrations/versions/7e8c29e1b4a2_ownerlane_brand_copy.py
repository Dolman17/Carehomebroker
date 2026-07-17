"""refresh legacy default copy for the Ownerlane brand

Revision ID: 7e8c29e1b4a2
Revises: c78299663cf2
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa


revision = "7e8c29e1b4a2"
down_revision = "c78299663cf2"
branch_labels = None
depends_on = None


COPY_UPDATES = (
    ("KAIJO", "OWNERLANE"),
    ("North Consulting", "Business Marketplace"),
    ("A confidential marketplace for buying & selling businesses.", "Where businesses find their next owner."),
    (
        "Built for operators, investors and owners who want a discreet, structured way to explore sales and acquisitions – without going straight to a public agent process.",
        "A modern, confidential marketplace for owners, operators and investors buying and selling established businesses.",
    ),
    ("Innovating", "Discover"),
    ("Expanding", "Meet"),
    ("Elevating", "Move"),
    (
        "Kaijo North Consulting brings together sector insight, commercial discipline and a practical route to market for owners and buyers.",
        "Ownerlane brings serious buyers and business owners together through a clear, controlled route to the right conversation.",
    ),
    ("What is the Private Deal Portal platform?", "A better lane to your next deal"),
    (
        "A controlled way to explore a sale while protecting residents, staff and reputation.",
        "A controlled way to explore a sale while protecting your people, operations and reputation.",
    ),
    ("Create confidential listings for one or multiple homes.", "Create confidential listings for one or multiple businesses."),
    (
        "Option to work with Kaijo North Consulting for deeper advisory support.",
        "Request supported introductions when you are ready to move forward.",
    ),
    ("Available Care Homes", "Business opportunities"),
    ("Confidential care home opportunity", "Confidential business opportunity"),
    (
        "The Care Home Broker platform is built for three groups: buyers, sellers, and valuers. Start by choosing your role, then pick the access level that fits how active you want to be in the marketplace.",
        "The Ownerlane platform is built for three groups: buyers, sellers, and valuers. Start by choosing your role, then pick the access level that fits how active you want to be in the marketplace.",
    ),
    ("For operators, groups and investors looking to acquire care homes.", "For operators, groups and investors looking to acquire established businesses."),
    ("Align with a specialist social care advisory brand.", "Build visibility across a modern, multi-sector marketplace."),
)


def _replace_copy(replacements):
    connection = op.get_bind()
    statement = sa.text(
        "UPDATE page_content SET content = :new_content WHERE content = :old_content"
    )
    for old_content, new_content in replacements:
        connection.execute(
            statement,
            {"old_content": old_content, "new_content": new_content},
        )


def upgrade():
    _replace_copy(COPY_UPDATES)


def downgrade():
    _replace_copy((new, old) for old, new in reversed(COPY_UPDATES))
