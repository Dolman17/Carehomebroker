"""staged data room

Revision ID: c94d20e71b63
Revises: aa54d3c128f7
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa


revision = "c94d20e71b63"
down_revision = "aa54d3c128f7"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "data_room_document",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("listing_id", sa.Integer(), nullable=False),
        sa.Column("uploaded_by_id", sa.Integer(), nullable=False),
        sa.Column("document_key", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("category", sa.String(length=30), nullable=False),
        sa.Column("disclosure_stage", sa.String(length=30), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("mime_type", sa.String(length=100), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("archived_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["listing_id"], ["listing.id"]),
        sa.ForeignKeyConstraint(["uploaded_by_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("document_key", "version", name="uq_data_room_document_version"),
    )
    for column in ("listing_id", "document_key", "category", "disclosure_stage", "is_current"):
        op.create_index(op.f(f"ix_data_room_document_{column}"), "data_room_document", [column], unique=False)

    op.create_table(
        "data_room_access",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("introduction_id", sa.Integer(), nullable=False),
        sa.Column("disclosure_stage", sa.String(length=30), nullable=False, server_default="teaser"),
        sa.Column("granted_by_id", sa.Integer(), nullable=False),
        sa.Column("granted_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["granted_by_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["introduction_id"], ["introductions.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("introduction_id"),
    )


def downgrade():
    op.drop_table("data_room_access")
    for column in ("is_current", "disclosure_stage", "category", "document_key", "listing_id"):
        op.drop_index(op.f(f"ix_data_room_document_{column}"), table_name="data_room_document")
    op.drop_table("data_room_document")
