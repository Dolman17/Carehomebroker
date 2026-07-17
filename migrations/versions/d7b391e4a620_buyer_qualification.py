"""buyer qualification

Revision ID: d7b391e4a620
Revises: c94d20e71b63
Create Date: 2026-07-17
"""

from alembic import op
import sqlalchemy as sa


revision = "d7b391e4a620"
down_revision = "c94d20e71b63"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "buyer_qualification",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("legal_name", sa.String(length=255), nullable=True),
        sa.Column("company_number", sa.String(length=50), nullable=True),
        sa.Column("website", sa.String(length=255), nullable=True),
        sa.Column("acquisitions_completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("track_record_summary", sa.Text(), nullable=True),
        sa.Column("identity_status", sa.String(length=20), nullable=False, server_default="not_submitted"),
        sa.Column("business_status", sa.String(length=20), nullable=False, server_default="not_submitted"),
        sa.Column("funds_status", sa.String(length=20), nullable=False, server_default="not_submitted"),
        sa.Column("funds_filename", sa.String(length=255), nullable=True),
        sa.Column("funds_original_filename", sa.String(length=255), nullable=True),
        sa.Column("funds_mime_type", sa.String(length=100), nullable=True),
        sa.Column("funds_size_bytes", sa.Integer(), nullable=True),
        sa.Column("submitted_at", sa.DateTime(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("reviewed_by_id", sa.Integer(), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
    )
    for column in ("identity_status", "business_status", "funds_status"):
        op.create_index(op.f(f"ix_buyer_qualification_{column}"), "buyer_qualification", [column], unique=False)


def downgrade():
    for column in ("funds_status", "business_status", "identity_status"):
        op.drop_index(op.f(f"ix_buyer_qualification_{column}"), table_name="buyer_qualification")
    op.drop_table("buyer_qualification")
