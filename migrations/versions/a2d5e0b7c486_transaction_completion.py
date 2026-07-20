"""transaction completion workflow

Revision ID: a2d5e0b7c486
Revises: f1c4d9a6b375
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "a2d5e0b7c486"
down_revision = "f1c4d9a6b375"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("introductions") as batch:
        batch.add_column(sa.Column("portfolio_id", sa.Integer()))
        batch.add_column(sa.Column("portfolio_lot_id", sa.Integer()))
        batch.add_column(sa.Column("portfolio_enquiry_id", sa.Integer()))
        batch.create_foreign_key("fk_introduction_portfolio", "portfolio", ["portfolio_id"], ["id"])
        batch.create_foreign_key("fk_introduction_portfolio_lot", "portfolio_lot", ["portfolio_lot_id"], ["id"])
        batch.create_foreign_key("fk_introduction_portfolio_enquiry", "portfolio_enquiry", ["portfolio_enquiry_id"], ["id"])
        batch.create_index("ix_introductions_portfolio_id", ["portfolio_id"])
        batch.create_index("ix_introductions_portfolio_lot_id", ["portfolio_lot_id"])
        batch.create_index("ix_introductions_portfolio_enquiry_id", ["portfolio_enquiry_id"], unique=True)

    op.create_table(
        "completion_checklist_item",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("introduction_id", sa.Integer(), sa.ForeignKey("introductions.id"), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("category", sa.String(30), nullable=False, server_default="other"),
        sa.Column("assigned_to", sa.String(20), nullable=False, server_default="joint"),
        sa.Column("is_required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("due_date", sa.Date()),
        sa.Column("note", sa.Text()),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("completed_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("completed_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    for column in ("introduction_id", "category", "assigned_to", "status", "due_date"):
        op.create_index(f"ix_completion_checklist_item_{column}", "completion_checklist_item", [column])

    op.create_table(
        "completion_condition",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("introduction_id", sa.Integer(), sa.ForeignKey("introductions.id"), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("responsible_party", sa.String(20), nullable=False, server_default="joint"),
        sa.Column("status", sa.String(20), nullable=False, server_default="outstanding"),
        sa.Column("due_date", sa.Date()),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("resolved_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("resolved_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    for column in ("introduction_id", "responsible_party", "status", "due_date"):
        op.create_index(f"ix_completion_condition_{column}", "completion_condition", [column])

    op.create_table(
        "signature_document",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("introduction_id", sa.Integer(), sa.ForeignKey("introductions.id"), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("mime_type", sa.String(100)),
        sa.Column("size_bytes", sa.Integer()),
        sa.Column("checksum_sha256", sa.String(64), nullable=False),
        sa.Column("requires_buyer", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("requires_seller", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(20), nullable=False, server_default="prepared"),
        sa.Column("buyer_signed_at", sa.DateTime()),
        sa.Column("seller_signed_at", sa.DateTime()),
        sa.Column("voided_at", sa.DateTime()),
        sa.Column("uploaded_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_signature_document_introduction_id", "signature_document", ["introduction_id"])
    op.create_index("ix_signature_document_status", "signature_document", ["status"])

    op.create_table(
        "completion_record",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("introduction_id", sa.Integer(), sa.ForeignKey("introductions.id"), nullable=False),
        sa.Column("handover_notes", sa.Text()),
        sa.Column("buyer_confirmed_at", sa.DateTime()),
        sa.Column("seller_confirmed_at", sa.DateTime()),
        sa.Column("completed_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_completion_record_introduction_id", "completion_record", ["introduction_id"], unique=True)


def downgrade():
    op.drop_table("completion_record")
    op.drop_table("signature_document")
    op.drop_table("completion_condition")
    op.drop_table("completion_checklist_item")
    with op.batch_alter_table("introductions") as batch:
        batch.drop_index("ix_introductions_portfolio_enquiry_id")
        batch.drop_index("ix_introductions_portfolio_lot_id")
        batch.drop_index("ix_introductions_portfolio_id")
        batch.drop_constraint("fk_introduction_portfolio_enquiry", type_="foreignkey")
        batch.drop_constraint("fk_introduction_portfolio_lot", type_="foreignkey")
        batch.drop_constraint("fk_introduction_portfolio", type_="foreignkey")
        batch.drop_column("portfolio_enquiry_id")
        batch.drop_column("portfolio_lot_id")
        batch.drop_column("portfolio_id")
