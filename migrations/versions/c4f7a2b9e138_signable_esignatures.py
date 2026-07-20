"""Signable electronic signatures

Revision ID: c4f7a2b9e138
Revises: b3e6f1a8d927
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "c4f7a2b9e138"
down_revision = "b3e6f1a8d927"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "esignature_envelope",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("document_id", sa.Integer(), sa.ForeignKey("signature_document.id"), nullable=False),
        sa.Column("provider", sa.String(30), nullable=False, server_default="signable"),
        sa.Column("provider_envelope_id", sa.String(128)),
        sa.Column("status", sa.String(30), nullable=False, server_default="creating"),
        sa.Column("requested_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("request_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text()),
        sa.Column("sent_at", sa.DateTime()),
        sa.Column("completed_at", sa.DateTime()),
        sa.Column("last_synced_at", sa.DateTime()),
        sa.Column("signed_filename", sa.String(255)),
        sa.Column("signed_original_filename", sa.String(255)),
        sa.Column("signed_mime_type", sa.String(100)),
        sa.Column("signed_size_bytes", sa.Integer()),
        sa.Column("signed_checksum_sha256", sa.String(64)),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("document_id", name="uq_esignature_envelope_document_id"),
    )
    op.create_index("ix_esignature_envelope_document_id", "esignature_envelope", ["document_id"], unique=True)
    op.create_index("ix_esignature_envelope_provider_envelope_id", "esignature_envelope", ["provider_envelope_id"], unique=True)
    op.create_index("ix_esignature_envelope_status", "esignature_envelope", ["status"])

    op.create_table(
        "esignature_party",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("envelope_id", sa.Integer(), sa.ForeignKey("esignature_envelope.id"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("party_role", sa.String(20), nullable=False),
        sa.Column("provider_party_id", sa.String(64)),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("signed_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("envelope_id", "party_role", name="uq_esignature_party_role"),
    )
    op.create_index("ix_esignature_party_envelope_id", "esignature_party", ["envelope_id"])
    op.create_index("ix_esignature_party_user_id", "esignature_party", ["user_id"])
    op.create_index("ix_esignature_party_status", "esignature_party", ["status"])

    op.create_table(
        "esignature_event",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("envelope_id", sa.Integer(), sa.ForeignKey("esignature_envelope.id"), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("action_at", sa.DateTime()),
        sa.Column("received_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("processed_at", sa.DateTime()),
        sa.Column("processing_error", sa.String(500)),
    )
    op.create_index("ix_esignature_event_envelope_id", "esignature_event", ["envelope_id"])
    op.create_index("ix_esignature_event_payload_hash", "esignature_event", ["payload_hash"], unique=True)
    op.create_index("ix_esignature_event_action", "esignature_event", ["action"])


def downgrade():
    op.drop_table("esignature_event")
    op.drop_table("esignature_party")
    op.drop_table("esignature_envelope")
