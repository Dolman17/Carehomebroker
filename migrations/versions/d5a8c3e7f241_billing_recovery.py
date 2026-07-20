"""Billing recovery and entitlement history

Revision ID: d5a8c3e7f241
Revises: c4f7a2b9e138
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "d5a8c3e7f241"
down_revision = "c4f7a2b9e138"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("subscriptions") as batch:
        batch.add_column(sa.Column("stripe_status", sa.String(30)))
        batch.add_column(sa.Column("grace_period_ends_at", sa.DateTime()))
        batch.add_column(sa.Column("payment_failed_at", sa.DateTime()))
        batch.add_column(sa.Column("last_payment_at", sa.DateTime()))
        batch.add_column(sa.Column("last_invoice_id", sa.String(255)))
        batch.add_column(sa.Column("last_stripe_event_created", sa.BigInteger()))
        batch.add_column(sa.Column("last_entitlement_reason", sa.String(255)))
        batch.add_column(sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()))
        batch.create_index("ix_subscriptions_stripe_status", ["stripe_status"])
        batch.create_index("ix_subscriptions_grace_period_ends_at", ["grace_period_ends_at"])
        batch.create_index("ix_subscriptions_last_invoice_id", ["last_invoice_id"])

    op.create_table(
        "subscription_entitlement_event",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("subscription_id", sa.Integer(), sa.ForeignKey("subscriptions.id")),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("stripe_event_id", sa.String(255), unique=True),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("previous_provider_status", sa.String(30)),
        sa.Column("provider_status", sa.String(30)),
        sa.Column("previous_access_state", sa.String(20)),
        sa.Column("access_state", sa.String(20), nullable=False),
        sa.Column("reason", sa.String(255), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_subscription_entitlement_event_subscription_id", "subscription_entitlement_event", ["subscription_id"])
    op.create_index("ix_subscription_entitlement_event_user_id", "subscription_entitlement_event", ["user_id"])
    op.create_index("ix_subscription_entitlement_event_stripe_event_id", "subscription_entitlement_event", ["stripe_event_id"], unique=True)
    op.create_index("ix_subscription_entitlement_event_event_type", "subscription_entitlement_event", ["event_type"])
    op.create_index("ix_subscription_entitlement_event_access_state", "subscription_entitlement_event", ["access_state"])
    op.create_index("ix_subscription_entitlement_event_created_at", "subscription_entitlement_event", ["created_at"])


def downgrade():
    op.drop_table("subscription_entitlement_event")
    with op.batch_alter_table("subscriptions") as batch:
        batch.drop_index("ix_subscriptions_last_invoice_id")
        batch.drop_index("ix_subscriptions_grace_period_ends_at")
        batch.drop_index("ix_subscriptions_stripe_status")
        batch.drop_column("updated_at")
        batch.drop_column("last_entitlement_reason")
        batch.drop_column("last_invoice_id")
        batch.drop_column("last_stripe_event_created")
        batch.drop_column("last_payment_at")
        batch.drop_column("payment_failed_at")
        batch.drop_column("grace_period_ends_at")
        batch.drop_column("stripe_status")
