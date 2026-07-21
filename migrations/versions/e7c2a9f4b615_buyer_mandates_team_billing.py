"""Buyer mandate approval and team billing

Revision ID: e7c2a9f4b615
Revises: d5a8c3e7f241
Create Date: 2026-07-21
"""

from alembic import op
import sqlalchemy as sa


revision = "e7c2a9f4b615"
down_revision = "d5a8c3e7f241"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "buyer_mandate_review",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("buyer_profile_id", sa.Integer(), sa.ForeignKey("buyer_profile.id"), nullable=False, unique=True),
        sa.Column("status", sa.String(24), nullable=False, server_default="draft"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("snapshot_hash", sa.String(64)),
        sa.Column("submitted_at", sa.DateTime()),
        sa.Column("reviewed_at", sa.DateTime()),
        sa.Column("reviewed_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("review_notes", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_buyer_mandate_review_buyer_profile_id", "buyer_mandate_review", ["buyer_profile_id"], unique=True)
    op.create_index("ix_buyer_mandate_review_status", "buyer_mandate_review", ["status"])

    with op.batch_alter_table("team_membership") as batch:
        batch.add_column(sa.Column("uses_billing_seat", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("billing_seat_assigned_at", sa.DateTime()))
        batch.add_column(sa.Column("billing_seat_assigned_by_id", sa.Integer()))
        batch.create_foreign_key("fk_team_membership_billing_seat_assigner", "user", ["billing_seat_assigned_by_id"], ["id"])
        batch.create_index("ix_team_membership_uses_billing_seat", ["uses_billing_seat"])
    op.execute("UPDATE team_membership SET uses_billing_seat = 1, billing_seat_assigned_at = joined_at, billing_seat_assigned_by_id = user_id WHERE role = 'owner' AND status = 'active'")

    with op.batch_alter_table("subscriptions") as batch:
        batch.add_column(sa.Column("team_id", sa.Integer()))
        batch.add_column(sa.Column("seat_limit", sa.Integer(), nullable=False, server_default="1"))
        batch.create_foreign_key("fk_subscriptions_team", "team", ["team_id"], ["id"])
        batch.create_index("ix_subscriptions_team_id", ["team_id"])

    with op.batch_alter_table("subscription_entitlement_event") as batch:
        batch.add_column(sa.Column("team_id", sa.Integer()))
        batch.create_foreign_key("fk_subscription_entitlement_event_team", "team", ["team_id"], ["id"])
        batch.create_index("ix_subscription_entitlement_event_team_id", ["team_id"])


def downgrade():
    with op.batch_alter_table("subscription_entitlement_event") as batch:
        batch.drop_index("ix_subscription_entitlement_event_team_id")
        batch.drop_constraint("fk_subscription_entitlement_event_team", type_="foreignkey")
        batch.drop_column("team_id")
    with op.batch_alter_table("subscriptions") as batch:
        batch.drop_index("ix_subscriptions_team_id")
        batch.drop_constraint("fk_subscriptions_team", type_="foreignkey")
        batch.drop_column("seat_limit")
        batch.drop_column("team_id")
    with op.batch_alter_table("team_membership") as batch:
        batch.drop_index("ix_team_membership_uses_billing_seat")
        batch.drop_constraint("fk_team_membership_billing_seat_assigner", type_="foreignkey")
        batch.drop_column("billing_seat_assigned_by_id")
        batch.drop_column("billing_seat_assigned_at")
        batch.drop_column("uses_billing_seat")
    op.drop_table("buyer_mandate_review")
