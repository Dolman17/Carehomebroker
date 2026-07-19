from datetime import timedelta

from conftest import login


def create_intro(app, status="initiated"):
    with app.app.app_context():
        intro = app.Introduction(
            buyer_id=3, seller_id=2, listing_id=1, status=status
        )
        app.db.session.add(intro)
        app.db.session.commit()
        return intro.id


def test_workspace_is_limited_to_approved_participants(client, seeded_app):
    approved_id = create_intro(seeded_app)
    pending_id = create_intro_for_other_listing(seeded_app, "pending_seller_request")
    login(client, "buyer")
    assert client.get(f"/introductions/{approved_id}/workspace").status_code == 200
    assert client.get(f"/introductions/{pending_id}/workspace").status_code == 404
    client.post("/logout")
    login(client, "valuer")
    assert client.get(f"/introductions/{approved_id}/workspace").status_code == 404


def create_intro_for_other_listing(app, status):
    with app.app.app_context():
        listing = app.Listing(
            seller_id=2, listing_code=f"WS-{status[:8]}", title="Workspace test",
            status="live",
        )
        app.db.session.add(listing)
        app.db.session.flush()
        intro = app.Introduction(
            buyer_id=3, seller_id=2, listing_id=listing.id, status=status
        )
        app.db.session.add(intro)
        app.db.session.commit()
        return intro.id


def test_messages_questions_and_resolution_are_private_and_audited(client, seeded_app):
    intro_id = create_intro(seeded_app)
    login(client, "buyer")
    response = client.post(
        f"/introductions/{intro_id}/workspace/messages",
        data={"message_type": "question", "body": "Can you share <script>contracts</script>?"},
    )
    assert response.status_code == 302
    with seeded_app.app.app_context():
        message = seeded_app.WorkspaceMessage.query.one()
        message_id = message.id
        assert seeded_app.Notification.query.filter_by(
            user_id=2, event_type="workspace_message"
        ).count() == 1
        assert seeded_app.AuditEvent.query.filter_by(
            event_type="workspace.question_added"
        ).count() == 1

    client.post("/logout")
    login(client, "seller")
    page = client.get(f"/introductions/{intro_id}/workspace")
    assert b"Can you share" in page.data
    assert b"Can you share <script>" not in page.data
    assert b"Can you share &lt;script&gt;" in page.data
    assert client.post(f"/workspace/messages/{message_id}/resolve").status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.WorkspaceMessage.query.one().resolved_at is not None


def test_tasks_are_assignable_only_to_deal_participants(client, seeded_app):
    intro_id = create_intro(seeded_app)
    login(client, "seller")
    invalid = client.post(
        f"/introductions/{intro_id}/workspace/tasks",
        data={"title": "Invalid owner", "owner_id": "4"},
    )
    assert invalid.status_code == 302
    valid = client.post(
        f"/introductions/{intro_id}/workspace/tasks",
        data={"title": "Review management accounts", "owner_id": "3", "due_date": "2026-07-25"},
    )
    assert valid.status_code == 302
    with seeded_app.app.app_context():
        task = seeded_app.WorkspaceTask.query.one()
        task_id = task.id
        assert task.owner_id == 3
    client.post("/logout")
    login(client, "buyer")
    assert client.post(
        f"/workspace/tasks/{task_id}/status", data={"status": "completed"}
    ).status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.WorkspaceTask.query.one().completed_at is not None


def test_due_task_reminders_are_deduplicated(client, seeded_app):
    intro_id = create_intro(seeded_app)
    with seeded_app.app.app_context():
        task = seeded_app.WorkspaceTask(
            introduction_id=intro_id, title="Confirm funding",
            owner_id=3, created_by_id=2,
            due_date=seeded_app.utcnow().date() + timedelta(days=2),
        )
        seeded_app.db.session.add(task)
        seeded_app.db.session.commit()
        task_id = task.id
        due_key = task.due_date.isoformat()
    assert client.get("/tasks/send_weekly_digest?token=test-digest-token").status_code == 200
    assert client.get("/tasks/send_weekly_digest?token=test-digest-token").status_code == 200
    with seeded_app.app.app_context():
        assert seeded_app.Notification.query.filter_by(
            user_id=3,
            dedupe_key=f"workspace-task-reminder:{task_id}:{due_key}",
        ).count() == 1


def test_milestones_can_be_created_and_completed(client, seeded_app):
    intro_id = create_intro(seeded_app)
    login(client, "seller")
    assert client.post(
        f"/introductions/{intro_id}/workspace/milestones",
        data={"title": "Heads of terms agreed", "due_date": "2026-08-01"},
    ).status_code == 302
    with seeded_app.app.app_context():
        milestone_id = seeded_app.WorkspaceMilestone.query.one().id
    assert client.post(
        f"/workspace/milestones/{milestone_id}/status",
        data={"status": "completed"},
    ).status_code == 302
    with seeded_app.app.app_context():
        assert seeded_app.WorkspaceMilestone.query.one().status == "completed"
