"""Verify the shared token issuance transaction with independent database readers."""

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from atlaso.app import token_service
from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal
from atlaso.app.models import ApiToken, AuditEvent, User
from atlaso.app.schemas import ApiTokenCreate
from atlaso.app.security import hash_token


@pytest.mark.parametrize("failure", ["audit_facade", "audit_flush", "commit"])
def test_issuance_failure_rolls_back_token_and_audit(client, monkeypatch, failure):
    """Keep both rows absent after failure, even if the caller later commits."""
    with SessionLocal() as db:
        user = db.query(User).filter_by(username="admin").one()

        def fail(*_args, **_kwargs):
            raise RuntimeError("synthetic issuance persistence failure")

        def fail_audit_flush(session, _context, _instances):
            if any(isinstance(row, AuditEvent) for row in session.new):
                fail()

        if failure == "audit_facade":
            monkeypatch.setattr(token_service, "record_audit", fail)
        elif failure == "audit_flush":
            event.listen(db, "before_flush", fail_audit_flush)
        else:
            monkeypatch.setattr(db, "commit", fail)
        with pytest.raises(RuntimeError, match="synthetic issuance persistence failure"):
            token_service.create_token_for_user(
                db, user=user, create=ApiTokenCreate(name="atomic-failure", scopes=[]),
                settings=get_settings(), actor="admin",
            )
        # Prove rollback belongs to the service, rather than session teardown.
        monkeypatch.undo()
        db.commit()
        with Session(db.get_bind()) as fresh:
            assert fresh.query(ApiToken).filter_by(name="atomic-failure").count() == 0
            assert fresh.query(AuditEvent).filter_by(action="create_api_token").count() == 0


def test_success_commits_token_and_creation_audit_together(client, monkeypatch):
    """Return a usable secret only after one commit makes both records durable."""
    with SessionLocal() as db:
        user = db.query(User).filter_by(username="admin").one()
        commits = []
        commit = db.commit

        def track_commit():
            commits.append(True)
            commit()

        monkeypatch.setattr(db, "commit", track_commit)
        created = token_service.create_token_for_user(
            db, user=user, create=ApiTokenCreate(name="atomic-success", scopes=[]),
            settings=get_settings(), actor="admin",
        )
        assert len(commits) == 1
        with Session(db.get_bind()) as fresh:
            token = fresh.query(ApiToken).filter_by(name="atomic-success").one()
            audit = fresh.query(AuditEvent).filter_by(action="create_api_token").one()
            assert token.enabled
            assert audit.resource_id == str(token.id) == str(created.token.id)
            assert audit.actor == "admin"
            assert audit.success
            # Avoid including credential material in assertion diagnostics.
            matches = token.token_hash == hash_token(created.raw_token)
            assert matches
            assert "raw_token" not in created.token.model_dump()
