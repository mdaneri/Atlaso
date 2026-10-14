"""Focused audit persistence and operational reporting behavior."""

import logging
from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app import audit
from atlaso.app.database import Base
from atlaso.app.models import AuditEvent
from atlaso.app.operational_logging import FORMATTER, _HistoryFileHandler
from atlaso.app.services import producer_log_history


@pytest.fixture
def db_session(tmp_path: Path) -> Generator[Session, None, None]:
    """Provide an isolated database session for audit persistence tests.

    Args:
        tmp_path: Pytest's task-local temporary directory.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def _fresh_events(session: Session) -> list[AuditEvent]:
    """Read committed audit rows through an independent session.

    Args:
        session: Session bound to the isolated audit database.
    """
    with Session(session.get_bind()) as fresh_session:
        return list(fresh_session.execute(select(AuditEvent)).scalars().all())


def _fail_capture(*_args, **_kwargs) -> None:
    """Simulate the durable operational-history writer failing.

    Args:
        *_args: Positional writer arguments ignored by the failure stub.
        **_kwargs: Keyword writer arguments ignored by the failure stub.
    """
    raise OSError("synthetic private capture failure")


def test_default_best_effort_keeps_commit_when_real_handler_capture_fails(
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Keep committed audit state when history capture blocks file mirroring.

    Args:
        db_session: Isolated audit database session.
        tmp_path: Pytest's task-local temporary directory.
        monkeypatch: Fixture used to force the history writer to fail.
        capsys: Fixture used to inspect the fixed failure diagnostic.
    """
    monkeypatch.setattr(producer_log_history, "capture_record", _fail_capture)
    handler = _HistoryFileHandler(
        tmp_path / "operational.log",
        tmp_path / "history.jsonl",
        "web",
    )
    handler.setFormatter(FORMATTER)
    logger = logging.getLogger("atlaso.operational")
    logger.addHandler(handler)
    monkeypatch.setattr(logger, "level", logging.INFO)
    monkeypatch.setattr(logger, "propagate", False)
    try:
        event = audit.record_audit(
            db_session,
            actor="test-admin",
            action="update_firewall_settings",
            resource_type="firewall",
            resource_id="private-resource-id",
            detail="private audit detail",
        )
    finally:
        logger.removeHandler(handler)
        handler.close()

    persisted = _fresh_events(db_session)
    captured = capsys.readouterr()
    assert event.id is not None
    assert len(persisted) == 1
    assert persisted[0].id == event.id
    assert persisted[0].detail == "private audit detail"
    assert captured.err == "event=audit_post_commit_reporting_failed\n"
    assert all(
        value not in captured.err
        for value in (
            "test-admin",
            "update_firewall_settings",
            "private-resource-id",
            "private audit detail",
            "synthetic private capture failure",
        )
    )
    assert (tmp_path / "operational.log").read_text(encoding="utf-8") == ""


def test_explicit_strict_mode_propagates_post_commit_failure(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve callers' explicit strict post-commit reporting behavior.

    Args:
        db_session: Isolated audit database session.
        monkeypatch: Fixture used to force operational reporting to fail.
    """
    def fail_reporting(_event: AuditEvent) -> None:
        """Simulate strict reporting failure.

        Args:
            _event: Audit event received by the operational reporter.
        """
        raise RuntimeError("synthetic reporting failure")

    monkeypatch.setattr(audit, "log_audit_event", fail_reporting)
    with pytest.raises(RuntimeError, match="synthetic reporting failure"):
        audit.record_audit(
            db_session,
            actor="test-admin",
            action="strict-audit",
            resource_type="test",
            post_commit_best_effort=False,
        )

    persisted = _fresh_events(db_session)
    assert len(persisted) == 1
    assert persisted[0].action == "strict-audit"


def test_commit_failure_still_propagates_without_reporting_diagnostic(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Keep database commit errors outside best-effort reporting handling.

    Args:
        db_session: Isolated audit database session.
        monkeypatch: Fixture used to force the commit to fail.
        capsys: Fixture used to verify no post-commit diagnostic is emitted.
    """
    def fail_commit() -> None:
        raise RuntimeError("synthetic commit failure")

    monkeypatch.setattr(db_session, "commit", fail_commit)
    with pytest.raises(RuntimeError, match="synthetic commit failure"):
        audit.record_audit(
            db_session,
            actor="test-admin",
            action="commit-failure",
            resource_type="test",
            emit_operational=False,
        )

    assert _fresh_events(db_session) == []
    assert capsys.readouterr().err == ""


def test_best_effort_survives_stderr_failure(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not let a broken diagnostic sink undo a committed audit row.

    Args:
        db_session: Isolated audit database session.
        monkeypatch: Fixture used to replace reporting and the stderr sink.
    """
    class BrokenStderr:
        def write(self, _value: str) -> int:
            """Fail every write to simulate an unavailable stderr sink.

            Args:
                _value: Diagnostic text passed to the stderr writer.
            """
            raise OSError("synthetic stderr failure")

    def fail_reporting(_event: AuditEvent) -> None:
        """Simulate best-effort reporting failure.

        Args:
            _event: Audit event received by the operational reporter.
        """
        raise RuntimeError("synthetic reporting failure")

    monkeypatch.setattr(audit, "log_audit_event", fail_reporting)
    monkeypatch.setattr(audit.sys, "stderr", BrokenStderr())
    event = audit.record_audit(
        db_session,
        actor="test-admin",
        action="stderr-failure",
        resource_type="test",
    )

    persisted = _fresh_events(db_session)
    assert len(persisted) == 1
    assert persisted[0].id == event.id


@pytest.fixture(autouse=True)
def _client_logging_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep application logging files beneath pytest's task-local root.

    Args:
        monkeypatch: Fixture used to isolate application log paths.
        tmp_path: Pytest's task-local temporary directory.
    """
    monkeypatch.setenv("ATLASO_APP_LOG_PATH", str(tmp_path / "client-operational.log"))


@pytest.fixture(autouse=True)
def _isolated_logging_configuration() -> Generator[None, None, None]:
    """Restore process logging after client startup and synthetic handler failures."""
    from atlaso.app import operational_logging

    root_logger = logging.getLogger()
    loggers = [root_logger, logging.getLogger("atlaso"), operational_logging.LOGGER]
    original_levels = [logger.level for logger in loggers]
    original_configuration = operational_logging._APPLIED_CONFIGURATION
    original_handlers = [
        handler for handler in root_logger.handlers
        if operational_logging._handler_is_file(handler) or operational_logging._handler_is_syslog(handler)
    ]
    # Keep the existing handlers alive and detached, so startup cannot close them
    # or advance another test's streaming redaction context.
    for handler in original_handlers:
        root_logger.removeHandler(handler)
    operational_logging._APPLIED_CONFIGURATION = None
    try:
        yield
    finally:
        for handler in list(root_logger.handlers):
            if operational_logging._handler_is_file(handler) or operational_logging._handler_is_syslog(handler):
                root_logger.removeHandler(handler)
                handler.close()
        for handler in original_handlers:
            root_logger.addHandler(handler)
        for logger, level in zip(loggers, original_levels, strict=True):
            logger.setLevel(level)
        operational_logging._APPLIED_CONFIGURATION = original_configuration


def test_firewall_settings_api_succeeds_when_audit_capture_fails(
    client,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Persist a real firewall settings request despite history capture failure.

    Args:
        client: Authenticated HTTP test client from the shared fixture.
        tmp_path: Pytest's task-local temporary directory.
        monkeypatch: Fixture used to simulate durable history capture failure.
    """
    from atlaso.app import database
    from atlaso.app.models import AuditEvent, FirewallSettings
    from tests.routers.api_v1.helpers import create_token

    token, _metadata = create_token(client, scopes=["read:firewall", "write:firewall"])
    headers = {"Authorization": f"Bearer {token}"}
    current = client.get("/api/v1/firewall/settings", headers=headers)
    assert current.status_code == 200, current.text

    capture_calls = 0

    def fail_capture(*_args, **_kwargs) -> None:
        """Count the real handler's attempted history capture, then fail.

        Args:
            *_args: Positional writer arguments ignored by the failure stub.
            **_kwargs: Keyword writer arguments ignored by the failure stub.
        """
        nonlocal capture_calls
        capture_calls += 1
        _fail_capture()

    monkeypatch.setattr(producer_log_history, "capture_record", fail_capture)
    handler = _HistoryFileHandler(
        tmp_path / "api-operational.log",
        tmp_path / "api-history.jsonl",
        "web",
    )
    handler.setFormatter(FORMATTER)
    logger = logging.getLogger("atlaso.operational")
    logger.addHandler(handler)
    monkeypatch.setattr(logger, "level", logging.INFO)
    monkeypatch.setattr(logger, "propagate", False)
    try:
        updated = client.patch(
            "/api/v1/firewall/settings",
            headers=headers,
            json={**current.json(), "enabled": True, "log_dropped": True},
        )
    finally:
        logger.removeHandler(handler)
        handler.close()

    assert updated.status_code == 200, updated.text
    assert capture_calls >= 1
    assert updated.json()["enabled"] is True
    assert updated.json()["log_dropped"] is True
    with database.SessionLocal() as fresh_session:
        settings = fresh_session.execute(select(FirewallSettings)).scalar_one()
        audit_event = fresh_session.execute(
            select(AuditEvent).where(AuditEvent.action == "update_firewall_settings")
        ).scalar_one()
        assert settings.enabled is True
        assert settings.log_dropped is True
        assert audit_event.resource_type == "firewall"
