"""Focused coverage for configurable operational log levels and safe output."""

import logging
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from atlaso.app import operational_logging as op_logging
from atlaso.app.database import Base


class _CaptureSyslogHandler(logging.Handler):
    """In-memory stand-in for the configured syslog output."""

    facility_names = {"local0": 16}
    LOG_LOCAL0 = 16

    def __init__(self, address, facility, socktype):
        """Store the endpoint arguments used by the production handler.

        Args:
            address: Configured syslog destination.
            facility: Selected syslog facility number.
            socktype: Selected socket type for syslog transport.
        """
        super().__init__()
        self.address = address
        self.facility = facility
        self.socktype = socktype
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Keep formatted output for assertions.

        Args:
            record: Sanitized record delivered by the handler filter.
        """
        self.messages.append(self.format(record))


class _SwitchableSyslogHandler(_CaptureSyslogHandler):
    """Allow one destination to simulate a sanitized initialization failure."""

    fail_alternate_host = False

    def __init__(self, address, facility, socktype):
        """Reject the alternate fixture host when failure simulation is enabled.

        Args:
            address: Configured syslog destination.
            facility: Selected syslog facility number.
            socktype: Selected socket type for syslog transport.
        """
        if self.fail_alternate_host and address[0] == "127.0.0.2":
            raise OSError("synthetic-token-must-not-be-logged")
        super().__init__(address, facility, socktype)


@pytest.fixture
def logging_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Provide a private database and file target, restoring root logging afterward.

    Args:
        tmp_path: Pytest-owned temporary directory beneath the task validation root.
        monkeypatch: Pytest fixture used to replace the operational logging settings.
    """
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    database = Session(engine)
    log_path = tmp_path / "atlaso.log"
    monkeypatch.setattr(
        op_logging,
        "get_settings",
        lambda: SimpleNamespace(app_log_path=log_path, app_log_history_path=None),
    )
    root_logger = logging.getLogger()
    atlaso_logger = logging.getLogger("atlaso")
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    original_atlaso_level = atlaso_logger.level
    for handler in list(root_logger.handlers):
        if op_logging._handler_is_file(handler) or op_logging._handler_is_syslog(handler):
            root_logger.removeHandler(handler)
            handler.close()
    op_logging._APPLIED_CONFIGURATION = None
    yield database, log_path
    for handler in list(root_logger.handlers):
        if op_logging._handler_is_file(handler) or op_logging._handler_is_syslog(handler):
            root_logger.removeHandler(handler)
            handler.close()
    for handler in original_handlers:
        if handler not in root_logger.handlers:
            root_logger.addHandler(handler)
    root_logger.setLevel(original_level)
    atlaso_logger.setLevel(original_atlaso_level)
    op_logging._APPLIED_CONFIGURATION = None
    database.close()
    engine.dispose()


def _save_preferences(
    database: Session,
    *,
    level: str,
    syslog_level: str = "INFO",
    syslog: bool = False,
    syslog_host: str = "127.0.0.1",
):
    """Persist one preference set for the isolated test database.

    Args:
        database: Isolated SQLAlchemy session.
        level: Selected file log level.
        syslog_level: Selected syslog log level.
        syslog: Whether to configure syslog forwarding.
        syslog_host: Safe syslog destination used for preference updates.
    """
    op_logging.save_logging_preferences(
        database,
        level=level,
        syslog_enabled=syslog,
        syslog_host=syslog_host if syslog else "",
        syslog_port=514,
        syslog_protocol="udp",
        syslog_facility="local0",
        syslog_level=syslog_level,
    )
    database.commit()


def _file_handler() -> RotatingFileHandler:
    """Return the active Atlaso file handler."""
    return next(
        handler
        for handler in logging.getLogger().handlers
        if op_logging._handler_is_file(handler)
    )


def test_file_level_routes_records_and_refresh_applies_changed_setting(logging_context):
    """File output follows persisted WARNING/DEBUG changes through bounded refresh.

    Args:
        logging_context: Isolated database and log path.
    """
    database, log_path = logging_context
    _save_preferences(database, level="WARNING")
    op_logging.refresh_logging_preferences(database)
    logging.getLogger("atlaso.test").info("filtered informational event")
    logging.getLogger("atlaso.test").warning("warning event retained")
    _file_handler().flush()
    content = log_path.read_text(encoding="utf-8")
    assert "filtered informational event" not in content
    assert "warning event retained" in content

    _save_preferences(database, level="DEBUG")
    op_logging.refresh_logging_preferences(database)
    logging.getLogger("atlaso.test").debug("debug event retained")
    _file_handler().flush()
    assert "debug event retained" in log_path.read_text(encoding="utf-8")


def test_refresh_with_unchanged_preferences_keeps_existing_handler(logging_context, monkeypatch):
    """A repeated polling refresh does not replace or rebuild configured handlers.

    Args:
        logging_context: Isolated database and log path.
        monkeypatch: Pytest fixture used to count handler setup calls.
    """
    database, _ = logging_context
    _save_preferences(database, level="INFO")
    setup_calls = 0
    original_setup = op_logging._ensure_file_handler

    def count_setup(*args, **kwargs):
        nonlocal setup_calls
        setup_calls += 1
        return original_setup(*args, **kwargs)

    monkeypatch.setattr(op_logging, "_ensure_file_handler", count_setup)
    op_logging.refresh_logging_preferences(database)
    configured_handler = _file_handler()
    op_logging.refresh_logging_preferences(database)
    assert setup_calls == 1
    assert _file_handler() is configured_handler


def test_failed_file_reconfiguration_keeps_handler_and_retries_on_next_refresh(logging_context, monkeypatch):
    """A failed path change preserves the old file and retries the same snapshot.

    Args:
        logging_context: Isolated database and log path.
        monkeypatch: Pytest fixture used to replace application path settings.
    """
    database, log_path = logging_context
    _save_preferences(database, level="INFO")
    op_logging.refresh_logging_preferences(database)
    existing_handler = _file_handler()
    blocked_parent = log_path.parent / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")
    settings = SimpleNamespace(
        app_log_path=blocked_parent / "atlaso.log",
        app_log_history_path=None,
    )
    monkeypatch.setattr(op_logging, "get_settings", lambda: settings)

    op_logging.refresh_logging_preferences(database)
    assert _file_handler() is existing_handler
    assert existing_handler.stream is not None

    blocked_parent.unlink()
    op_logging.refresh_logging_preferences(database)
    replacement = _file_handler()
    assert replacement is not existing_handler
    assert Path(replacement.baseFilename) == settings.app_log_path.resolve()


def test_file_replacement_shares_private_key_state_with_concurrent_records(logging_context, monkeypatch):
    """A record arriving before handler swap remains protected by the replacement.

    Args:
        logging_context: Isolated database and log path.
        monkeypatch: Pytest fixture used to pause the handler replacement boundary.
    """
    database, old_path = logging_context
    settings = SimpleNamespace(app_log_path=old_path, app_log_history_path=None)
    monkeypatch.setattr(op_logging, "get_settings", lambda: settings)
    _save_preferences(database, level="WARNING")
    preferences = op_logging.refresh_logging_preferences(database)
    old_handler = _file_handler()
    new_path = old_path.parent / "replacement.log"
    settings.app_log_path = new_path

    before_add = threading.Event()
    resume_add = threading.Event()
    root_logger = logging.getLogger()
    original_add_handler = root_logger.addHandler

    def pause_before_replacement_add(handler: logging.Handler) -> None:
        """Pause after shared-state binding and before the new handler is visible.

        Args:
            handler: Handler being registered with the root logger.
        """
        if op_logging._handler_is_file(handler) and Path(handler.baseFilename) == new_path.resolve():
            before_add.set()
            if not resume_add.wait(timeout=5):
                raise TimeoutError("Timed out waiting for concurrent log fixture.")
        original_add_handler(handler)

    monkeypatch.setattr(root_logger, "addHandler", pause_before_replacement_add)
    configure_errors: list[Exception] = []

    def reconfigure() -> None:
        """Apply the changed file path in a separate logging thread."""
        try:
            op_logging._apply_logging_preferences(preferences, settings, "web")
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            configure_errors.append(error)

    configuration_thread = threading.Thread(target=reconfigure)
    configuration_thread.start()
    assert before_add.wait(timeout=5)
    logger = logging.getLogger("atlaso.test.concurrent-replacement")
    logger.debug("-----BEGIN RSA PRIVATE KEY-----")
    resume_add.set()
    configuration_thread.join(timeout=5)
    assert not configuration_thread.is_alive()
    assert not configure_errors

    logger.warning("synthetic-concurrent-private-fragment")
    logger.info("-----END RSA PRIVATE KEY-----")
    logger.warning("safe event after concurrent handler replacement")
    for handler in root_logger.handlers:
        if op_logging._handler_is_file(handler):
            handler.flush()

    old_content = old_path.read_text(encoding="utf-8")
    new_content = new_path.read_text(encoding="utf-8")
    assert old_handler not in root_logger.handlers
    assert "synthetic-concurrent-private-fragment" not in old_content + new_content
    assert "safe event after concurrent handler replacement" in new_content


def test_failed_syslog_reconfiguration_preserves_handler_and_retries(logging_context, monkeypatch):
    """A failed syslog endpoint change retains the previous handler and retries.

    Args:
        logging_context: Isolated database and log path.
        monkeypatch: Pytest fixture used to replace the native syslog handler.
    """
    database, _ = logging_context
    monkeypatch.setattr(op_logging, "SysLogHandler", _SwitchableSyslogHandler)
    monkeypatch.setattr(_SwitchableSyslogHandler, "fail_alternate_host", False)
    _save_preferences(database, level="INFO", syslog=True)
    op_logging.refresh_logging_preferences(database)
    root_logger = logging.getLogger()
    existing_handler = next(handler for handler in root_logger.handlers if op_logging._handler_is_syslog(handler))

    _save_preferences(database, level="INFO", syslog=True, syslog_host="127.0.0.2")
    _SwitchableSyslogHandler.fail_alternate_host = True
    op_logging.refresh_logging_preferences(database)
    assert next(handler for handler in root_logger.handlers if op_logging._handler_is_syslog(handler)) is existing_handler

    _SwitchableSyslogHandler.fail_alternate_host = False
    op_logging.refresh_logging_preferences(database)
    replacement = next(handler for handler in root_logger.handlers if op_logging._handler_is_syslog(handler))
    assert replacement is not existing_handler
    assert replacement.address == ("127.0.0.2", 514)
    assert any("error_code=syslog_handler_unavailable" in value for value in existing_handler.messages)
    assert all("synthetic-token-must-not-be-logged" not in value for value in existing_handler.messages)


def test_file_and_syslog_redact_split_private_keys_and_exception_details(logging_context, monkeypatch):
    """Both destinations redact stateful private-key fragments and exception messages.

    Args:
        logging_context: Isolated database and log path.
        monkeypatch: Pytest fixture used to replace the native syslog handler.
    """
    database, log_path = logging_context
    monkeypatch.setattr(op_logging, "SysLogHandler", _CaptureSyslogHandler)
    _save_preferences(database, level="DEBUG", syslog_level="WARNING", syslog=True)
    op_logging.refresh_logging_preferences(database)
    root_logger = logging.getLogger()
    syslog_handler = next(handler for handler in root_logger.handlers if op_logging._handler_is_syslog(handler))

    logger = logging.getLogger("atlaso.test.redaction")
    logger.debug("-----BEGIN RSA PRIVATE KEY-----")
    _save_preferences(database, level="WARNING", syslog_level="WARNING", syslog=True)
    op_logging.refresh_logging_preferences(database)
    logger.warning("synthetic-private-key-fragment")
    logger.info("-----END RSA PRIVATE KEY-----")
    logger.warning("safe event after key block")
    try:
        raise ValueError("access_token=synthetic-secret-value")
    except ValueError:
        logger.exception("operation failed")
    for handler in root_logger.handlers:
        if op_logging._handler_is_file(handler) or op_logging._handler_is_syslog(handler):
            handler.flush()

    file_content = log_path.read_text(encoding="utf-8")
    syslog_content = "\n".join(syslog_handler.messages)
    for content in (file_content, syslog_content):
        assert "synthetic-private-key-fragment" not in content
        assert "synthetic-secret-value" not in content
        assert "ValueError" in content
        assert "safe event after key block" in content
    assert "operation failed" in syslog_content


def test_warning_destinations_consume_debug_and_info_private_key_markers(logging_context, monkeypatch):
    """WARNING outputs consume filtered DEBUG/INFO key markers before later events.

    Args:
        logging_context: Isolated database and log path.
        monkeypatch: Pytest fixture used to replace the native syslog handler.
    """
    database, log_path = logging_context
    monkeypatch.setattr(op_logging, "SysLogHandler", _CaptureSyslogHandler)
    _save_preferences(database, level="WARNING", syslog_level="WARNING", syslog=True)
    root_level = logging.getLogger().level
    op_logging.refresh_logging_preferences(database)
    root_logger = logging.getLogger()
    syslog_handler = next(handler for handler in root_logger.handlers if op_logging._handler_is_syslog(handler))
    logger = logging.getLogger("atlaso.test.warning")

    logger.debug("-----BEGIN RSA PRIVATE KEY-----")
    logger.warning("synthetic-warning-private-fragment")
    logger.info("-----END RSA PRIVATE KEY-----")
    logger.warning("safe warning after filtered close marker")
    for handler in root_logger.handlers:
        if op_logging._handler_is_file(handler) or op_logging._handler_is_syslog(handler):
            handler.flush()

    file_content = log_path.read_text(encoding="utf-8")
    syslog_content = "\n".join(syslog_handler.messages)
    assert logging.getLogger().level == root_level
    for content in (file_content, syslog_content):
        assert "synthetic-warning-private-fragment" not in content
        assert "safe warning after filtered close marker" in content


def test_oversized_record_is_bounded_after_redaction_consumes_full_source(logging_context, monkeypatch):
    """Oversized output is marked and truncated after the private-key parser sees its tail.

    Args:
        logging_context: Isolated database and log path.
        monkeypatch: Pytest fixture used to replace the native syslog handler.
    """
    database, log_path = logging_context
    monkeypatch.setattr(op_logging, "SysLogHandler", _CaptureSyslogHandler)
    _save_preferences(database, level="INFO", syslog=True)
    op_logging.refresh_logging_preferences(database)
    syslog_handler = next(
        handler for handler in logging.getLogger().handlers if op_logging._handler_is_syslog(handler)
    )
    logger = logging.getLogger("atlaso.test.bounds")
    logger.warning(
        "x" * 70_000
        + "\n-----BEGIN RSA PRIVATE KEY-----\nsynthetic-long-key-fragment\n"
        + "-----END RSA PRIVATE KEY-----\nrecord tail"
    )
    logger.warning("safe record after oversized key block")
    for handler in logging.getLogger().handlers:
        if op_logging._handler_is_file(handler) or op_logging._handler_is_syslog(handler):
            handler.flush()

    content = log_path.read_text(encoding="utf-8")
    oversized_line = next(line for line in content.splitlines() if "x" * 100 in line)
    assert len(oversized_line.encode("utf-8")) < op_logging.MAX_LOG_RECORD_BYTES
    assert op_logging.TRUNCATION_MARKER in oversized_line
    assert "synthetic-long-key-fragment" not in content
    assert "safe record after oversized key block" in content
    syslog_record = next(value for value in syslog_handler.messages if "x" * 100 in value)
    assert len(syslog_record.encode("utf-8")) < op_logging.MAX_LOG_RECORD_BYTES
    assert op_logging.TRUNCATION_MARKER in syslog_record
    assert "synthetic-long-key-fragment" not in "\n".join(syslog_handler.messages)


def test_helper_observation_transitions_are_quiet_and_independent(caplog, monkeypatch):
    """Suppress repeated observations without confusing independent source actions.

    Args:
        caplog: Capture typed helper events.
        monkeypatch: Isolate the process observation cache.
    """
    from atlaso.app.adapters import system

    monkeypatch.setattr(system, "_HELPER_OBSERVATIONS", {})
    caplog.set_level(logging.INFO, logger="atlaso.helper")
    healthy = system.AdapterResult(command=["ignored"], dry_run=False, returncode=0)
    failed = system.AdapterResult(command=["ignored"], dry_run=False, returncode=1,
                                  stderr="permission denied password=synthetic-secret")
    system._log_helper_outcome("network", "status", healthy)
    for group, action in (("logs", "page"), ("network", "address-status"), ("appliance-update", "status-inspect")):
        for _ in range(3):
            system._log_helper_outcome(group, action, healthy)
    assert not caplog.records
    system._log_helper_outcome("network", "status", failed)
    system._log_helper_outcome("network", "logs", healthy)
    system._log_helper_outcome("network", "status", failed)
    assert len(caplog.records) == 1
    assert "reason=permission_denied" in caplog.text
    assert "synthetic-secret" not in caplog.text
    system._log_helper_outcome("network", "status", healthy)
    assert len(caplog.records) == 2
    assert "outcome=succeeded" in caplog.records[-1].message
