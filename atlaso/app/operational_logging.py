"""Configure redacted file and syslog output for operational events."""

from __future__ import annotations

import copy
import logging
import socket
import threading
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler, SysLogHandler
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from atlaso.app.config import get_settings
from atlaso.app.models import Setting, utcnow
from atlaso.app.services.log_sanitization import (
    JSON_SECRET_FIELD_PATTERN as JSON_SECRET_FIELD_PATTERN,
)
from atlaso.app.services.log_sanitization import (
    JWT_PATH_SEGMENT_PATTERN as JWT_PATH_SEGMENT_PATTERN,
)
from atlaso.app.services.log_sanitization import (
    OIDC_QUERY_SECRET_PATTERN as OIDC_QUERY_SECRET_PATTERN,
)
from atlaso.app.services.log_sanitization import (
    PRIVATE_KEY_BEGIN_PATTERN as PRIVATE_KEY_BEGIN_PATTERN,
)
from atlaso.app.services.log_sanitization import (
    PRIVATE_KEY_END_PATTERN as PRIVATE_KEY_END_PATTERN,
)
from atlaso.app.services.log_sanitization import (
    SECRET_LINE_PATTERN as SECRET_LINE_PATTERN,
)
from atlaso.app.services.log_sanitization import (
    URL_USERINFO_PATTERN as URL_USERINFO_PATTERN,
)
from atlaso.app.services.log_sanitization import _safe_lines as _safe_lines
from atlaso.app.services.log_sanitization import (
    redact_operational_text as redact_operational_text,
)

LOGGING_LEVEL_KEY = "logging.level"
LOGGING_SYSLOG_ENABLED_KEY = "logging.syslog.enabled"
LOGGING_SYSLOG_HOST_KEY = "logging.syslog.host"
LOGGING_SYSLOG_PORT_KEY = "logging.syslog.port"
LOGGING_SYSLOG_PROTOCOL_KEY = "logging.syslog.protocol"
LOGGING_SYSLOG_FACILITY_KEY = "logging.syslog.facility"
LOGGING_SYSLOG_LEVEL_KEY = "logging.syslog.level"

LOG_LEVELS = ("WARNING", "INFO", "DEBUG")
SYSLOG_PROTOCOLS = ("udp", "tcp")
SYSLOG_FACILITIES = ("auth", "authpriv", "cron", "daemon", "kern", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7", "user")

LOGGER = logging.getLogger("atlaso.operational")
MAX_LOG_RECORD_BYTES = 64 * 1024
_MAX_FORMATTED_BYTES = MAX_LOG_RECORD_BYTES - 64
TRUNCATION_MARKER = " [truncated]"


class _BoundedFormatter(logging.Formatter):
    """Format a sanitized record within the fixed output byte limit."""

    def format(self, record: logging.LogRecord) -> str:
        """Format and byte-bound one already-sanitized record.

        Args:
            record: Sanitized log record supplied by an output handler.
        """
        rendered = super().format(record)
        encoded = rendered.encode("utf-8")
        if len(encoded) <= _MAX_FORMATTED_BYTES:
            return rendered
        marker = TRUNCATION_MARKER.encode("utf-8")
        prefix = encoded[: _MAX_FORMATTED_BYTES - len(marker)].decode("utf-8", errors="ignore").rstrip()
        return f"{prefix}{TRUNCATION_MARKER}"


FORMATTER = _BoundedFormatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
_CONFIGURATION_LOCK = threading.RLock()
_APPLIED_CONFIGURATION: tuple[object, ...] | None = None


@dataclass(frozen=True)
class LoggingPreferences:
    """Represent logging preferences.

    Attributes:
        level: Level maintained by this loggingpreferences.
        syslog_enabled: Whether syslog is enabled.
        syslog_host: Syslog host maintained by this loggingpreferences.
        syslog_port: Network port used for syslog.
        syslog_protocol: Syslog protocol maintained by this loggingpreferences.
        syslog_facility: Syslog facility maintained by this loggingpreferences.
        syslog_level: Syslog level maintained by this loggingpreferences.
    """
    level: str = "INFO"
    syslog_enabled: bool = False
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_protocol: str = "udp"
    syslog_facility: str = "local0"
    syslog_level: str = "INFO"


def _normalize_level(value: str | None, *, default: str = "INFO") -> str:
    """Normalize level.

    Args:
        value: Candidate value consumed by normalize level.
        default: Candidate default to normalize.


    Returns:
        The normalize level result.
    """
    normalized = (value or default).strip().upper()
    return normalized if normalized in LOG_LEVELS else default


def _normalize_bool(value: str | None) -> bool:
    """Normalize bool.

    Args:
        value: Candidate value consumed by normalize bool.


    Returns:
        The normalize bool result.
    """
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _normalize_port(value: str | int | None) -> int:
    """Normalize port.

    Args:
        value: Candidate value consumed by normalize port.


    Returns:
        The normalize port result.
    """
    try:
        port = int(value or 514)
    except (TypeError, ValueError):
        return 514
    return port if 1 <= port <= 65535 else 514


def _normalize_protocol(value: str | None) -> str:
    """Normalize protocol.

    Args:
        value: Candidate value consumed by normalize protocol.


    Returns:
        The normalize protocol result.
    """
    protocol = (value or "udp").strip().lower()
    return protocol if protocol in SYSLOG_PROTOCOLS else "udp"


def _normalize_facility(value: str | None) -> str:
    """Normalize facility.

    Args:
        value: Candidate value consumed by normalize facility.


    Returns:
        The normalize facility result.
    """
    facility = (value or "local0").strip().lower()
    return facility if facility in SYSLOG_FACILITIES else "local0"


def _setting_map(db: Session | None) -> dict[str, str] | None:
    """Return setting map.

    Args:
        db: Active database session.
    """
    if db is None:
        return {}
    try:
        keys = {
            LOGGING_LEVEL_KEY,
            LOGGING_SYSLOG_ENABLED_KEY,
            LOGGING_SYSLOG_HOST_KEY,
            LOGGING_SYSLOG_PORT_KEY,
            LOGGING_SYSLOG_PROTOCOL_KEY,
            LOGGING_SYSLOG_FACILITY_KEY,
            LOGGING_SYSLOG_LEVEL_KEY,
        }
        return {row.key: row.value for row in db.execute(select(Setting).where(Setting.key.in_(keys))).scalars().all()}
    except SQLAlchemyError:
        return None


def _read_logging_preferences(db: Session | None) -> LoggingPreferences | None:
    """Read preferences, returning ``None`` when a database read failed.

    Args:
        db: Active database session.
    """
    values = _setting_map(db)
    if values is None:
        return None
    return LoggingPreferences(
        level=_normalize_level(values.get(LOGGING_LEVEL_KEY)),
        syslog_enabled=_normalize_bool(values.get(LOGGING_SYSLOG_ENABLED_KEY)),
        syslog_host=(values.get(LOGGING_SYSLOG_HOST_KEY) or "").strip(),
        syslog_port=_normalize_port(values.get(LOGGING_SYSLOG_PORT_KEY)),
        syslog_protocol=_normalize_protocol(values.get(LOGGING_SYSLOG_PROTOCOL_KEY)),
        syslog_facility=_normalize_facility(values.get(LOGGING_SYSLOG_FACILITY_KEY)),
        syslog_level=_normalize_level(values.get(LOGGING_SYSLOG_LEVEL_KEY)),
    )


def logging_preferences_from_db(db: Session | None) -> LoggingPreferences:
    """Return logging preferences from db.

    Args:
        db: Active database session.
    """
    return _read_logging_preferences(db) or LoggingPreferences()


def _set_setting(db: Session, key: str, value: str) -> Setting:
    """Update setting.

    Args:
        db: Active database session.
        key: Stable setting, vault, or mapping key.
        value: Value to process.

    Returns:
        The set setting result.
    """
    setting = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
    if setting is None:
        setting = Setting(key=key, value=value)
        db.add(setting)
    else:
        setting.value = value
        setting.updated_at = utcnow()
    return setting


def save_logging_preferences(
    db: Session,
    *,
    level: str,
    syslog_enabled: bool,
    syslog_host: str,
    syslog_port: str | int,
    syslog_protocol: str,
    syslog_facility: str,
    syslog_level: str,
) -> LoggingPreferences:
    """Persist logging preferences.

    Args:
        db: Active database session.
        level: Level supplied by the caller.
        syslog_enabled: Syslog enabled supplied by the caller.
        syslog_host: Syslog host supplied by the caller.
        syslog_port: Syslog port supplied by the caller.
        syslog_protocol: Syslog protocol supplied by the caller.
        syslog_facility: Syslog facility supplied by the caller.
        syslog_level: Syslog level supplied by the caller.

    Returns:
        The save logging preferences result.

    Raises:
        ValueError: If an input value is invalid.
    """
    preferences = LoggingPreferences(
        level=_normalize_level(level),
        syslog_enabled=bool(syslog_enabled),
        syslog_host=syslog_host.strip(),
        syslog_port=_normalize_port(syslog_port),
        syslog_protocol=_normalize_protocol(syslog_protocol),
        syslog_facility=_normalize_facility(syslog_facility),
        syslog_level=_normalize_level(syslog_level),
    )
    if preferences.syslog_enabled and not preferences.syslog_host:
        raise ValueError("External syslog host is required when syslog forwarding is enabled.")
    for key, value in {
        LOGGING_LEVEL_KEY: preferences.level,
        LOGGING_SYSLOG_ENABLED_KEY: "true" if preferences.syslog_enabled else "false",
        LOGGING_SYSLOG_HOST_KEY: preferences.syslog_host,
        LOGGING_SYSLOG_PORT_KEY: str(preferences.syslog_port),
        LOGGING_SYSLOG_PROTOCOL_KEY: preferences.syslog_protocol,
        LOGGING_SYSLOG_FACILITY_KEY: preferences.syslog_facility,
        LOGGING_SYSLOG_LEVEL_KEY: preferences.syslog_level,
    }.items():
        _set_setting(db, key, value)
    db.flush()
    return preferences


def logging_preferences_to_dict(preferences: LoggingPreferences) -> dict[str, Any]:
    """Return logging preferences to dict.

    Args:
        preferences: Preferences consumed by logging preferences to dict.
    """
    return {
        "level": preferences.level,
        "levels": LOG_LEVELS,
        "syslog_enabled": preferences.syslog_enabled,
        "syslog_host": preferences.syslog_host,
        "syslog_port": preferences.syslog_port,
        "syslog_protocol": preferences.syslog_protocol,
        "syslog_protocols": SYSLOG_PROTOCOLS,
        "syslog_facility": preferences.syslog_facility,
        "syslog_facilities": SYSLOG_FACILITIES,
        "syslog_level": preferences.syslog_level,
    }


def _handler_is_file(handler: logging.Handler) -> bool:
    """Return handler is file.

    Args:
        handler: Handler consumed by handler is file.
    """
    return bool(getattr(handler, "_atlaso_file_handler", False))


def _handler_is_syslog(handler: logging.Handler) -> bool:
    """Return handler is syslog.

    Args:
        handler: Handler consumed by handler is syslog.
    """
    return bool(getattr(handler, "_atlaso_syslog_handler", False))


def _remove_handlers(predicate) -> None:
    """Remove handlers.

    Args:
        predicate: Predicate consumed by remove handlers.
    """
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if not predicate(handler):
            continue
        root_logger.removeHandler(handler)
        handler.close()


def _level_number(level: str) -> int:
    """Return level number.

    Args:
        level: Level consumed by level number.
    """
    return int(getattr(logging, _normalize_level(level), logging.INFO))


class _OperationalRedactionState:
    """Share parser state across handlers that emit the same process records."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.parser: dict[str, str] = {}
        self.private = False


class _OperationalRedactionFilter(logging.Filter):
    """Sanitize handler records using shared, synchronized private-key state."""

    def __init__(self, destination_level: int, state: _OperationalRedactionState | None = None) -> None:
        """Create an output filter with destination-specific level and shared parser state.

        Args:
            destination_level: Minimum level emitted by this destination.
            state: Parser state shared with other Atlaso output handlers.
        """
        super().__init__()
        self.destination_level = destination_level
        self._state = state or _OperationalRedactionState()

    def filter(self, record: logging.LogRecord) -> bool | logging.LogRecord:
        """Return a sanitized record, consuming lower-level records to keep parser state.

        Args:
            record: Candidate log record dispatched to the output handler.
        """
        with self._state.lock:
            safe_record = copy.copy(record)
            cache = record.__dict__.get("_atlaso_redacted_messages")
            if not isinstance(cache, dict):
                cache = {}
            state_key = id(self._state)
            if state_key not in cache:
                try:
                    message = record.getMessage()
                except (AttributeError, IndexError, KeyError, TypeError, ValueError):
                    message = "[log message formatting failed]"
                lines, self._state.private = _safe_lines(
                    [message],
                    self._state.private,
                    self._state.parser,
                )
                safe_message = "\n".join(lines)
                if record.exc_info and record.exc_info[0] is not None:
                    exception_name = record.exc_info[0].__name__
                    if not exception_name.isascii() or not exception_name.isidentifier():
                        exception_name = "Error"
                    safe_message = f"{safe_message} exception_type={exception_name}"
                cache[state_key] = safe_message
                record.__dict__["_atlaso_redacted_messages"] = cache
            else:
                safe_message = cache[state_key]
            safe_record.msg = safe_message
            safe_record.args = ()
            safe_record.exc_info = None
            safe_record.exc_text = None
            safe_record.stack_info = None
            if record.levelno < self.destination_level:
                return False
            return safe_record


class _HistoryFileHandler(RotatingFileHandler):
    """Capture App records synchronously before mirroring them to the existing file."""

    def __init__(self, log_path: Path, history_path: Path, writer: str) -> None:
        """Bind a prepared store and the fixed process writer slot.

        Args:
            log_path: Existing rotating operational log path.
            history_path: Prepared private producer history store.
            writer: Fixed web or worker producer identity.
        """
        super().__init__(log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
        self.history_path = history_path
        self.writer = writer

    def emit(self, record: logging.LogRecord) -> None:
        """Require durable capture before acknowledging an operational record.

        Args:
            record: Newly emitted Python logging event.
        """
        from atlaso.app.services.producer_log_history import capture_record

        capture_record(self.history_path, self.writer, record, self.formatter or FORMATTER)
        super().emit(record)


def _redaction_filter(handler: logging.Handler | None) -> _OperationalRedactionFilter | None:
    """Find the operational redaction filter attached to a handler.

    Args:
        handler: Output handler to inspect.
    """
    if handler is None:
        return None
    return next((item for item in handler.filters if isinstance(item, _OperationalRedactionFilter)), None)


def _set_destination_level(
    handler: logging.Handler,
    destination_level: int,
    state: _OperationalRedactionState | None = None,
) -> None:
    """Update a destination threshold without resetting redaction state.

    Args:
        handler: Output handler to update.
        destination_level: Threshold selected for this destination.
        state: Shared parser state for an output handler replacement.
    """
    # Receive every Atlaso record so filtered low-level PEM markers still update
    # the stateful sanitizer before the destination threshold is applied.
    handler.setLevel(logging.DEBUG)
    redactor = _redaction_filter(handler)
    if redactor is None:
        redactor = _OperationalRedactionFilter(destination_level, state)
        handler.addFilter(redactor)
    else:
        with redactor._state.lock:
            redactor.destination_level = destination_level


def _ensure_file_handler(
    log_path: Path,
    level: int,
    history_path: Path | None = None,
    writer: str = "web",
) -> None:
    """Ensure file handler.

    Args:
        log_path: Filesystem path used for log.
        level: Minimum file destination level.
        history_path: Optional prepared producer store; absent until explicit capture cutover.
        writer: Fixed process writer slot for producer capture.
    """
    root_logger = logging.getLogger()
    previous_handler: logging.Handler | None = None
    previous_redactor: _OperationalRedactionFilter | None = None
    for handler in list(root_logger.handlers):
        if not _handler_is_file(handler):
            continue
        if (Path(getattr(handler, "baseFilename", "")) == log_path
                and getattr(handler, "history_path", None) == history_path
                and getattr(handler, "writer", "web") == writer):
            _set_destination_level(handler, level)
            return
        previous_handler = handler
        previous_redactor = _redaction_filter(handler)
    if previous_redactor is None:
        previous_redactor = _redaction_filter(
            next((handler for handler in root_logger.handlers if _handler_is_syslog(handler)), None)
        )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = (_HistoryFileHandler(log_path, history_path, writer) if history_path is not None
               else RotatingFileHandler(log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"))
    handler.setFormatter(FORMATTER)
    _set_destination_level(handler, level, previous_redactor._state if previous_redactor is not None else None)
    handler._atlaso_file_handler = True  # type: ignore[attr-defined]  # Atlaso adds a private runtime marker to Handler.
    root_logger.addHandler(handler)
    if previous_handler is not None:
        root_logger.removeHandler(previous_handler)
        previous_handler.close()


def _ensure_syslog_handler(preferences: LoggingPreferences) -> bool:
    """Ensure syslog handler.

    Args:
        preferences: Preferences consumed by ensure syslog handler.
    Returns:
        The ensure syslog handler result.
    """
    if not preferences.syslog_enabled or not preferences.syslog_host:
        _remove_handlers(_handler_is_syslog)
        return False
    signature = (
        preferences.syslog_host,
        preferences.syslog_port,
        preferences.syslog_protocol,
        preferences.syslog_facility,
    )
    existing = next((handler for handler in logging.getLogger().handlers if _handler_is_syslog(handler)), None)
    if existing is not None and getattr(existing, "_atlaso_syslog_configuration", None) == signature:
        _set_destination_level(existing, _level_number(preferences.syslog_level))
        return True
    previous_redactor = _redaction_filter(existing) if existing is not None else _redaction_filter(
        next((handler for handler in logging.getLogger().handlers if _handler_is_file(handler)), None)
    )
    socktype = socket.SOCK_STREAM if preferences.syslog_protocol == "tcp" else socket.SOCK_DGRAM
    facility = SysLogHandler.facility_names.get(preferences.syslog_facility, SysLogHandler.LOG_LOCAL0)
    handler = SysLogHandler(address=(preferences.syslog_host, preferences.syslog_port), facility=facility, socktype=socktype)
    handler.setFormatter(_BoundedFormatter("atlaso %(levelname)s [%(name)s] %(message)s"))
    _set_destination_level(
        handler,
        _level_number(preferences.syslog_level),
        previous_redactor._state if previous_redactor is not None else None,
    )
    handler._atlaso_syslog_configuration = signature  # type: ignore[attr-defined]  # Atlaso tracks its owned handler configuration.
    handler._atlaso_syslog_handler = True  # type: ignore[attr-defined]  # Atlaso adds a private runtime marker to Handler.
    logging.getLogger().addHandler(handler)
    if existing is not None:
        logging.getLogger().removeHandler(existing)
        existing.close()
    return True


def _configuration_signature(preferences: LoggingPreferences, settings: Any, writer: str) -> tuple[object, ...]:
    """Return the normalized process logging configuration identity.

    Args:
        preferences: Validated logging preferences.
        settings: Current application settings.
        writer: Fixed producer identity used for history capture.
    """
    return (
        preferences,
        str(settings.app_log_path),
        str(settings.app_log_history_path),
        writer,
    )


def _apply_logging_preferences(
    preferences: LoggingPreferences,
    settings: Any,
    writer: str,
) -> LoggingPreferences:
    """Apply one normalized preference snapshot under the process configuration lock.

    Args:
        preferences: Current normalized logging preferences.
        settings: Current application path settings.
        writer: Fixed process producer identity when history capture is enabled.

    Returns:
        The applied logging preferences.
    """
    signature = _configuration_signature(preferences, settings, writer)
    global _APPLIED_CONFIGURATION
    with _CONFIGURATION_LOCK:
        if _APPLIED_CONFIGURATION == signature:
            return preferences
        file_level = _level_number(preferences.level)
        logging.getLogger("atlaso").setLevel(logging.DEBUG)
        try:
            _ensure_file_handler(
                settings.app_log_path,
                file_level,
                settings.app_log_history_path,
                writer,
            )
        except OSError:
            logging.getLogger("atlaso").error(
                "event=operational_logging_initialization_failed destination=file error_code=file_handler_unavailable"
            )
            return preferences
        configuration_succeeded = True
        try:
            syslog_configured = _ensure_syslog_handler(preferences)
        except OSError:
            logging.getLogger("atlaso").warning(
                "event=operational_logging_initialization_failed destination=syslog error_code=syslog_handler_unavailable"
            )
            syslog_configured = False
            configuration_succeeded = False
        if configuration_succeeded:
            _APPLIED_CONFIGURATION = signature
        LOGGER.info(
            "Atlaso operational logging configured level=%s syslog=%s",
            preferences.level,
            "enabled" if syslog_configured else "disabled",
        )
        return preferences


def configure_operational_logging(db: Session | None = None, *, writer: str = "web") -> LoggingPreferences:
    """Update operational logging.

    Args:
        db: Active database session.
        writer: Fixed process producer identity when history capture is enabled.

    Returns:
        The configure operational logging result.
    """
    settings = get_settings()
    preferences = logging_preferences_from_db(db)
    return _apply_logging_preferences(preferences, settings, writer)


def refresh_logging_preferences(db: Session | None, *, writer: str = "web") -> LoggingPreferences:
    """Apply persisted preference changes without rebuilding handlers on each refresh.

    Args:
        db: Active database session used to read current settings.
        writer: Fixed process producer identity when history capture is enabled.

    Returns:
        The latest available logging preferences. A failed database read preserves
        the last applied preferences and handlers.
    """
    preferences = _read_logging_preferences(db)
    if preferences is None:
        with _CONFIGURATION_LOCK:
            if _APPLIED_CONFIGURATION is not None:
                cached = _APPLIED_CONFIGURATION[0]
                if isinstance(cached, LoggingPreferences):
                    return cached
        return LoggingPreferences()
    settings = get_settings()
    signature = _configuration_signature(preferences, settings, writer)
    with _CONFIGURATION_LOCK:
        if _APPLIED_CONFIGURATION == signature:
            return preferences
    return _apply_logging_preferences(preferences, settings, writer)


def log_audit_event(event: Any) -> None:
    """Handle log audit event.

    Args:
        event: Event consumed by log audit event.
    """
    detail = redact_operational_text(getattr(event, "detail", "") or "").replace("\n", " | ")
    resource_id = getattr(event, "resource_id", None) or ""
    request_id = getattr(event, "request_id", None) or ""
    LOGGER.info(
        "audit actor=%s action=%s resource=%s resource_id=%s success=%s request_id=%s%s",
        getattr(event, "actor", ""),
        getattr(event, "action", ""),
        getattr(event, "resource_type", ""),
        resource_id,
        bool(getattr(event, "success", False)),
        request_id,
        f" detail={detail}" if detail else "",
    )
    if detail:
        LOGGER.debug(
            "audit.detail action=%s resource=%s resource_id=%s detail=%s",
            getattr(event, "action", ""),
            getattr(event, "resource_type", ""),
            resource_id,
            detail,
        )
