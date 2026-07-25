from __future__ import annotations

from dataclasses import dataclass
import logging
from logging.handlers import RotatingFileHandler, SysLogHandler
import re
import socket
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from atlaso.app.config import get_settings
from atlaso.app.models import Setting, utcnow

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
FORMATTER = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

SECRET_LINE_PATTERN = re.compile(
    r"(rootpw|password|passwd|token|secret|credential|private[_-]?key|robot[_-]?account|ca[_-]?bundle[_-]?pem|activation[_-]?code|license|ipxe[_-]?script|payload[_-]?b64)",
    re.IGNORECASE,
)
PRIVATE_KEY_BEGIN_PATTERN = re.compile(r"-----BEGIN .*PRIVATE KEY-----")
PRIVATE_KEY_END_PATTERN = re.compile(r"-----END .*PRIVATE KEY-----")
JWT_PATH_SEGMENT_PATTERN = re.compile(r"(?<=/)[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?=/|$)")
JSON_SECRET_FIELD_PATTERN = re.compile(r'^(\s*"[^"]+"\s*:\s*)(.*?)(,?)\s*$')


@dataclass(frozen=True)
class LoggingPreferences:
    level: str = "INFO"
    syslog_enabled: bool = False
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_protocol: str = "udp"
    syslog_facility: str = "local0"
    syslog_level: str = "INFO"


def _normalize_level(value: str | None, *, default: str = "INFO") -> str:
    normalized = (value or default).strip().upper()
    return normalized if normalized in LOG_LEVELS else default


def _normalize_bool(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _normalize_port(value: str | int | None) -> int:
    try:
        port = int(value or 514)
    except (TypeError, ValueError):
        return 514
    return port if 1 <= port <= 65535 else 514


def _normalize_protocol(value: str | None) -> str:
    protocol = (value or "udp").strip().lower()
    return protocol if protocol in SYSLOG_PROTOCOLS else "udp"


def _normalize_facility(value: str | None) -> str:
    facility = (value or "local0").strip().lower()
    return facility if facility in SYSLOG_FACILITIES else "local0"


def _setting_map(db: Session | None) -> dict[str, str]:
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
        return {}


def logging_preferences_from_db(db: Session | None) -> LoggingPreferences:
    values = _setting_map(db)
    return LoggingPreferences(
        level=_normalize_level(values.get(LOGGING_LEVEL_KEY)),
        syslog_enabled=_normalize_bool(values.get(LOGGING_SYSLOG_ENABLED_KEY)),
        syslog_host=(values.get(LOGGING_SYSLOG_HOST_KEY) or "").strip(),
        syslog_port=_normalize_port(values.get(LOGGING_SYSLOG_PORT_KEY)),
        syslog_protocol=_normalize_protocol(values.get(LOGGING_SYSLOG_PROTOCOL_KEY)),
        syslog_facility=_normalize_facility(values.get(LOGGING_SYSLOG_FACILITY_KEY)),
        syslog_level=_normalize_level(values.get(LOGGING_SYSLOG_LEVEL_KEY)),
    )


def _set_setting(db: Session, key: str, value: str) -> Setting:
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
    return bool(getattr(handler, "_atlaso_file_handler", False))


def _handler_is_syslog(handler: logging.Handler) -> bool:
    return bool(getattr(handler, "_atlaso_syslog_handler", False))


def _remove_handlers(predicate) -> None:
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if not predicate(handler):
            continue
        root_logger.removeHandler(handler)
        handler.close()


def _level_number(level: str) -> int:
    return int(getattr(logging, _normalize_level(level), logging.INFO))


def _ensure_file_handler(log_path: Path, level: int) -> None:
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if not _handler_is_file(handler):
            continue
        if Path(getattr(handler, "baseFilename", "")) == log_path:
            handler.setLevel(level)
            return
        root_logger.removeHandler(handler)
        handler.close()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
    handler.setFormatter(FORMATTER)
    handler.setLevel(level)
    handler._atlaso_file_handler = True  # type: ignore[attr-defined]
    root_logger.addHandler(handler)


def _ensure_syslog_handler(preferences: LoggingPreferences) -> bool:
    _remove_handlers(_handler_is_syslog)
    if not preferences.syslog_enabled or not preferences.syslog_host:
        return False
    socktype = socket.SOCK_STREAM if preferences.syslog_protocol == "tcp" else socket.SOCK_DGRAM
    facility = SysLogHandler.facility_names.get(preferences.syslog_facility, SysLogHandler.LOG_LOCAL0)
    handler = SysLogHandler(address=(preferences.syslog_host, preferences.syslog_port), facility=facility, socktype=socktype)
    handler.setFormatter(logging.Formatter("atlaso %(levelname)s [%(name)s] %(message)s"))
    handler.setLevel(_level_number(preferences.syslog_level))
    handler._atlaso_syslog_handler = True  # type: ignore[attr-defined]
    logging.getLogger().addHandler(handler)
    return True


def configure_operational_logging(db: Session | None = None) -> LoggingPreferences:
    settings = get_settings()
    preferences = logging_preferences_from_db(db)
    root_logger = logging.getLogger()
    file_level = _level_number(preferences.level)
    root_logger.setLevel(min(file_level, _level_number(preferences.syslog_level) if preferences.syslog_enabled else file_level))
    try:
        _ensure_file_handler(settings.app_log_path, file_level)
    except OSError:
        logging.getLogger("atlaso").exception("Unable to initialize Atlaso app log at %s", settings.app_log_path)
        return preferences
    try:
        syslog_configured = _ensure_syslog_handler(preferences)
    except OSError as exc:
        _remove_handlers(_handler_is_syslog)
        logging.getLogger("atlaso").warning("Unable to initialize external syslog forwarding: %s", exc)
        syslog_configured = False
    LOGGER.info(
        "Atlaso operational logging configured file=%s level=%s syslog=%s",
        settings.app_log_path,
        preferences.level,
        "enabled" if syslog_configured else "disabled",
    )
    return preferences


def redact_operational_text(value: str | None) -> str:
    lines: list[str] = []
    in_private_key = False
    for line in (value or "").splitlines():
        if PRIVATE_KEY_BEGIN_PATTERN.search(line):
            lines.append("[redacted private key]")
            in_private_key = True
            continue
        if in_private_key:
            if PRIVATE_KEY_END_PATTERN.search(line):
                in_private_key = False
            continue
        if SECRET_LINE_PATTERN.search(line):
            json_match = JSON_SECRET_FIELD_PATTERN.match(line)
            if json_match:
                lines.append(f'{json_match.group(1)}"[redacted]"{json_match.group(3)}')
                continue
            separator = "=" if "=" in line else ":" if ":" in line else None
            if separator:
                prefix = line.split(separator, 1)[0].rstrip()
                lines.append(f"{prefix}{separator} [redacted]")
            else:
                lines.append("[redacted sensitive line]")
            continue
        lines.append(JWT_PATH_SEGMENT_PATTERN.sub("[redacted-token]", line))
    return "\n".join(lines)


def log_audit_event(event: Any) -> None:
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
