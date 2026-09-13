"""Sanitize task values independently of the UI route facade."""

import re
from typing import Any

TASK_SECRET_KEY_RE = re.compile(r"(password|passwd|secret|token|credential|authorization|activation|private[_-]?key|api[_-]?key|payload[_-]?b64)", re.IGNORECASE)
TASK_SECRET_VALUE_RE = re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-[A-Za-z0-9_-]{16,}|Bearer\s+[A-Za-z0-9._-]{12,})", re.IGNORECASE)
TASK_INLINE_SECRET_RE = re.compile(
    r"(?P<label>\b[a-z0-9_-]*(?:password|passwd|secret|token|credential|authorization|activation|private[_-]?key|api[_-]?key|payload[_-]?b64)\b)"
    r"(?P<separator>\s*(?:=|:)\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;]+)",
    re.IGNORECASE,
)


def redact_task_value(value: Any, *, key: str = "") -> Any:
    """Redact secret keys and recognized credential text recursively.

    Args:
        value: Task result value or audit detail to sanitize.
        key: Stable key identifying the setting, secret, or mapping entry.
    """
    if key and TASK_SECRET_KEY_RE.search(key):
        return "[redacted]"
    if isinstance(value, dict):
        return {str(item_key): redact_task_value(item_value, key=str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact_task_value(item) for item in value]
    if isinstance(value, str):
        if TASK_SECRET_VALUE_RE.search(value):
            return "[redacted]"
        return TASK_INLINE_SECRET_RE.sub(lambda match: f"{match.group('label')}{match.group('separator')}[redacted]", value)
    return value

