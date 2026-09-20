"""Bounded unsigned producer pages behind the helper's fixed-source boundary."""

from __future__ import annotations

import json
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from atlaso.app.services.producer_log_history import read_page, read_tail, source_active

STORE_PATHS = {
    "nginx-access": Path("/var/lib/atlaso-privileged/log-history/nginx.sqlite"),
    "nginx-error": Path("/var/lib/atlaso-privileged/log-history/nginx.sqlite"),
    "kms": Path("/var/lib/atlaso-kmip-log-history/history.sqlite"),
}
ACTIVATION_PATHS = {
    "nginx-access": Path("/var/lib/atlaso-privileged/log-history/nginx-state.json"),
    "nginx-error": Path("/var/lib/atlaso-privileged/log-history/nginx-state.json"),
    "kms": Path("/etc/atlaso/kmip/history.env"),
}
MAX_RESPONSE_BYTES = 1024 * 1024


def producer_page(source: str, position: dict[str, object]) -> dict[str, object]:
    """Read only a fixed store and return rows for application-side cursor signing.

    Args:
        source: Allowlisted external producer identifier.
        position: Unsigned position decoded and authenticated by the application.
    """
    if source not in STORE_PATHS or set(position) - {
            "transport", "after", "through", "before", "generation", "limit", "tail", "metadata"}:
        raise ValueError("Invalid external producer position.")
    if position.get("transport") != "producer":
        raise ValueError("Invalid external producer transport.")
    if "metadata" in position and (type(position["metadata"]) is not bool or
                                   set(position) != {"transport", "metadata"}):
        raise ValueError("Invalid external producer metadata request.")
    for key in ("after", "through", "before", "limit"):
        value = position.get(key)
        if key in position and (not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**63):
            raise ValueError("Invalid external producer boundary.")
    limit = position.get("limit", 500)
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("Invalid external producer page limit.")
    generation = position.get("generation")
    if generation is not None and (
            not isinstance(generation, str) or len(generation) != 32 or
            any(character not in "0123456789abcdef" for character in generation)):
        raise ValueError("Invalid external producer generation.")
    if "tail" in position and type(position["tail"]) is not bool:
        raise ValueError("Invalid external producer direction.")
    if "before" in position and any(key in position for key in ("after", "through")):
        raise ValueError("Conflicting external producer boundaries.")
    path = STORE_PATHS[source]
    if not path.exists():
        if ACTIVATION_PATHS[source].exists():
            raise ValueError("Selected external producer store is unavailable.")
        return {"active": False}
    if path.is_symlink() or not path.is_file():
        raise ValueError("Invalid external producer store.")
    if not source_active(path, source):
        if ACTIVATION_PATHS[source].exists():
            raise ValueError("External producer cutover is incomplete.")
        return {"active": False}
    if position.get("metadata"):
        return {"active": True}
    before, after, through = position.get("before"), position.get("after", 0), position.get("through")
    if not isinstance(after, int) or (before is not None and not isinstance(before, int)) or (
            through is not None and not isinstance(through, int)):
        raise ValueError("Invalid external producer boundaries.")
    backward = bool(position.get("tail")) or before is not None
    if backward:
        page = read_tail(path, source, before=before, generation=generation, limit=limit)
    else:
        page = read_page(path, source, after=after, through=through, generation=generation, limit=limit)
    result: dict[str, Any] = {"active": True, **asdict(page)}
    # JSON escaping must fit the wire bound as well as decoded producer bytes.
    while len(json.dumps(result, ensure_ascii=False).encode("utf-8")) + 1 > MAX_RESPONSE_BYTES:
        if len(result["lines"]) <= 1:
            raise ValueError("External producer record exceeds the response bound.")
        if backward:
            result["lines"] = result["lines"][1:]
            result["start"] += 1
        else:
            result["lines"] = result["lines"][:-1]
            result["after"] -= 1
            result["more"] = True
    return result


def main(argv: list[str] | None = None) -> int:
    """Serve the helper's fixed, bounded read-only subprocess request.

    Args:
        argv: Exact source and JSON position, or the process arguments.
    """
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2 or len(arguments[1]) > 4096:
        return 2
    try:
        position = json.loads(arguments[1])
        if not isinstance(position, dict):
            return 2
        result = producer_page(arguments[0], position)
    except (ValueError, OSError, sqlite3.Error):
        print("External producer history is unavailable.", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
