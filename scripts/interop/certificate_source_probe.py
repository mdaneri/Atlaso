"""Read-only, allowlisted predeployment routing-intent snapshot for a lifecycle clone.

Run as root inside the cloned guest before syncing the lifecycle helper or wheel.
Only aggregate counts and feature flags leave the guest; no database rows or secrets do.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

DATABASE = "/var/lib/atlaso/atlaso.db"
TABLES = (
    "routes",
    "routing_rules",
    "nat_rules",
    "port_forwards",
    "wan_policies",
)
SETTING_KEYS = (
    "routes_wan.routing_enabled",
    "routes_wan.wan_simulation_enabled",
    "routes_wan.nat_enabled",
    "traffic_publishing.nat_enabled",
)
REQUIRED_TABLES = frozenset((*TABLES, "physical_interfaces", "vlan_interfaces", "settings", "service_states"))


def wait_for_schema(database: str, timeout_seconds: int) -> bool:
    """Wait read-only for first boot to publish the complete source schema.

    This establishes readiness only. The strict intent snapshot must still run
    afterward; missing tables never establish routing absence.

    Args:
        database: Original source database, never opened in create mode.
        timeout_seconds: Explicit bounded fixture-bootstrap wait, from 1 to 120.
    """
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
        raise ValueError("schema readiness timeout outside fixture bounds")
    deadline = time.monotonic() + timeout_seconds
    while (remaining := deadline - time.monotonic()) > 0:
        if Path(database).is_file():
            connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=min(5, remaining))
            try:
                connection.execute("PRAGMA query_only = ON")
                existing = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
                if REQUIRED_TABLES.issubset(existing):
                    return True
            finally:
                connection.close()
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))
    return False


def snapshot(database: str = DATABASE) -> dict[str, object]:
    """Return absence proof from one read-only SQLite transaction, or fail closed.

    Args:
        database: Path to the cloned guest's SQLite database.
    """
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        existing = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not REQUIRED_TABLES.issubset(existing):
            raise ValueError("required routing schema missing")
        counts = {table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in TABLES}
        counts["route_physical_interfaces"] = connection.execute(
            "SELECT count(*) FROM physical_interfaces WHERE lower(trim(role)) = 'route'"
        ).fetchone()[0]
        counts["route_vlan_interfaces"] = connection.execute(
            "SELECT count(*) FROM vlan_interfaces WHERE lower(trim(role)) = 'route'"
        ).fetchone()[0]
        settings: dict[str, bool | None] = {}
        for key in SETTING_KEYS:
            rows = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchall()
            if len(rows) > 1:
                raise ValueError("duplicate routing setting")
            if not rows:
                settings[key] = None
            else:
                value = rows[0][0]
                if not isinstance(value, str) or value.strip().lower() not in {"true", "false", "1", "0", "on", "off", "yes", "no"}:
                    raise ValueError("unrecognized routing setting")
                settings[key] = value.strip().lower() in {"true", "1", "on", "yes"}
        services = connection.execute(
            "SELECT enabled, running FROM service_states WHERE service = 'routing'"
        ).fetchall()
        if len(services) > 1:
            raise ValueError("duplicate routing service")
        service = None if not services else {"enabled": bool(services[0][0]), "running": bool(services[0][1])}
        connection.execute("ROLLBACK")
    finally:
        connection.close()
    if any(not isinstance(value, int) or value < 0 for value in counts.values()):
        raise ValueError("invalid routing count")
    absent = not any(counts.values()) and not any(value is True for value in settings.values()) and (
        service is None or not service["enabled"] and not service["running"]
    )
    return {
        "schema": 1,
        "database": DATABASE,
        "state": "proven-absent" if absent else "present",
        "counts": counts,
        "settings": settings,
        "routing_service": service,
    }


def main(argv: list[str] | None = None) -> int:
    """Read strict source facts, with an explicit NTP fixture startup wait.

    Args:
        argv: Explicit CLI arguments; ordinary callers retain immediate strict inspection.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait-for-schema-seconds", type=int)
    args = parser.parse_args([] if argv is None else argv)
    try:
        if args.wait_for_schema_seconds is not None and not wait_for_schema(DATABASE, args.wait_for_schema_seconds):
            return 2
        result = snapshot(DATABASE)
    except (OSError, sqlite3.Error, ValueError):
        return 2
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
