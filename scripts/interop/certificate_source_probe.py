"""Read-only, allowlisted predeployment routing-intent snapshot for a lifecycle clone.

Run as root inside the cloned guest before syncing the lifecycle helper or wheel.
Only aggregate counts and feature flags leave the guest; no database rows or secrets do.
"""

from __future__ import annotations

import json
import sqlite3
import sys

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


def snapshot(database: str = DATABASE) -> dict[str, object]:
    """Return absence proof from one read-only SQLite transaction, or fail closed.

    Args:
        database: Path to the cloned guest's SQLite database.
    """
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        required = {*TABLES, "physical_interfaces", "vlan_interfaces", "settings", "service_states"}
        existing = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if not required.issubset(existing):
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


def main() -> int:
    try:
        result = snapshot()
    except (OSError, sqlite3.Error, ValueError):
        return 2
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
