"""Fail-closed checks for the predeployment certificate routing-intent evidence."""

import sqlite3

import pytest

from scripts.interop.certificate_source_probe import snapshot


@pytest.fixture
def source_database(tmp_path):
    path = tmp_path / "atlaso.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE routes (id INTEGER PRIMARY KEY);
            CREATE TABLE routing_rules (id INTEGER PRIMARY KEY);
            CREATE TABLE nat_rules (id INTEGER PRIMARY KEY);
            CREATE TABLE port_forwards (id INTEGER PRIMARY KEY);
            CREATE TABLE wan_policies (id INTEGER PRIMARY KEY);
            CREATE TABLE physical_interfaces (id INTEGER PRIMARY KEY, role TEXT);
            CREATE TABLE vlan_interfaces (id INTEGER PRIMARY KEY, role TEXT);
            CREATE TABLE settings (key TEXT, value TEXT);
            CREATE TABLE service_states (service TEXT, enabled INTEGER, running INTEGER);
            """
        )
    return path


def test_empty_source_proves_absence_without_exposing_rows(source_database):
    result = snapshot(str(source_database))
    assert result["state"] == "proven-absent"
    assert set(result["counts"].values()) == {0}
    assert set(result["settings"].values()) == {None}
    assert result["routing_service"] is None
    assert set(result) == {"schema", "database", "state", "counts", "settings", "routing_service"}


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("INSERT INTO routes VALUES (1)", "routes"),
        ("INSERT INTO nat_rules VALUES (1)", "nat_rules"),
        ("INSERT INTO port_forwards VALUES (1)", "port_forwards"),
        ("INSERT INTO physical_interfaces VALUES (1, 'route')", "route_physical_interfaces"),
        ("INSERT INTO vlan_interfaces VALUES (1, 'route')", "route_vlan_interfaces"),
        ("INSERT INTO settings VALUES ('routes_wan.routing_enabled', 'true')", "routes_wan.routing_enabled"),
        ("INSERT INTO settings VALUES ('traffic_publishing.nat_enabled', 'yes')", "traffic_publishing.nat_enabled"),
        ("INSERT INTO service_states VALUES ('routing', 1, 0)", "routing_service"),
    ],
)
def test_any_route_domain_intent_refuses_absence(source_database, statement, expected):
    with sqlite3.connect(source_database) as connection:
        connection.execute(statement)
    result = snapshot(str(source_database))
    assert result["state"] == "present"
    if expected in result["counts"]:
        assert result["counts"][expected] == 1
    elif expected in result["settings"]:
        assert result["settings"][expected] is True
    else:
        assert result["routing_service"]["enabled"] is True


def test_missing_schema_and_unknown_setting_fail_closed(source_database):
    with sqlite3.connect(source_database) as connection:
        connection.execute("DROP TABLE routing_rules")
    with pytest.raises(ValueError, match="schema"):
        snapshot(str(source_database))

    with sqlite3.connect(source_database) as connection:
        connection.execute("CREATE TABLE routing_rules (id INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO settings VALUES ('routes_wan.routing_enabled', 'maybe')")
    with pytest.raises(ValueError, match="setting"):
        snapshot(str(source_database))
