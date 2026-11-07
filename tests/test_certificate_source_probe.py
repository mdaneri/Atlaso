"""Fail-closed checks for the predeployment certificate routing-intent evidence."""

import json
import sqlite3

import pytest

from scripts.interop import certificate_source_probe as probe
from scripts.interop.certificate_source_probe import snapshot


@pytest.fixture
def source_database(tmp_path):
    """Create a minimal source database for routing-intent probes.

    Args:
        tmp_path: Temporary directory supplied by pytest.
    """
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
    """Report absence without returning database rows.

    Args:
        source_database: Minimal source database fixture.
    """
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
    """Reject absence whenever an allowlisted routing signal is present.

    Args:
        source_database: Minimal source database fixture.
        statement: SQL statement that adds one routing signal.
        expected: Aggregate signal expected in the probe output.
    """
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
    """Reject incomplete schemas and unrecognized routing settings.

    Args:
        source_database: Minimal source database fixture.
    """
    with sqlite3.connect(source_database) as connection:
        connection.execute("DROP TABLE routing_rules")
    with pytest.raises(ValueError, match="schema"):
        snapshot(str(source_database))

    with sqlite3.connect(source_database) as connection:
        connection.execute("CREATE TABLE routing_rules (id INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO settings VALUES ('routes_wan.routing_enabled', 'maybe')")
    with pytest.raises(ValueError, match="setting"):
        snapshot(str(source_database))


@pytest.mark.parametrize("partial", [False, True], ids=["database-not-created", "schema-not-complete"])
def test_explicit_bootstrap_wait_requires_complete_schema_before_intent_snapshot(
    tmp_path, source_database, monkeypatch, capsys, partial,
):
    """Readiness waits for application-created state and retains any existing intent.

    Args:
        tmp_path: Temporary directory for the target database path.
        source_database: Complete source database copied when the wait is released.
        monkeypatch: Patcher for the probe database path and readiness delay.
        capsys: Capture fixture used to read the bounded JSON result.
        partial: Whether to create a database with an incomplete schema first.
    """
    target = tmp_path / "starting.db"
    if partial:
        with sqlite3.connect(target) as connection:
            connection.execute("CREATE TABLE routes (id INTEGER PRIMARY KEY)")
            connection.execute("INSERT INTO routes VALUES (1)")
    monkeypatch.setattr(probe, "DATABASE", str(target))
    waits = []

    def application_finishes_schema(_delay):
        """Copy the complete application-created schema into the target database.

        Args:
            _delay: Readiness sleep duration requested by the probe.
        """
        waits.append(True)
        with sqlite3.connect(source_database) as source, sqlite3.connect(target) as destination:
            for statement in source.iterdump():
                destination.execute(statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS "))

    monkeypatch.setattr(probe.time, "sleep", application_finishes_schema)
    assert probe.main(["--wait-for-schema-seconds", "2"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert waits == [True]
    assert result["state"] == ("present" if partial else "proven-absent")
    assert result["counts"]["routes"] == (1 if partial else 0)


@pytest.mark.parametrize("partial", [False, True], ids=["missing-database", "missing-tables"])
def test_schema_timeout_never_creates_state_or_reports_zero_counts(tmp_path, monkeypatch, capsys, partial):
    """Absent readiness remains an unproven source, without a synthesized absence result.

    Args:
        tmp_path: Temporary directory for the not-ready database.
        monkeypatch: Patcher for database access and the bounded readiness clock.
        capsys: Capture fixture used to verify that refusal emits no snapshot.
        partial: Whether to preserve an existing database that lacks required tables.
    """
    target = tmp_path / "not-ready.db"
    if partial:
        with sqlite3.connect(target) as connection:
            connection.execute("CREATE TABLE routes (id INTEGER PRIMARY KEY)")
    before = target.read_bytes() if partial else None
    monkeypatch.setattr(probe, "DATABASE", str(target))
    clock = {"now": 0.0}
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(probe.time, "sleep", lambda delay: clock.update(now=clock["now"] + delay))
    assert probe.main(["--wait-for-schema-seconds", "1"]) == 2
    assert capsys.readouterr().out == ""
    if partial:
        assert target.read_bytes() == before
    else:
        assert not target.exists()


def test_ordinary_probe_does_not_wait_or_create_missing_database(tmp_path, monkeypatch, capsys):
    """Historical certificate inspection remains immediate and strict by default.

    Args:
        tmp_path: Temporary directory for the absent database path.
        monkeypatch: Patcher used to reject any default readiness sleep.
        capsys: Capture fixture used to verify that no snapshot is emitted.
    """
    target = tmp_path / "missing.db"
    monkeypatch.setattr(probe, "DATABASE", str(target))
    monkeypatch.setattr(probe.time, "sleep", lambda _: pytest.fail("default probe waited"))
    assert probe.main() == 2
    assert capsys.readouterr().out == "" and not target.exists()


def test_readiness_does_not_retry_or_repair_invalid_routing_settings(source_database, monkeypatch, capsys):
    """A complete schema still receives the unchanged strict semantic validation.

    Args:
        source_database: Complete source database with an invalid routing setting.
        monkeypatch: Patcher used to target the source and reject readiness retries.
        capsys: Capture fixture used to verify that refusal emits no snapshot.
    """
    with sqlite3.connect(source_database) as connection:
        connection.execute("INSERT INTO settings VALUES ('routes_wan.routing_enabled', 'maybe')")
    before = source_database.read_bytes()
    monkeypatch.setattr(probe, "DATABASE", str(source_database))
    monkeypatch.setattr(probe.time, "sleep", lambda _: pytest.fail("invalid intent was retried"))
    assert probe.main(["--wait-for-schema-seconds", "1"]) == 2
    assert capsys.readouterr().out == "" and source_database.read_bytes() == before


@pytest.mark.parametrize("budget", ["0", "-1", "121"])
def test_schema_wait_refuses_out_of_bounds_budgets(budget, monkeypatch, capsys):
    """Bootstrap cannot turn into an unbounded guest operation.

    Args:
        budget: Invalid schema-wait duration passed through the command line.
        monkeypatch: Patcher used to ensure invalid budgets skip snapshot inspection.
        capsys: Capture fixture used to verify that refusal emits no snapshot.
    """
    monkeypatch.setattr(probe, "snapshot", lambda _: pytest.fail("invalid budget reached source inspection"))
    assert probe.main(["--wait-for-schema-seconds", budget]) == 2
    assert capsys.readouterr().out == ""


def test_schema_wait_does_not_retry_a_corrupt_database(tmp_path, monkeypatch, capsys):
    """Invalid storage is a source failure rather than missing first-boot schema.

    Args:
        tmp_path: Temporary directory for the corrupt database file.
        monkeypatch: Patcher used to direct the probe at corrupt storage.
        capsys: Capture fixture used to verify that refusal emits no snapshot.
    """
    target = tmp_path / "corrupt.db"
    target.write_bytes(b"not a SQLite database")
    monkeypatch.setattr(probe, "DATABASE", str(target))
    monkeypatch.setattr(probe.time, "sleep", lambda _: pytest.fail("corruption was retried"))
    assert probe.main(["--wait-for-schema-seconds", "1"]) == 2
    assert capsys.readouterr().out == "" and target.read_bytes() == b"not a SQLite database"
