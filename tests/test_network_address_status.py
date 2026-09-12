"""Exercise native conflict attribution and recovery without sending any packets."""

from datetime import datetime, timezone

import pytest

from atlaso.app.services.network_address_status import project_status, row_status


def observation(*, address="192.0.2.10", state="assigned", conflicts=None, complete=True):
    """Build a bounded native observation fixture.

    Args:
        address: Currently observed local address.
        state: Native address activation state.
        conflicts: Historical native conflict events.
        complete: Whether every observation source answered.
    """
    return {
        "observed_at": datetime.now(timezone.utc).isoformat(), "complete": complete,
        "links": [{"name": "eth0", "mac": "00:11:22:33:44:55", "up": True, "carrier": True,
                   "configured": True, "addresses": [{"address": address, "state": state}]}],
        "conflicts": conflicts or [],
    }


def resource(*, key="physical:1", name="eth0", desired="192.0.2.20", identity="00:11:22:33:44:55"):
    """Build a desired record without implying that its address has been applied.

    Args:
        key: Stable database resource key.
        name: Link name to attribute.
        desired: Candidate address, distinct from the restored live address.
        identity: Stable hardware identity.
    """
    return {"key": key, "name": name, "identity": identity, "physical": True,
            "desired": [desired], "checking": True}


def test_failed_candidate_remains_distinct_from_restored_address():
    """Retain a rejected candidate while displaying the healthy rollback address separately."""
    event = {"name": "eth0", "address": "192.0.2.20", "detected_at": "2026-09-12T00:00:00+00:00", "mac": ""}
    result = project_status(observation(conflicts=[event]), {}, [resource()])
    row = result["rows"]["physical:1"]
    assert row["state"] == "conflict"
    assert row["active_addresses"] == ["192.0.2.10"]
    assert "failed attempted address is not active" in row["detail"]
    retained = project_status(observation(), result, [resource()])
    assert retained["rows"]["physical:1"]["last_conflict"] == event
    corrected = project_status(observation(), result, [resource(desired="192.0.2.10")])
    assert corrected["rows"]["physical:1"]["state"] == "assigned"
    assert corrected["rows"]["physical:1"]["last_conflict"] == event


def test_conflicts_do_not_cross_links_or_replaced_hardware():
    """Overlapping address space is insufficient evidence to attribute a conflict."""
    event = {"name": "eth1", "address": "192.0.2.20", "detected_at": "2026-09-12T00:00:00+00:00", "mac": ""}
    result = project_status(observation(conflicts=[event]), {}, [resource()])
    assert result["rows"]["physical:1"]["last_conflict"] is None
    event["name"] = "eth0"
    changed = project_status(observation(conflicts=[event]), result, [resource(identity="00:11:22:33:44:66")])
    assert changed["rows"]["physical:1"]["state"] == "unknown"
    assert changed["rows"]["physical:1"]["last_conflict"] is None


def test_unavailable_and_tentative_are_not_conflicts_or_success():
    """A missing source and an address still undergoing DAD remain distinct outcomes."""
    unavailable = project_status(observation(complete=False), {}, [resource()])
    assert unavailable["rows"]["physical:1"]["state"] == "unknown"
    checking = project_status(observation(state="checking"), {}, [resource()])
    assert checking["rows"]["physical:1"]["state"] == "checking"
    checking["rows"]["physical:1"]["observed_at"] = "2020-01-01T00:00:00+00:00"
    assert row_status(checking, "physical", 1)["state"] == "unknown"


def test_successful_reverification_retains_history():
    """A newly active formerly rejected address resolves current conflict without losing history."""
    event = {"name": "eth0", "address": "192.0.2.20", "detected_at": "2026-09-12T00:00:00+00:00", "mac": ""}
    result = project_status(observation(address="192.0.2.20", conflicts=[event]), {}, [resource()])
    assert result["rows"]["physical:1"]["state"] == "assigned"
    assert result["rows"]["physical:1"]["last_conflict"] == event


def test_native_rendering_keeps_ipv6_dad_and_dhcp_lease_retention(tmp_path, monkeypatch):
    """Only explicit IPv4 opt-out disables native checks, including on tagged links.

    Args:
        tmp_path: Isolated staged configuration directory.
        monkeypatch: Prevent reading host management state.
    """
    from tests.test_appliance_helper import load_helper_module, network_config_text

    helper = load_helper_module()
    monkeypatch.setattr(helper, "_read_existing_management_network_values", lambda: {"DNS": [], "Gateway": []})
    monkeypatch.setattr(helper.shutil, "which", lambda _command: None)
    path = tmp_path / "network.conf"
    text = network_config_text(dual_stack=True)
    path.write_text(text, encoding="utf-8")
    files, _, _ = helper._systemd_networkd_files(path)
    for contents in files.values():
        if "Address=" in contents:
            assert "[Address]" in contents
            assert "DuplicateAddressDetection=ipv6" in contents
    assert "Address=192.168.20.1/24\nDuplicateAddressDetection=ipv4" in "".join(files.values())
    text = text.replace("  role=", "  check_duplicate_ip_addresses=false\n  role=")
    path.write_text(text, encoding="utf-8")
    files, _, _ = helper._systemd_networkd_files(path)
    combined = "".join(files.values())
    assert "Address=192.168.20.1/24\nDuplicateAddressDetection=none" in combined
    assert "Address=2001:db8:20::1/64\nDuplicateAddressDetection=ipv6" in combined
    text = text.replace("  ipv4_method=static", "  ipv4_method=dhcp", 1).replace("  ip_cidr=192.168.49.1/24", "  ip_cidr=")
    for enabled in (False, True):
        path.write_text(text.replace("check_duplicate_ip_addresses=false", "check_duplicate_ip_addresses=true") if enabled else text, encoding="utf-8")
        files, _, _ = helper._systemd_networkd_files(path)
        management = files["00-atlaso-mgmt.network"]
        assert "[DHCPv4]\nSendRelease=no\nSendDecline=" + ("yes" if enabled else "no") in management


def test_native_readiness_rejects_pending_and_static_dhcp_holdover(tmp_path, monkeypatch):
    """An old working static address cannot satisfy the candidate DHCP readiness gate.

    Args:
        tmp_path: Isolated staged configuration directory.
        monkeypatch: Supply controlled native observations without touching host links.
    """
    import pytest

    from tests.test_appliance_helper import load_helper_module, network_config_text

    helper = load_helper_module()
    path = tmp_path / "network.conf"
    path.write_text(network_config_text(include_vlan=False).replace("  ipv4_method=static", "  ipv4_method=dhcp", 1).replace("  ip_cidr=192.168.49.1/24", "  ip_cidr="), encoding="utf-8")
    native = observation()
    native["links"][0]["addresses"][0]["source"] = "static"
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native)
    with pytest.raises(ValueError, match="Unable to verify"):
        helper._wait_network_addresses(path, attempts=1)
    native["links"][0]["addresses"][0]["source"] = "DHCPv4"
    native["links"][0]["configured"] = False
    with pytest.raises(ValueError, match="Unable to verify"):
        helper._wait_network_addresses(path, attempts=1)
    native["links"][0]["configured"] = True
    assert helper._wait_network_addresses(path, attempts=1) == native
    native["links"][0]["addresses"][0]["state"] = "checking"
    with pytest.raises(ValueError, match="Unable to verify"):
        helper._wait_network_addresses(path, attempts=1)


def test_handoff_keeps_address_sections_and_previous_dhcp_policy():
    """Transition retains the old path policy without duplicating candidate addresses."""
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    previous = "[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n[DHCPv4]\nSendRelease=no\nSendDecline=yes\n[Address]\nAddress=192.0.2.10/24\nDuplicateAddressDetection=none\n"
    candidate = "[Match]\nName=eth0\n[Network]\n[Address]\nAddress=192.0.2.20/24\nDuplicateAddressDetection=ipv4\n"
    merged = helper._networkd_handoff_text(previous, candidate)
    assert "[Address]\nAddress=192.0.2.10/24\nDuplicateAddressDetection=none" in merged
    assert "[Address]\nAddress=192.0.2.20/24\nDuplicateAddressDetection=ipv4" in merged
    assert "[DHCPv4]\nSendRelease=no\nSendDecline=yes" in merged
    assert helper._networkd_handoff_text(candidate, candidate).count("Address=192.0.2.20/24") == 1


def test_native_observation_sanitizes_and_attributes_structured_sources(monkeypatch):
    """Read IPv4 rejection and DHCP source without retaining unrelated journal content.

    Args:
        monkeypatch: Replace only fixed native observation commands.
    """
    import json
    import subprocess

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    ip_rows = [{"ifname": "eth0", "ifindex": 2, "address": "00:11:22:33:44:55", "link_type": "ether", "flags": ["UP", "LOWER_UP"], "addr_info": [{"local": "192.0.2.10"}]}]
    networkd = {"Interfaces": [{"Name": "eth0", "AdministrativeState": "configured", "Addresses": [{"Address": [192, 0, 2, 10], "ConfigSource": "DHCPv4"}]}]}
    journal = [{"MESSAGE": "eth0: Dropping address 192.0.2.20, as an address conflict was detected.", "INTERFACE": "eth0", "__REALTIME_TIMESTAMP": "1789171200000000"}, {"MESSAGE": "unrelated-sensitive-text"}]

    def command(args, **_kwargs):
        """Provide the command-specific bounded fixture.

        Args:
            args: Fixed command under test.
            _kwargs: Runtime bound retained by the caller.
        """
        value = json.dumps(ip_rows) if args[0] == "ip" else json.dumps(networkd) if args[0] == "networkctl" else "\n".join(json.dumps(item) for item in journal)
        return subprocess.CompletedProcess(args, 0, value, "")

    monkeypatch.setattr(helper, "_network_observation_command", command)
    result = helper._network_address_observation()
    assert result["complete"] is True
    assert result["links"][0]["addresses"][0]["source"] == "DHCPv4"
    assert result["conflicts"][0]["address"] == "192.0.2.20"
    assert result["conflicts"][0]["mac"] == ""
    assert "unrelated-sensitive-text" not in json.dumps(result)


def test_upgrade_defaults_on_without_overwriting_explicit_opt_out(client):
    """Legacy database rows gain enabled checks; later startup preserves explicit false.

    Args:
        client: Application fixture with an isolated SQLite database.
    """
    from sqlalchemy import text

    from atlaso.app.database import engine, init_db

    with engine.begin() as connection:
        for table in ("physical_interfaces", "vlan_interfaces"):
            connection.execute(text(f"ALTER TABLE {table} DROP COLUMN check_duplicate_ip_addresses"))
    init_db()
    with engine.begin() as connection:
        for table in ("physical_interfaces", "vlan_interfaces"):
            assert connection.execute(text(f"SELECT COUNT(*) FROM {table} WHERE check_duplicate_ip_addresses != 1")).scalar_one() == 0
            connection.execute(text(f"UPDATE {table} SET check_duplicate_ip_addresses = 0"))
    init_db()
    with engine.connect() as connection:
        for table in ("physical_interfaces", "vlan_interfaces"):
            assert connection.execute(text(f"SELECT COUNT(*) FROM {table} WHERE check_duplicate_ip_addresses != 0")).scalar_one() == 0


def test_postgresql_startup_adds_address_checks_under_schema_lock(monkeypatch):
    """Exercise the PostgreSQL startup branch and repeat it without rewriting values.

    Args:
        monkeypatch: Supply a recording PostgreSQL connection without a server.
    """
    from contextlib import nullcontext
    from types import SimpleNamespace

    from atlaso.app import database

    calls = []
    columns = {table: [{"name": "id"}] for table in ("physical_interfaces", "vlan_interfaces")}

    def execute(statement, _parameters=None):
        """Record the advisory lock and apply additive metadata changes.

        Args:
            statement: Startup SQL statement.
            _parameters: Advisory lock parameter binding.
        """
        sql = str(statement)
        calls.append(sql)
        if sql.startswith("ALTER TABLE"):
            assert "pg_advisory_xact_lock" in calls[0]
            assert sql.endswith("BOOLEAN NOT NULL DEFAULT TRUE")
            columns[sql.split()[2]].append({"name": "check_duplicate_ip_addresses"})

    connection = SimpleNamespace(execute=execute)
    engine = SimpleNamespace(dialect=SimpleNamespace(name="postgresql"), begin=lambda: nullcontext(connection))
    monkeypatch.setattr(database, "inspect", lambda _connection: SimpleNamespace(get_columns=columns.__getitem__))
    monkeypatch.setattr(database.Base.metadata, "create_all", lambda **_kwargs: None)
    monkeypatch.setattr(database, "_reconcile_nat_ingress_column", lambda _connection: None)
    database._create_database_schema(engine)
    database._create_database_schema(engine)
    assert len([sql for sql in calls if sql.startswith("ALTER TABLE")]) == 2
    assert len([sql for sql in calls if "pg_advisory_xact_lock" in sql]) == 2


def test_archive_preserves_opt_out_and_defaults_legacy_omission(client):
    """Transport the setting but exclude operational conflict observations from backups.

    Args:
        client: Application fixture with isolated desired state.
    """
    import copy

    import pytest
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, Setting, VlanInterface
    from atlaso.app.services.network_address_status import STATUS_KEY
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        for model in (PhysicalInterface, VlanInterface):
            for row in db.scalars(select(model)):
                row.check_duplicate_ip_addresses = False
        db.add(Setting(key=STATUS_KEY, value='{"private-runtime-evidence":true}'))
        db.commit()
        archive = export_settings_archive(db, actor="test")
        assert "private-runtime-evidence" not in str(archive)
        restore_settings_archive(db, archive)
        db.commit()
        for model in (PhysicalInterface, VlanInterface):
            assert all(row.check_duplicate_ip_addresses is False for row in db.scalars(select(model)))
        invalid = copy.deepcopy(archive)
        invalid["data"]["physical_interfaces"][0]["check_duplicate_ip_addresses"] = None
        with pytest.raises(ValueError, match="must be a boolean"):
            restore_settings_archive(db, invalid)
        db.rollback()
        for collection in ("physical_interfaces", "vlan_interfaces"):
            for row in archive["data"][collection]:
                row.pop("check_duplicate_ip_addresses")
        restore_settings_archive(db, archive)
        db.commit()
        for model in (PhysicalInterface, VlanInterface):
            assert all(row.check_duplicate_ip_addresses is True for row in db.scalars(select(model)))


def test_physical_api_preserves_omission_and_rejects_non_boolean(client):
    """An API edit persists explicit false while null, strings and numbers are rejected.

    Args:
        client: Authenticated API transport fixture.
    """
    from tests.routers.api_v1.helpers import create_token

    token, _ = create_token(client, scopes=["read:interfaces", "write:interfaces"])
    headers = {"Authorization": f"Bearer {token}"}
    listed = client.get("/api/v1/interfaces/physical", headers=headers)
    item = listed.json()[0]
    assert item["check_duplicate_ip_addresses"] is True
    url = f"/api/v1/interfaces/physical/{item['name']}"
    response = client.patch(url, headers=headers, json={"check_duplicate_ip_addresses": False})
    assert response.status_code == 200, response.text
    assert response.json()["check_duplicate_ip_addresses"] is False
    response = client.patch(url, headers=headers, json={"mtu": item["mtu"]})
    assert response.status_code == 200, response.text
    assert response.json()["check_duplicate_ip_addresses"] is False
    for value in (None, "false", 0):
        assert client.patch(url, headers=headers, json={"check_duplicate_ip_addresses": value}).status_code == 422


def test_vlan_evidence_requires_actual_tag_and_parent():
    """A reused VLAN name cannot attribute another segment's conflict to this record."""
    import copy

    from tests.test_appliance_helper import load_helper_module

    native = observation()
    native["links"][0]["ifindex"] = 2
    native["links"].append({"name": "eth0.20", "kind": "vlan", "vlan_id": 20, "parent_index": 2,
                            "up": True, "carrier": True, "configured": True,
                            "addresses": [{"address": "192.0.2.20", "state": "assigned"}]})
    candidate = resource(key="vlan:1", name="eth0.20", identity="00:11:22:33:44:55:20")
    candidate.update(physical=False, parent="eth0")
    assert project_status(native, {}, [candidate])["rows"]["vlan:1"]["state"] == "assigned"
    helper = load_helper_module()
    staged = {"name": "eth0.20", "parent": "eth0", "vlan_id": "20"}
    assert helper._native_vlan_matches(staged, {row["name"]: row for row in native["links"]}) is True
    for changed in ({"vlan_id": 21}, {"parent_index": 3}, {"kind": ""}):
        wrong = copy.deepcopy(native)
        wrong["links"][1].update(changed)
        assert project_status(wrong, {}, [candidate])["rows"]["vlan:1"]["state"] == "unknown"
        assert helper._native_vlan_matches(staged, {row["name"]: row for row in wrong["links"]}) is False


def test_status_command_entrypoint_returns_one_json_document(monkeypatch, capsys):
    """The worker's exact no-path invocation reaches observation with parseable stdout.

    Args:
        monkeypatch: Replace native reads while exercising the actual command dispatcher.
        capsys: Capture the protocol response.
    """
    import json

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    native = observation()
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native)
    assert helper.main(["atlaso-helper", "network", "address-status", "--real"]) == 0
    assert json.loads(capsys.readouterr().out) == native
    assert helper.main(["atlaso-helper", "network", "address-status", "unexpected", "--real"]) == 2


def test_dhcp_decline_remains_conflict_until_a_replacement_lease_activates():
    """A dropped DHCP offer has no desired static address, but still represents a conflict."""
    event = {"name": "eth0", "address": "192.0.2.20", "detected_at": "2026-09-12T00:00:00+00:00", "mac": ""}
    desired = resource()
    desired.update(desired=[], dhcp4=True)
    native = observation(conflicts=[event])
    native["links"][0]["addresses"] = []
    rejected = project_status(native, {}, [desired])
    assert rejected["rows"]["physical:1"]["state"] == "conflict"
    native["conflicts"] = []
    native["links"][0]["addresses"] = [{"address": "192.0.2.10", "state": "assigned", "source": "static"}]
    assert project_status(native, rejected, [desired])["rows"]["physical:1"]["state"] == "conflict"
    native["links"][0]["addresses"][0]["source"] = "DHCPv4"
    recovered = project_status(native, rejected, [desired])["rows"]["physical:1"]
    assert recovered["state"] == "assigned"
    assert recovered["last_conflict"] == event


def test_resolved_dhcp_conflict_does_not_reappear_after_lease_loss():
    """A later outage remains unavailable until a genuinely new decline is observed."""
    event = {"name": "eth0", "address": "192.0.2.20", "detected_at": "2026-09-12T00:00:00+00:00", "mac": ""}
    desired = resource()
    desired.update(desired=[], dhcp4=True)
    native = observation(conflicts=[event])
    native["links"][0]["addresses"][0]["source"] = "DHCPv4"
    recovered = project_status(native, {}, [desired])
    assert recovered["rows"]["physical:1"]["conflict_resolved"] is True
    native["links"][0]["addresses"] = []
    lost = project_status(native, recovered, [desired])
    assert lost["rows"]["physical:1"]["state"] == "unknown"
    assert lost["rows"]["physical:1"]["last_conflict"] == event
    native["conflicts"] = [dict(event, detected_at="2026-09-12T01:00:00+00:00")]
    again = project_status(native, lost, [desired])["rows"]["physical:1"]
    assert again["state"] == "conflict"
    assert again["conflict_resolved"] is False


def test_apply_rejects_partial_native_evidence_before_install(tmp_path, monkeypatch, capsys):
    """Missing native evidence blocks mutation even when IPv4 checking was opted out.

    Args:
        tmp_path: Isolated staged intent.
        monkeypatch: Supply failed native observation and trap any installer entry.
        capsys: Capture the safe diagnostic.
    """
    import subprocess

    from tests.test_appliance_helper import load_helper_module, network_config_text

    helper = load_helper_module()
    path = tmp_path / "network.conf"
    monkeypatch.setattr(helper, "_validate_network_config_path", lambda _value: path)
    monkeypatch.setattr(helper, "_run", lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "systemd 257", ""))
    native = observation(complete=False)
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native)

    def forbidden_install(_path):
        """Detect unintended mutation.

        Args:
            _path: Candidate intent that must never reach installation.
        """
        raise AssertionError("installation must not run")

    monkeypatch.setattr(helper, "_install_systemd_networkd_files", forbidden_install)
    for enabled in (True, False):
        config = network_config_text(include_vlan=False)
        if not enabled:
            config = config.replace("  role=", "  check_duplicate_ip_addresses=false\n  role=")
        path.write_text(config, encoding="utf-8")
        assert helper._handle_network("apply", [str(path)]) == 2
        assert "native networkd evidence is unavailable" in capsys.readouterr().err


@pytest.mark.parametrize("failure", ["install", "readiness", "retirement", "rollback", "cleanup", "none"])
def test_ordinary_apply_restores_rejected_candidate(tmp_path, monkeypatch, capsys, failure):
    """Restore persistent bytes and links, retaining evidence when rollback fails.

    Args:
        tmp_path: Isolated staged intent and runtime configuration.
        monkeypatch: Replace native commands with an observable link simulation.
        capsys: Capture the operator recovery diagnostic.
        failure: Transaction stage to reject, or successful activation.
    """
    import subprocess

    from tests.test_appliance_helper import load_helper_module, network_config_text

    helper = load_helper_module()
    config = tmp_path / "candidate.conf"
    config.write_text(network_config_text(include_vlan=False), encoding="utf-8")
    runtime = tmp_path / "networkd"
    runtime.mkdir()
    previous = runtime / "10-atlaso-eth0.network"
    previous.write_bytes(b"[Match]\nName=eth0\n[Network]\nAddress=192.0.2.10/24\n")
    original = previous.read_bytes()
    candidate_only = runtime / "10-atlaso-eth0.20.netdev"
    state = {"eth0": {"existed": True, "admin_up": True, "mtu": 1500},
             "eth0.20": {"existed": False, "admin_up": False, "mtu": None}}
    live = {"eth0"}
    commands = []
    vlan_stages = []
    monkeypatch.setattr(helper, "NETWORK_APPLY_DIR", tmp_path)
    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", runtime)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", runtime / "00-atlaso-mgmt.network")
    monkeypatch.setattr(helper, "_validate_network_config_path", lambda _path: config)
    monkeypatch.setattr(helper, "_network_detection_preflight", lambda _path: None)
    monkeypatch.setattr(helper, "_systemd_networkd_files", lambda _path: (
        {previous.name: "candidate", candidate_only.name: "new VLAN"}, ["eth0"], [],
    ))
    monkeypatch.setattr(helper, "_management_handoff_candidate_links", lambda _payload, **_kwargs: (
        ["eth0"], ["eth0.20"], state,
    ))
    monkeypatch.setattr(helper.os, "chown", lambda *_args: None, raising=False)
    monkeypatch.setattr(helper, "_link_exists", lambda name: name in live)

    def run(command):
        """Record native rollback and remove the simulated candidate-only VLAN.

        Args:
            command: Native command to simulate.
        """
        commands.append(command)
        if command[:3] == ["ip", "link", "delete"]:
            live.discard(command[-1])
        return subprocess.CompletedProcess(command, int(failure == "rollback"), "", "")

    def install(_path):
        """Install a candidate before simulating a partial installer failure.

        Args:
            _path: Validated intent path.
        """
        previous.write_bytes(b"rejected candidate")
        candidate_only.write_bytes(b"new VLAN")
        live.add("eth0.20")
        return int(failure == "install"), [str(previous)], ["eth0"], []

    def apply_vlans(_path, *, defer_removed=False, removed_only=False):
        """Record that old VLAN retirement is deferred until readiness.

        Args:
            _path: Validated intent path.
            defer_removed: Whether old VLAN removal must wait.
            removed_only: Avoid reconfiguring ready candidate links during retirement.
        """
        vlan_stages.append(defer_removed)
        assert removed_only is not defer_removed
        return int(failure == "retirement" and not defer_removed)

    def wait(_path, **_kwargs):
        """Reject address readiness without probing a real network.

        Args:
            _path: Validated intent path.
            **_kwargs: Activation timestamp supplied by the transaction.
        """
        if failure in {"readiness", "rollback"}:
            raise ValueError("candidate address conflict")

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_install_systemd_networkd_files", install)
    monkeypatch.setattr(helper, "_apply_vlan_interfaces", apply_vlans)
    monkeypatch.setattr(helper, "_wait_network_addresses", wait)
    if failure == "cleanup":
        def fail_cleanup(_path):
            """Simulate backup disposal failure after successful activation.

            Args:
                _path: Transaction-owned backup directory.
            """
            raise OSError("backup cleanup unavailable")

        monkeypatch.setattr(helper.shutil, "rmtree", fail_cleanup)
    assert helper._handle_network("apply", [str(config)]) == (0 if failure in {"none", "cleanup"} else 2)
    backups = list(tmp_path.glob(".network-rollback-*"))
    if failure in {"none", "cleanup"}:
        assert previous.read_bytes() == b"rejected candidate"
        assert candidate_only.is_file()
        assert vlan_stages == [True, False]
        if failure == "cleanup":
            assert len(backups) == 1
            assert "backup cleanup incomplete" in capsys.readouterr().err
            assert not commands
            return
    else:
        assert previous.read_bytes() == original
        assert not candidate_only.exists()
        assert ["networkctl", "reload"] in commands
        if failure == "rollback":
            assert len(backups) == 1
            assert (backups[0] / "state.json").is_file()
            assert "rollback incomplete" in capsys.readouterr().err
            return
        assert "eth0.20" not in live
        assert ["networkctl", "reconfigure", "eth0"] in commands
        assert ["ip", "link", "set", "dev", "eth0", "up"] in commands
        assert "previous network configuration restored" in capsys.readouterr().err
    assert not backups


@pytest.mark.parametrize("ready_at", [20, 30, None])
def test_address_readiness_uses_full_thirty_second_window(tmp_path, monkeypatch, ready_at):
    """Accept late DHCP leases and exhaust the deadline without real sleeping.

    Args:
        tmp_path: Isolated network intent.
        monkeypatch: Supply a deterministic monotonic clock and native evidence.
        ready_at: Simulated lease acquisition time, or no lease before timeout.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    elapsed = [0.0]
    samples = []
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: (
        [{"name": "eth0", "ipv4_method": "dhcp", "ipv6_enabled": "false"}], [], [],
    ))
    monkeypatch.setattr(helper.time, "monotonic", lambda: elapsed[0])

    def sleep(seconds):
        """Advance the fake clock.

        Args:
            seconds: Requested bounded sleep duration.
        """
        elapsed[0] += seconds

    def observe():
        """Return the lease only after the simulated acquisition time."""
        samples.append(elapsed[0])
        native = observation()
        if ready_at is None or elapsed[0] < ready_at:
            native["links"][0]["addresses"] = []
        else:
            native["links"][0]["addresses"][0]["source"] = "DHCPv4"
        return native

    monkeypatch.setattr(helper.time, "sleep", sleep)
    monkeypatch.setattr(helper, "_network_address_observation", observe)
    if ready_at is None:
        with pytest.raises(ValueError):
            helper._wait_network_addresses(tmp_path / "intent.conf")
        assert elapsed[0] == 30
    else:
        helper._wait_network_addresses(tmp_path / "intent.conf")
        assert elapsed[0] == ready_at
    assert samples[-1] == elapsed[0]
