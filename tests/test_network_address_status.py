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


@pytest.mark.parametrize("vlan", [False, True])
@pytest.mark.parametrize("recreated", [False, True])
@pytest.mark.parametrize("absent_poll", [False, True])
def test_replacement_link_does_not_replay_name_only_journal_history(vlan, recreated, absent_poll):
    """Keep old journal events out of a replacement NIC or VLAN parent's identity.

    Args:
        vlan: Exercise parent-MAC identity as well as a physical NIC replacement.
        recreated: Recreate the database row while retaining its link name.
        absent_poll: Omit the resource for intervening observer polls before replacement.
    """
    name = "eth0.20" if vlan else "eth0"
    key = "vlan:1" if vlan else "physical:1"
    suffix = ":20" if vlan else ""
    desired = resource(key=key, name=name, identity="00:11:22:33:44:55" + suffix)
    desired.update(physical=not vlan, parent="eth0", dhcp4=not vlan)
    native = observation()
    native["observed_at"] = "2026-09-12T00:01:00+00:00"
    native["links"][0].update(ifindex=2, addresses=[])
    if vlan:
        native["links"].append({"name": name, "kind": "vlan", "vlan_id": 20,
                                "parent_index": 2, "up": True, "carrier": True,
                                "configured": True, "addresses": []})
    event = {"name": name, "address": "192.0.2.20", "detected_at": "2026-09-12T00:00:00+00:00"}
    native["conflicts"] = [event]
    old = project_status(native, {}, [desired])
    assert old["rows"][key]["state"] == "conflict"
    if absent_poll:
        old = project_status(native, old, [])
        old = project_status(native, old, [])
        assert old["rows"] == {}
    desired["identity"] = "00:11:22:33:44:66" + suffix
    if recreated:
        key = key.replace(":1", ":2")
        desired["key"] = key
    native["links"][0]["mac"] = "00:11:22:33:44:66"
    native["observed_at"] = "2026-09-12T00:02:00+00:00"
    changed = project_status(native, old, [desired])
    assert changed["rows"][key]["last_conflict"] is None
    assert changed["rows"][key]["state"] == "unknown"
    native["observed_at"] = "2026-09-12T00:03:00+00:00"
    repeated = project_status(native, changed, [desired])
    assert repeated["rows"][key]["last_conflict"] is None
    assert repeated["rows"][key]["identity_since"] == "2026-09-12T00:02:00+00:00"
    native["conflicts"] = [dict(event, detected_at="2026-09-12T00:02:30+00:00")]
    assert project_status(native, repeated, [desired])["rows"][key]["state"] == "conflict"
    native["conflicts"] = [dict(event, identity=desired["identity"])]
    assert project_status(native, repeated, [desired])["rows"][key]["state"] == "conflict"


def test_successful_reverification_retains_history():
    """A newly active formerly rejected address resolves current conflict without losing history."""
    event = {"name": "eth0", "address": "192.0.2.20", "detected_at": "2026-09-12T00:00:00+00:00", "mac": ""}
    desired = resource()
    desired["desired_cidrs"] = {"192.0.2.20": "192.0.2.20/24"}
    prior = project_status(observation(conflicts=[event]), {}, [desired])
    native = observation(address="192.0.2.20")
    native["links"][0]["addresses"][0].update(cidr="192.0.2.20/24", source="static")
    result = project_status(native, prior, [desired])
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
    ip_rows = [{"ifname": "eth0", "ifindex": 2, "address": "00:11:22:33:44:55", "link_type": "ether", "flags": ["UP", "LOWER_UP"], "addr_info": [{"local": "192.0.2.10", "prefixlen": 24}]}]
    networkd = {"Interfaces": [{"Name": "eth0", "AdministrativeState": "configured", "Addresses": [{"Address": [192, 0, 2, 10], "PrefixLength": 24, "ConfigSource": "DHCPv4"}]}]}
    networkd["Interfaces"][0]["Addresses"].append(
        {"Address": [192, 0, 2, 10], "PrefixLength": 25, "ConfigSource": "static"},
    )
    journal = [{"MESSAGE": "eth0: Dropping address 192.0.2.20, as an address conflict was detected.", "INTERFACE": "eth0", "__REALTIME_TIMESTAMP": "1789171200000000"}, {"MESSAGE": "unrelated-sensitive-text"}]

    def command(args, **_kwargs):
        """Provide the command-specific bounded fixture.

        Args:
            args: Fixed command under test.
            **_kwargs: Runtime bound retained by the caller.
        """
        value = json.dumps(ip_rows) if args[0] == "ip" else json.dumps(networkd) if args[0] == "networkctl" else "\n".join(json.dumps(item) for item in journal)
        return subprocess.CompletedProcess(args, 0, value, "")

    monkeypatch.setattr(helper, "_network_observation_command", command)
    result = helper._network_address_observation()
    assert result["complete"] is True
    assert result["links"][0]["addresses"][0]["source"] == "DHCPv4"
    assert result["links"][0]["addresses"][0]["cidr"] == "192.0.2.10/24"
    assert result["conflicts"][0]["address"] == "192.0.2.20"
    assert result["conflicts"][0]["mac"] == ""
    assert "unrelated-sensitive-text" not in json.dumps(result)


@pytest.mark.parametrize("candidate", ["192.0.2.10/25", "2001:db8::10/80"])
def test_static_readiness_requires_candidate_prefix_and_source(tmp_path, monkeypatch, candidate):
    """Holdovers at the same IP cannot prove a static prefix or source transition.

    Args:
        tmp_path: Isolated intent path.
        monkeypatch: Replace native observation with successive handoff states.
        candidate: IPv4 or IPv6 candidate with a changed prefix.
    """
    from ipaddress import ip_interface

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    monkeypatch.setattr(helper, "NETWORK_APPLY_DIR", tmp_path)
    monkeypatch.setattr(helper, "NETWORK_TRANSACTION_DIR", tmp_path / "transaction")
    parsed = ip_interface(candidate)
    row = {"name": "eth0", "ipv6_enabled": "true" if parsed.version == 6 else "false",
           "ipv6_cidr" if parsed.version == 6 else "ip_cidr": candidate}
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([row], [], []))
    native = observation(address=str(parsed.ip))
    record = native["links"][0]["addresses"][0]
    record.update(source="static", cidr=f"{parsed.ip}/{24 if parsed.version == 4 else 64}")
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native)
    path = tmp_path / "intent.conf"
    with pytest.raises(ValueError, match="Unable to verify"):
        helper._wait_network_addresses(path, attempts=1)
    record.update(cidr=candidate, source="DHCPv4" if parsed.version == 4 else "DHCPv6")
    with pytest.raises(ValueError, match="Unable to verify"):
        helper._wait_network_addresses(path, attempts=1)
    record["source"] = "static"
    assert helper._wait_network_addresses(path, attempts=1) == native
    record["state"] = "conflict"
    with pytest.raises(ValueError, match="IP conflict"):
        helper._wait_network_addresses(path, attempts=1)


def test_candidate_vlan_conflict_survives_link_removal(tmp_path, monkeypatch):
    """Capture identity-bound rejection before rollback, without a worker sample.

    Args:
        tmp_path: Task-owned native evidence root.
        monkeypatch: Supply candidate topology and rejection evidence.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    monkeypatch.setattr(helper, "NETWORK_APPLY_DIR", tmp_path)
    monkeypatch.setattr(helper, "NETWORK_TRANSACTION_DIR", tmp_path / "transaction")
    candidate = {"name": "eth0.20", "parent": "eth0", "vlan_id": "20", "ip_cidr": "192.0.2.20/24"}
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([], [candidate], []))
    native = observation()
    native["links"][0]["ifindex"] = 2
    native["links"].append({"name": "eth0.20", "kind": "vlan", "vlan_id": 20,
                            "parent_index": 2, "configured": False, "addresses": []})
    native["conflicts"] = [{"name": "eth0.20", "address": "192.0.2.20",
                            "detected_at": native["observed_at"], "mac": ""}]
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native)
    with pytest.raises(ValueError, match="IP conflict"):
        helper._wait_network_addresses(tmp_path / "intent.conf", attempts=1, started_at="2026-01-01T00:00:00+00:00")
    retained = helper._read_retained_network_conflicts()
    assert retained[0]["identity"] == "00:11:22:33:44:55:20"
    native["links"] = native["links"][:1]
    native["conflicts"] = retained
    desired = resource(key="vlan:2", name="eth0.20", identity="00:11:22:33:44:55:20")
    desired.update(physical=False, parent="eth0")
    projected = project_status(native, {}, [desired])["rows"]["vlan:2"]
    assert projected["state"] == "conflict"
    assert projected["active_addresses"] == []
    assert projected["last_conflict"]["address"] == "192.0.2.20"
    desired["identity"] = "00:11:22:33:44:66:20"
    assert project_status(native, {}, [desired])["rows"]["vlan:2"]["last_conflict"] is None


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
    columns["jobs"] = [{"name": name} for name in (
        "id", "cancel_requested_at", "cancel_requested_by", "cancel_completed_at", "cancel_outcome",
    )]

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

    connection = SimpleNamespace(execute=execute, dialect=SimpleNamespace(name="postgresql"))
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
    rejected = project_status(native, {}, [desired])
    assert rejected["rows"]["physical:1"]["state"] == "conflict"
    repeated = project_status(native, rejected, [desired])
    assert repeated["rows"]["physical:1"]["conflict_resolved"] is False
    native["links"][0]["addresses"][0]["address"] = "192.0.2.11"
    recovered = project_status(native, repeated, [desired])
    assert recovered["rows"]["physical:1"]["conflict_resolved"] is True
    native["links"][0]["addresses"] = []
    lost = project_status(native, recovered, [desired])
    assert lost["rows"]["physical:1"]["state"] == "unknown"
    assert lost["rows"]["physical:1"]["last_conflict"] == event
    native["conflicts"] = [dict(event, detected_at="2026-09-12T01:00:00+00:00")]
    again = project_status(native, lost, [desired])["rows"]["physical:1"]
    assert again["state"] == "conflict"
    assert again["conflict_resolved"] is False


@pytest.mark.parametrize("old_address", ["192.0.2.10", "192.0.2.20"])
def test_dhcp_decline_requires_lease_appearance_after_conflict(old_address):
    """Old or simultaneously discovered leases cannot resolve a fresh decline.

    Args:
        old_address: A retained lease, including the declined address itself.
    """
    desired = resource()
    desired.update(desired=[], dhcp4=True)
    native = observation(address=old_address)
    native["observed_at"] = "2026-09-12T00:00:00+00:00"
    native["links"][0]["addresses"][0]["source"] = "DHCPv4"
    prior = project_status(native, {}, [desired])
    event = {"name": "eth0", "address": "192.0.2.20", "detected_at": "2026-09-12T00:00:01+00:00"}
    native["conflicts"] = [event]
    native["observed_at"] = "2026-09-12T00:00:02+00:00"
    # Even a different lease in the first post-decline sample has no proven ordering.
    native["links"][0]["addresses"][0]["address"] = "192.0.2.11"
    rejected = project_status(native, prior, [desired])
    assert rejected["rows"]["physical:1"]["conflict_resolved"] is False
    retained = project_status(native, rejected, [desired])
    assert retained["rows"]["physical:1"]["state"] == "conflict"
    native["observed_at"] = "2026-09-12T00:00:03+00:00"
    native["links"][0]["addresses"][0]["address"] = "192.0.2.12"
    recovered = project_status(native, retained, [desired])
    assert recovered["rows"]["physical:1"]["conflict_resolved"] is True


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
    monkeypatch.setattr(helper, "NETWORK_TRANSACTION_DIR", tmp_path / "transaction")
    monkeypatch.setattr(helper, "fcntl", None)
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


@pytest.mark.parametrize("failure", ["backup", "marker"])
def test_network_acknowledgement_retries_terminal_cleanup(tmp_path, monkeypatch, failure):
    """Report incomplete disposal without rolling back an application-committed candidate.

    Args:
        tmp_path: Isolated root-owned transaction simulation.
        monkeypatch: Inject backup or durable marker removal failure.
        failure: Cleanup stage which must remain retryable.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    root = tmp_path / "transaction"
    root.mkdir()
    backup = root / "backup-test"
    backup.mkdir()
    (backup / "snapshot").write_text("old configuration", encoding="utf-8")
    marker = root / "state.json"
    monkeypatch.setattr(helper, "NETWORK_TRANSACTION_DIR", root)
    monkeypatch.setattr(helper, "fcntl", None)
    helper._durable_management_handoff_state_write({"phase": "awaiting-commit", "job_id": "job-test",
                                                    "backup_root": str(backup), "snapshots": []}, marker)
    original_remove = helper.shutil.rmtree
    original_unlink = helper._durable_management_handoff_unlink

    def failed_cleanup(_path):
        """Interrupt the selected cleanup stage.

        Args:
            _path: Transaction-owned cleanup target.
        """
        raise OSError("injected cleanup failure")

    def forbidden_restore(_state):
        """Detect any attempt to roll back the committed candidate.

        Args:
            _state: Persisted committed state.
        """
        pytest.fail("committed candidate must never roll back for a cleanup failure")

    monkeypatch.setattr(helper, "_restore_network_transaction", forbidden_restore)
    if failure == "backup":
        monkeypatch.setattr(helper.shutil, "rmtree", failed_cleanup)
    else:
        monkeypatch.setattr(helper, "_durable_management_handoff_unlink", failed_cleanup)
    assert helper._handle_network("acknowledge", ["job-test"]) == 2
    assert helper._network_transaction_state()["phase"] == "committed"
    assert helper._handle_network("recover", ["job-test"]) == 2
    monkeypatch.setattr(helper.shutil, "rmtree", original_remove)
    monkeypatch.setattr(helper, "_durable_management_handoff_unlink", original_unlink)
    assert helper._handle_network("recover", ["job-test"]) == 0
    assert not marker.exists()
    assert not backup.exists()
    assert helper._handle_network("acknowledge", ["job-test"]) == 0


def test_network_transaction_excludes_a_live_helper(tmp_path, monkeypatch):
    """Use real POSIX locking to refuse recovery until the owning helper exits.

    Args:
        tmp_path: Isolated transaction directory.
        monkeypatch: Map root ownership checks onto the unprivileged test directory.
    """
    from types import SimpleNamespace

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    if helper.fcntl is None:
        pytest.skip("POSIX flock is verified on Linux CI")
    monkeypatch.setattr(helper, "NETWORK_TRANSACTION_DIR", tmp_path / "transaction")
    original_fstat = helper.os.fstat

    def root_metadata(descriptor):
        """Preserve actual filesystem type and permissions while substituting UID.

        Args:
            descriptor: Real directory or lock-file descriptor.
        """
        value = original_fstat(descriptor)
        return SimpleNamespace(st_uid=0, st_mode=value.st_mode, st_nlink=value.st_nlink)

    monkeypatch.setattr(helper.os, "fstat", root_metadata)
    with helper._network_transaction_lock():
        with pytest.raises(ValueError, match="live helper"):
            with helper._network_transaction_lock():
                pytest.fail("a second owner acquired the transaction lock")
    with helper._network_transaction_lock():
        assert helper._network_transaction_state() == {}


@pytest.mark.parametrize("failure", ["install", "readiness", "retirement", "rollback", "cleanup", "none",
                                     "interrupted", "awaiting", "acknowledged", "publication"])
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
    if failure in {"interrupted", "awaiting", "acknowledged", "publication"}:
        config.write_text("# atlaso-network-task: test-task\n" + config.read_text(encoding="utf-8"), encoding="utf-8")
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
    monkeypatch.setattr(helper, "NETWORK_TRANSACTION_DIR", tmp_path / "transaction")
    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", runtime)
    monkeypatch.setattr(helper, "fcntl", None)
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
        if failure == "interrupted":
            raise KeyboardInterrupt("helper stopped before readiness")

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
    if failure == "publication":
        original_replace = helper.Path.replace

        def fail_after_rename(source, target):
            """Expose the marker, then fail before the parent-directory sync.

            Args:
                source: Temporary marker file being atomically published.
                target: Destination marker path.
            """
            result = original_replace(source, target)
            if target == helper.NETWORK_TRANSACTION_DIR / "state.json":
                raise OSError("marker parent sync unavailable")
            return result

        monkeypatch.setattr(helper.Path, "replace", fail_after_rename)
        assert helper._handle_network("apply", [str(config)]) == 2
        pending = helper._network_transaction_state()
        assert pending["phase"] == "applying"
        for snapshot in pending["snapshots"]:
            if snapshot["existed"]:
                assert helper.Path(snapshot["backup"]).read_bytes() == original
        assert previous.read_bytes() == original
        assert not commands and not vlan_stages and not candidate_only.exists()
        monkeypatch.setattr(helper.Path, "replace", original_replace)
        assert helper._handle_network("recover", ["test-task"]) == 0
        assert helper._network_transaction_state() == {}
    elif failure == "interrupted":
        with pytest.raises(KeyboardInterrupt):
            helper._handle_network("apply", [str(config)])
        assert helper._network_transaction_state()["phase"] == "applying"
        assert helper._handle_network("apply", [str(config)]) == 2
        assert helper._handle_network("acknowledge", ["test-task"]) == 2
        assert helper._handle_network("recover", ["test-task"]) == 0
    elif failure in {"awaiting", "acknowledged"}:
        assert helper._handle_network("apply", [str(config)]) == 0
        assert helper._network_transaction_state()["phase"] == "awaiting-commit"
        assert helper._handle_network("acknowledge", ["wrong-task"]) == 2
        action = "acknowledge" if failure == "acknowledged" else "recover"
        assert helper._handle_network(action, ["test-task"]) == 0
        assert helper._handle_network(action, ["test-task"]) == 0
    else:
        assert helper._handle_network("apply", [str(config)]) == (0 if failure in {"none", "cleanup"} else 2)
    backups = list((tmp_path / "transaction").glob("backup-*"))
    if failure in {"none", "cleanup", "acknowledged"}:
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
            assert (tmp_path / "transaction" / "state.json").is_file()
            assert "rollback incomplete" in capsys.readouterr().err
            return
        assert "eth0.20" not in live
        assert ["networkctl", "reconfigure", "eth0"] in commands
        assert ["ip", "link", "set", "dev", "eth0", "up"] in commands
        if failure not in {"interrupted", "awaiting", "publication"}:
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


@pytest.mark.parametrize("source,prefix", [("static", 24), ("DHCPv4", 25), ("static", 25)])
def test_static_prefix_failure_requires_later_exact_candidate_activation(source, prefix):
    """Rollback holdovers and leases cannot resolve a failed static prefix change.

    Args:
        source: Native source of the retained address.
        prefix: Prefix on the pre-existing address record.
    """
    desired = resource(desired="192.0.2.20")
    desired["desired_cidrs"] = {"192.0.2.20": "192.0.2.20/25"}
    event = {"name": "eth0", "address": "192.0.2.20", "detected_at": "2026-09-12T00:00:00+00:00"}
    native = observation(address="192.0.2.20", conflicts=[event])
    native["links"][0]["addresses"][0].update(source=source, cidr=f"192.0.2.20/{prefix}")
    rejected = project_status(native, {}, [desired])
    retained = project_status(native, rejected, [desired])
    assert retained["rows"]["physical:1"]["state"] == "conflict"
    assert retained["rows"]["physical:1"]["conflict_resolved"] is False
    native["links"][0]["addresses"] = []
    absent = project_status(native, retained, [desired])
    native["links"][0]["addresses"] = [{"address": "192.0.2.20", "cidr": "192.0.2.20/25",
                                        "source": "static", "state": "assigned"}]
    recovered = project_status(native, absent, [desired])
    assert recovered["rows"]["physical:1"]["state"] == "assigned"
    assert recovered["rows"]["physical:1"]["conflict_resolved"] is True


@pytest.mark.parametrize("source", ["static", "DHCPv6", "NDisc"])
def test_ipv6_conflict_recovery_ignores_ipv4_opt_out(source):
    """Retain rejected IPv6 attempts until a later matching replacement activates.

    Args:
        source: Static or automatic native IPv6 configuration source.
    """
    desired = resource(desired="2001:db8::20")
    desired.update(checking=False, auto6=source != "static")
    desired["desired_cidrs"] = {"2001:db8::20": "2001:db8::20/64"}
    if source != "static":
        desired.update(desired=[], desired_cidrs={})
    event = {"name": "eth0", "address": "2001:db8::20", "detected_at": "2026-09-12T00:00:00+00:00"}
    native = observation(conflicts=[event])
    native["links"][0]["addresses"].append({"address": "2001:db8::10", "cidr": "2001:db8::10/64",
                                           "source": source, "state": "assigned"})
    rejected = project_status(native, {}, [desired])
    native["conflicts"] = []
    retained = project_status(native, rejected, [desired])
    assert retained["rows"]["physical:1"]["state"] == "conflict"
    native["links"][0]["addresses"].append({"address": "fe80::1", "source": source, "state": "assigned"})
    link_local = project_status(native, retained, [desired])
    assert link_local["rows"]["physical:1"]["conflict_resolved"] is False
    native["links"][0]["addresses"].append({"address": "2001:db8::20", "cidr": "2001:db8::20/64",
                                           "source": source, "state": "assigned"})
    recovered = project_status(native, link_local, [desired])
    assert recovered["rows"]["physical:1"]["state"] == "assigned"
    assert recovered["rows"]["physical:1"]["conflict_resolved"] is True
    native["links"][0]["addresses"] = []
    lost = project_status(native, recovered, [desired])
    assert lost["rows"]["physical:1"]["state"] == "unknown"
