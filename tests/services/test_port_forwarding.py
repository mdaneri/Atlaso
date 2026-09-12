"""Exercise destination-translation boundaries before any host mutation."""

import hashlib
import json
import subprocess
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.models import AuditEvent, Base, PhysicalInterface, PortForward
from atlaso.app.port_forward_schemas import PortForwardCreate
from atlaso.app.services.network_objects import (
    source_group_consumers,
    source_group_nat_validation_errors,
)
from atlaso.app.services.port_forwarding import (
    ListenerClaim,
    port_forward_firewall_projection,
    port_forward_status,
    render_port_forward_records,
    save_port_forward,
    snapshot_has_port_forwards,
    source_networks,
    validate_port_forward,
)
from atlaso.app.services.traffic_publishing import (
    TrafficPublishingSettings,
    nat_targets,
    render_nat_config,
)
from tests.test_appliance_helper import load_helper_module


def test_replacement_refreshes_desired_timestamp(monkeypatch):
    """Return the mutation timestamp for edits and enabled-state replacements.

    Args:
        monkeypatch: Set a deterministic service clock after initial creation.
    """
    from atlaso.app import models

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(interfaces())
        db.commit()
        saved = save_port_forward(db, PortForwardCreate(**payload()), actor="operator")
        for day, enabled in ((1, False), (2, True)):
            timestamp = datetime(2030, 1, day, tzinfo=timezone.utc)
            monkeypatch.setattr(models, "utcnow", lambda value=timestamp: value)
            changed = save_port_forward(db, PortForwardCreate(**payload(enabled=enabled)),
                                       actor="operator", rule_id=saved.id)
            assert changed.updated_at.replace(tzinfo=timezone.utc) == timestamp


@pytest.mark.parametrize("installed", [False, True])
@pytest.mark.parametrize("succeeds", [False, True])
def test_signed_upgrade_bootstraps_conntrack(monkeypatch, tmp_path, installed, succeeds):
    """An older updater starts the candidate hook before exposing forwarding.

    Args:
        monkeypatch: Replace package and command observations.
        tmp_path: Isolated active signed-release layout.
        installed: Whether the previous image already contains the package.
        succeeds: Whether Photon can provide the missing executable.
    """
    from pathlib import Path

    helper = load_helper_module()
    release = tmp_path / "releases/candidate"
    release.mkdir(parents=True)
    current = tmp_path / "current"
    current.symlink_to(release, target_is_directory=True)
    monkeypatch.setattr(helper, "ATLASO_CURRENT_LINK", current)
    monkeypatch.setattr(helper, "ATLASO_RELEASES_DIR", release.parent)
    available = {"tdnf": "/usr/bin/tdnf"}
    if installed:
        available["conntrack"] = "/usr/sbin/conntrack"
    monkeypatch.setattr(helper, "_command_path", available.get)
    commands = []

    def install(command, *, timeout):
        """Simulate the single bounded fixed-package installation.

        Args:
            command: Exact package installation command.
            timeout: Maximum installation duration.
        """
        assert command == ["/usr/bin/tdnf", "install", "-y", "conntrack-tools"]
        assert timeout == 60
        commands.append(command)
        if succeeds:
            available["conntrack"] = "/usr/sbin/conntrack"
        return subprocess.CompletedProcess(command, 0 if succeeds else 1, "", "")

    monkeypatch.setattr(helper, "_run", install)
    if not installed and not succeeds:
        with pytest.raises(ValueError, match="prerequisite installation failed"):
            helper._bootstrap_port_forwarding(release)
    else:
        helper._bootstrap_port_forwarding(release)
        assert helper._bootstrap_port_forwarding(release) == []
    assert len(commands) == (0 if installed else 1)
    unit = Path("image/common/systemd/atlaso.service").read_text(encoding="utf-8")
    assert "ExecStartPre=+/opt/atlaso/bin/atlaso-helper appliance-update bootstrap-port-forwarding --real /opt/atlaso/current" in unit


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("missing", [None, "dnat", "original", "reply"])
def test_status_requires_translation_and_both_admissions(family, missing, monkeypatch, tmp_path, capsys):
    """Surviving counters cannot conceal partially removed publication members.

    Args:
        family: Applied destination address family.
        missing: Member removed independently after a successful apply.
        monkeypatch: Replace host observations with a bounded runtime snapshot.
        tmp_path: Isolated applied configuration path.
        capsys: Capture the public status response.
    """
    helper = load_helper_module()
    path = tmp_path / "nat.conf"
    path.write_text("applied", encoding="utf-8")
    row = {"id": 1, "ip_family": family}
    monkeypatch.setattr(helper, "NAT_RUNTIME_CONFIG_PATH", path)
    monkeypatch.setattr(helper, "_parse_wan_config", lambda path: {})
    monkeypatch.setattr(helper, "_port_forward_records", lambda parsed: [row])
    monkeypatch.setattr(helper, "_port_forward_target_warnings", lambda rows: {})
    entries = [{"counter": {"family": "inet", "table": "atlaso_port_forwards",
                            "name": "pf_1", "packets": 7, "bytes": 700}}]
    if missing != "dnat":
        entries.append({"rule": {"family": "ip" if family == 4 else "ip6", "table": "atlaso_nat",
                                 "chain": "prerouting", "comment": "Atlaso port forward 1",
                                 "expr": [{"dnat": {"addr": "198.51.100.10"}}]}})
    for direction in ("original", "reply"):
        if missing != direction:
            entries.append({"rule": {"family": "inet", "table": "atlaso", "chain": "forward",
                                     "comment": "Atlaso port forward 1", "expr": [
                                         {"match": {"op": "==", "left": {"ct": {"key": "direction"}},
                                                    "right": direction}}, {"accept": None}]}})

    def observe(command, *, timeout):
        """Allow exactly one read-only bounded nftables observation.

        Args:
            command: Fixed ruleset inspection command.
            timeout: Maximum observation duration.
        """
        assert command == ["nft", "-j", "list", "ruleset"]
        assert timeout == 2
        return subprocess.CompletedProcess(command, 0, json.dumps({"nftables": entries}), "")

    monkeypatch.setattr(helper, "_run", observe)
    assert helper._port_forward_status() == 0
    observed = json.loads(capsys.readouterr().out)["rules"][0]
    assert observed["state"] == ("applied" if missing is None else "degraded")
    assert observed["packets"] == 7


@pytest.mark.parametrize(("preview", "expected"), [
    ("[nat_rules]\n", False),
    ("[port_forwards]\njson=[]\n", False),
    ('[port_forwards]\njson=[{"id":1}]\n', True),
    ("[port_forwards]\njson=broken\n", True),
    ("[port_forwards]\njson={}\n", True),
    ("[port_forwards]\n[another]\n", True),
])
def test_applied_forward_presence_preserves_retirement_boundary(preview, expected):
    """Keep the paired boundary for old or malformed forwarding snapshots.

    Args:
        preview: Applied configuration from before or after forwarding support.
        expected: Whether independent source NAT publication is unsafe.
    """
    assert snapshot_has_port_forwards(preview) is expected


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("routing", [False, True])
def test_firewall_preview_matches_independent_helper_admission(family, routing):
    """Preview and root validation agree without editable generated rules.

    Args:
        family: Original tuple address family.
        routing: Whether the admission is effective.
    """
    values = payload(ip_family=family)
    if family == 6:
        values.update(listener_address="2001:db8:2::1", target_address="2001:db8:3::10")
    rule = PortForward(id=1, **values)
    firewall = "flush ruleset\ntable inet atlaso {\n chain forward { type filter hook forward priority 0; policy drop; }\n}\n"
    preview, rows = port_forward_firewall_projection(firewall, [rule], [], routing_enabled=routing)
    record = json.loads(render_port_forward_records([rule], []).split("json=", 1)[1])[0]
    assert preview == load_helper_module()._render_port_forward_firewall(firewall, [record] if routing else [])
    assert bool(rows) is routing
    if rows:
        assert rows[0]["source_group_id"] == ""
        assert "Port forward #1" in rows[0]["description"]


@pytest.mark.parametrize("condition,expected", [
    ("healthy", ""), ("missing", "target_route_missing"),
    ("blackhole", "target_route_missing"), ("failed", "target_neighbor_failed"),
    ("incomplete", ""), ("unavailable", "target_observation_unavailable"),
])
def test_target_path_warnings_are_read_only_and_bounded(monkeypatch, condition, expected):
    """Only affirmative route or neighbor failures claim target unreachability.

    Args:
        monkeypatch: Replace the read-only kernel inventory boundary.
        condition: Route and neighbor condition under observation.
        expected: Sanitized status reason, if any.
    """
    helper = load_helper_module()
    commands = []

    def observe(command, *, timeout):
        """Return bounded route and neighbor inventories.

        Args:
            command: One fixed read-only ip invocation.
            timeout: Per-command observation deadline.
        """
        commands.append(command)
        assert timeout == 1
        if condition == "unavailable":
            return subprocess.CompletedProcess(command, 1, "", "unavailable")
        if "route" in command:
            data = [] if condition == "missing" else [{"dst": "198.51.100.0/24", "dev": "eth2",
                                                        "type": "blackhole" if condition == "blackhole" else "unicast"}]
        else:
            data = [{"dst": "198.51.100.10", "dev": "eth2", "state": [condition.upper()]}]
        return subprocess.CompletedProcess(command, 0, json.dumps(data), "")

    monkeypatch.setattr(helper, "_run", observe)
    warnings = helper._port_forward_target_warnings([{"id": 1, **payload()}])
    assert warnings.get(1, "") == expected
    assert len(commands) <= 2
    assert all(command[:3] == ["ip", "-j", "-4"] and "show" in command for command in commands)


def payload(**changes):
    """Build a complete rule while permitting one focused boundary change.

    Args:
        **changes: Fields changed by a validation scenario.
    """
    return {**dict(name="web", description="Lab endpoint", priority=100, enabled=True,
                   ip_family=4, ingress_interface="eth1", listener_address="192.0.2.1",
                   protocol="tcp", external_port_start=12000, external_port_end=12002,
                   target_address="198.51.100.10", target_port_start=13000, target_port_end=13002,
                   source="any", reply_mode="preserve"), **changes}


def interfaces():
    """Return dual-stack access listeners and an isolated management interface."""
    return [PhysicalInterface(name="eth0", mac_address="00:11:22:33:44:00", role="management", mode="access", admin_state="up", oper_state="up",
                              ip_cidr="10.1.1.1/24", ipv6_cidr="2001:db8:1::1/64"),
            PhysicalInterface(name="eth1", mac_address="00:11:22:33:44:01", role="access", mode="access", admin_state="up", oper_state="up",
                              ip_cidr="192.0.2.1/24", ipv6_cidr="2001:db8:2::1/64", access_management_ui_enabled=True)]


def context():
    """Capture pure validation inputs without making host probes."""
    rows = interfaces()
    return dict(interfaces=rows, targets=nat_targets(rows, []), groups=[], claims=[])


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_equal_length_maps_allow_flagged_access_management(family, protocol):
    """Flagged access retains lab eligibility without changing management role.

    Args:
        family: Translation family.
        protocol: TCP or UDP.
    """
    values = payload(ip_family=family, protocol=protocol)
    if family == 6:
        values.update(listener_address="2001:db8:2::1", target_address="2001:db8:3::10")
    assert not validate_port_forward(PortForward(**values), [], context())


@pytest.mark.parametrize("change", [
    {"external_port_start": 0}, {"target_port_end": 65536},
    {"external_port_end": 11999}, {"target_port_end": 13003},
    {"protocol": "sctp"}, {"reply_mode": "masquerade"},
])
def test_schema_rejects_ambiguous_mapping_or_unacknowledged_masquerade(change):
    """Invalid mapping and source-loss requests fail before domain mutation.

    Args:
        change: One invalid field combination.
    """
    with pytest.raises(ValidationError):
        PortForwardCreate(**payload(**change))
    assert PortForwardCreate(**payload(reply_mode="masquerade", acknowledge_source_loss=True)).reply_mode == "masquerade"


@pytest.mark.parametrize("change", [
    {"ingress_interface": "eth0", "listener_address": "10.1.1.1"},
    {"listener_address": "192.0.2.99"}, {"target_address": "192.0.2.1"},
    {"target_address": "10.1.1.20"}, {"target_address": "192.0.2.255"},
    {"target_address": "127.0.0.1"}, {"target_address": "169.254.1.1"},
    {"target_address": "224.0.0.1"}, {"target_address": "0.0.0.0"},
    {"source": "2001:db8::/32"}, {"source": "group:missing"},
])
def test_listener_target_and_source_boundaries(change):
    """Reject management, local, ambiguous and wrong-family paths.

    Args:
        change: Candidate escape from the reviewed boundary.
    """
    assert validate_port_forward(PortForward(**payload(**change)), [], context())


def test_overlap_is_global_to_listener_not_source_or_interface_name():
    """Different sources cannot make overlapping destination translations safe."""
    old = PortForward(id=1, **payload())
    candidate = PortForward(id=2, **payload(name="other", source="192.0.2.10/32", external_port_start=12002, external_port_end=12004))
    assert any("overlap" in error for error in validate_port_forward(candidate, [old], context()))
    candidate.enabled = False
    assert not validate_port_forward(candidate, [old], context())
    candidate.enabled = True
    candidate.protocol = "udp"
    assert not validate_port_forward(candidate, [old], context())


def test_owned_listener_claim_catches_intersecting_external_range():
    """A custom service port inside a range remains reserved to the appliance."""
    state = context()
    state["claims"] = [ListenerClaim("eth1", "*", "tcp", 12001, 12001)]
    assert any("collides" in error for error in validate_port_forward(PortForward(**payload()), [], state))


def test_mixed_source_group_is_rejected_without_dropping_members():
    """Source expansion must never silently filter out another family."""
    groups = [{"id": "mixed", "name": "Mixed", "entries": ["192.0.2.0/24", "2001:db8::/32"]}]
    with pytest.raises(ValueError):
        source_networks("group:mixed", 4, groups)


def test_source_group_edits_validate_saved_port_forward_family_and_usage():
    """Group edits cannot widen a port forward or orphan its disabled intent."""
    row = PortForward(id=1, **payload(source="group:clients"))
    groups = [{"id": "clients", "name": "Clients", "entries": ["192.0.2.0/24"]}]
    assert source_group_nat_validation_errors(groups, [row]) == {}
    groups[0]["entries"].append("2001:db8::/32")
    assert "clients" in source_group_nat_validation_errors(groups, [row])
    row.enabled = False
    consumers = source_group_consumers("clients", groups, {}, [], [row])
    assert consumers == [{"kind": "port_forward", "label": "Port forward: web", "detail": "Source restriction"}]
    assert "clients" in source_group_nat_validation_errors(groups, [row], include_disabled=True)


@pytest.mark.parametrize("change", [
    {"ingress_interface": "missing"}, {"listener_address": "192.0.2.99"},
    {"target_address": "10.1.1.20"}, {"target_address": "192.0.2.1"},
    {"source": "missing-group"},
    {"external_port_start": 22, "external_port_end": 24},
])
def test_disabled_replacement_revalidates_bindings_and_preserves_saved_rule(change):
    """Disabled replacements cannot clear archive review with unsafe bindings.

    Args:
        change: Invalid replacement binding or service collision.
    """
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(interfaces())
        db.commit()
        saved = save_port_forward(db, PortForwardCreate(**payload(enabled=False)), actor="operator")
        saved.restore_review_required = True
        db.commit()
        rule_id = saved.id
        with pytest.raises(ValueError):
            save_port_forward(db, PortForwardCreate(**payload(enabled=False, **change)),
                              actor="operator", rule_id=rule_id)
        db.expire_all()
        restored = db.get(PortForward, rule_id)
        assert restored.ingress_interface == "eth1"
        assert restored.target_address == "198.51.100.10"
        assert restored.restore_review_required is True
        assert len(list(db.scalars(select(AuditEvent)))) == 1


def test_failed_overlap_preserves_row_and_audit_atomically():
    """A rejected complete replacement cannot leave changed values or an audit."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all(interfaces())
        db.commit()
        saved = save_port_forward(db, PortForwardCreate(**payload()), actor="operator")
        other = save_port_forward(db, PortForwardCreate(**payload(name="other", external_port_start=14000, external_port_end=14002)), actor="operator")
        with pytest.raises(ValueError, match="overlap"):
            save_port_forward(db, PortForwardCreate(**payload(name="changed")), actor="operator", rule_id=other.id)
        db.expire_all()
        assert db.get(PortForward, other.id).external_port_start == 14000
        assert db.get(PortForward, saved.id).name == "web"
        assert len(list(db.scalars(select(AuditEvent)))) == 2


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_helper_translates_each_range_port_to_its_exact_offset(family, protocol, tmp_path):
    """The privileged renderer must not treat a mapped range as a random pool.

    Args:
        family: Destination translation family.
        protocol: TCP or UDP header carrying the port.
        tmp_path: Task-owned helper input directory.
    """
    helper = load_helper_module()
    values = payload(ip_family=family, protocol=protocol)
    if family == 6:
        values.update(listener_address="2001:db8:2::1", target_address="2001:db8:3::10")
    row = PortForward(id=1, **values)
    config = render_nat_config([], nat_targets(interfaces(), []), [], TrafficPublishingSettings(False, True))
    config += render_port_forward_records([row], [])
    path = tmp_path / "nat.conf"
    path.write_text(config)
    parsed = helper._parse_wan_config(path)
    rows = helper._port_forward_records(parsed)
    program = helper._render_wan_nat_config([], {"eth1": 11}, rows)
    assert 'meta iif 11 iifname "eth1"' in program
    assert f'{protocol} dport map {{ 12000 : 13000, 12001 : 13001, 12002 : 13002 }}' in program
    assert 'ct mark 0xa7000001 ct status dnat return' in program
    assert 'type filter hook forward priority -10' in program
    assert 'ct original proto-dst 12000-12002' in program
    assert 'counter pf_1' in program
    assert 'hook output' not in program
    row.reply_mode = "masquerade"
    parsed = helper._parse_wan_config(path, content=config.split("[port_forwards]")[0] + render_port_forward_records([row], []))
    assert 'ct mark 0xa7000001 ct status dnat masquerade' in helper._render_wan_nat_config([], {"eth1": 11}, helper._port_forward_records(parsed))
    parsed["feature_settings"][0]["routing_enabled"] = "false"
    assert helper._port_forward_records(parsed) == []


def test_status_never_reuses_counters_from_an_old_mapping():
    """Changing a target or Source Group makes the previous counters pending."""
    row = PortForward(id=1, **payload())
    record = json.loads(render_port_forward_records([row], []).split("json=", 1)[1])[0]
    fingerprint = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    observation = {"available": True, "rules": [{"id": 1, "snapshot_hash": fingerprint,
                    "state": "applied", "packets": 12, "bytes": 900}]}
    status = port_forward_status([row], [], routing_enabled=True, observation=observation)[0]
    assert (status.state, status.packets, status.bytes) == ("applied", 12, 900)
    row.target_address = "198.51.100.11"
    status = port_forward_status([row], [], routing_enabled=True, observation=observation)[0]
    assert (status.state, status.packets, status.bytes) == ("pending", None, None)
    row.enabled = False
    assert port_forward_status([row], [], routing_enabled=True, observation=observation)[0].state == "pending"


def test_status_cli_has_no_mutation_or_recovery_side_effects(tmp_path, monkeypatch, capsys):
    """A status read admits zero paths and emits one bounded JSON observation.

    Args:
        tmp_path: Isolated task-owned runtime root.
        monkeypatch: Replace filesystem constants and forbid every mutation path.
        capsys: Capture the exact public helper output.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "NAT_RUNTIME_CONFIG_PATH", tmp_path / "absent.conf")

    def forbidden(*args, **kwargs):
        """Fail when observation attempts recovery, writes, or systemd execution.

        Args:
            *args: Unexpected mutation arguments.
            **kwargs: Unexpected mutation options.
        """
        pytest.fail("Status invoked a mutating path")

    monkeypatch.setattr(helper, "_nat_recover", forbidden)
    monkeypatch.setattr(helper, "_nat_write", forbidden)
    monkeypatch.setattr(helper, "_run_real_action_with_systemd", forbidden)
    assert helper.main(["atlaso-helper", "nat", "status", "--real"]) == 0
    assert json.loads(capsys.readouterr().out) == {"available": True, "rules": []}
    assert helper._handle_nat("status", ["unexpected"]) == 2


@pytest.mark.parametrize("change,error", [
    ("none", ""), ("owned_target", "live appliance addresses"),
    ("management_target", "non-lab appliance network"),
    ("broadcast_target", "broadcast"), ("tentative", "live appliance addresses"),
    ("wildcard_socket", "live appliance service"), ("exact_socket", "live appliance service"),
    ("loopback_socket", ""), ("unselected_socket", ""),
])
def test_helper_rechecks_actual_addresses_and_owned_sockets(monkeypatch, change, error):
    """Desired validation cannot bypass changed kernel addresses or local listeners.

    Args:
        monkeypatch: Replace fixed read-only host probes.
        change: One changed kernel boundary.
        error: Expected rejection, or empty when the exact ingress stays safe.
    """
    helper = load_helper_module()
    row = {**payload(), "id": 1, "source_networks": []}
    parsed = {"targets": [{"name": "eth1"}]}
    addresses = [
        {"ifname": "eth0", "addr_info": [{"local": "10.1.1.1", "prefixlen": 24}]},
        {"ifname": "eth1", "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]},
    ]
    sockets = ""
    if change == "owned_target":
        row["target_address"] = "10.1.1.1"
    elif change == "management_target":
        row["target_address"] = "10.1.1.20"
    elif change == "broadcast_target":
        row["target_address"] = "192.0.2.255"
    elif change == "tentative":
        addresses[1]["addr_info"][0]["tentative"] = True
    elif change.endswith("socket"):
        address = {"wildcard_socket": "0.0.0.0", "exact_socket": "192.0.2.1",
                   "loopback_socket": "127.0.0.1", "unselected_socket": "10.1.1.1"}[change]
        sockets = f"tcp LISTEN 0 128 {address}:12001 0.0.0.0:*\n"

    def run(command):
        """Return one bounded kernel inventory snapshot.

        Args:
            command: Exact address or socket inventory command.
        """
        if command == ["ip", "-j", "address", "show"]:
            return subprocess.CompletedProcess(command, 0, json.dumps(addresses), "")
        assert command == ["ss", "-H", "-l", "-n", "-t", "-u"]
        return subprocess.CompletedProcess(command, 0, sockets, "")

    monkeypatch.setattr(helper, "_wan_nat_interface_indexes", lambda *args: {"eth1": 11})
    monkeypatch.setattr(helper, "_run", run)
    if error:
        with pytest.raises(ValueError, match=error):
            helper._port_forward_observed_interfaces(parsed, [row])
    else:
        assert helper._port_forward_observed_interfaces(parsed, [row]) == {"eth1": 11}


@pytest.mark.parametrize("enabled,routing,available,expected", [
    (False, True, True, "disabled"), (True, False, True, "suspended"),
    (True, True, True, "pending"), (False, True, False, "degraded"),
])
def test_unobserved_status_retains_uncertainty(enabled, routing, available, expected):
    """Absent observations never fabricate zero counters or applied state.

    Args:
        enabled: Desired per-rule switch.
        routing: Desired global forwarding switch.
        available: Whether the read-only helper could prove runtime state.
        expected: Required bounded state.
    """
    row = PortForward(id=1, **payload(enabled=enabled))
    status = port_forward_status([row], [], routing_enabled=routing, observation={"available": available, "rules": []})[0]
    assert status.state == expected
    assert status.packets is None and status.bytes is None


@pytest.mark.parametrize("returncode,stderr,succeeds", [
    (0, "conntrack v1.4.8 (conntrack-tools): 2 flow entries have been deleted.", True),
    (1, "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n", True),
    (1, "Operation not permitted", False), (127, "conntrack unavailable", False),
])
def test_retirement_selects_only_owned_marks_in_both_families(monkeypatch, returncode, stderr, succeeds):
    """Empty selection is allowed; failures cannot trigger a broad flush fallback.

    Args:
        monkeypatch: Replace only the privileged command boundary.
        returncode: Simulated conntrack command status.
        stderr: Bounded tool diagnostic.
        succeeds: Whether connection retirement is proven.
    """
    helper = load_helper_module()
    commands = []

    def run(command):
        """Record the exact deletion selector.

        Args:
            command: Fixed allowlisted conntrack operation.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, returncode, "", stderr)

    monkeypatch.setattr(helper, "_run", run)
    if succeeds:
        helper._retire_port_forward_connections()
        assert [command[3] for command in commands] == ["ipv4", "ipv6"]
    else:
        with pytest.raises(ValueError, match="retirement failed"):
            helper._retire_port_forward_connections()
    assert all(command[1] == "--delete" and command[-2:] == ["--mark", "0xa7000000/0xff000000"] for command in commands)
