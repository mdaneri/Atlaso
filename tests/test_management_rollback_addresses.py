"""Verify rollback waits for authoritative ownership of prior management addresses."""

import copy
import json
import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module


@pytest.mark.parametrize("failure", ["none", "lease", "nginx-validation"])
def test_depot_listener_rollback_rechecks_addresses_before_its_nginx_restart(monkeypatch, failure):
    """The generic Depot restorer cannot bypass the final nginx ownership gate.

    Args:
        monkeypatch: Pytest fixture for replacing helper dependencies.
        failure: Injected rollback or nginx-validation failure mode.
    """
    helper = load_helper_module()
    state = rollback_state()
    prior = {"active": True, "enabled": True, "enabled_state": "enabled"}
    state["listener_service_states"] = {"vcf_offline_depot": dict(prior), "kms": dict(prior)}
    events = []

    def wait(_state):
        """Record address readiness and optionally reject a missing lease.

        Args:
            _state: Rollback snapshot passed to the address waiter.
        """
        events.append("native-address-check")
        if failure == "lease":
            raise ValueError("restored lease disappeared")

    monkeypatch.setattr(helper, "_wait_restored_management_addresses", wait)
    monkeypatch.setattr(helper, "_nginx_binary", lambda: "nginx")
    monkeypatch.setattr(helper, "_nginx_test_command", lambda: events.append("nginx-test")
                        or subprocess.CompletedProcess([], int(failure == "nginx-validation")))
    monkeypatch.setattr(helper, "_run", lambda command: events.append(" ".join(command))
                        or subprocess.CompletedProcess(command, 0))
    monkeypatch.setattr(helper, "_management_handoff_listener_unit_state", lambda _unit: dict(prior))
    monkeypatch.setattr(helper, "_verify_management_handoff_listener_runtime",
                        lambda service, _moves: events.append("verify-" + service))
    if failure != "none":
        with pytest.raises(ValueError, match="vcf_offline_depot"):
            helper._restore_management_handoff_listener_services(state, [])
        assert "systemctl restart nginx.service" not in events
    else:
        helper._restore_management_handoff_listener_services(state, [])
        assert events.index("native-address-check") < events.index("nginx-test")
        assert events.index("nginx-test") < events.index("systemctl restart nginx.service")
        assert events.index("systemctl restart nginx.service") < events.index("verify-vcf_offline_depot")
    assert "systemctl restart atlaso-kmip.service" in events


def rollback_state(*, paths=None, routing=None, addresses=None):
    """Return an immutable management-address snapshot for rollback tests.

    Args:
        paths: Prior management paths with their address methods and families.
        routing: Prior interface identity, CIDR, routes, and table snapshots.
        addresses: Prior management listener addresses.
    """
    return {
        "previous_management_addresses": addresses or ["192.0.2.10"],
        "previous_management_paths": paths or [
            {"name": "eth0", "ipv4_method": "dhcp", "ipv6_enabled": "false", "ipv6_cidr": ""}
        ],
        "previous_management_routing": routing or {
            "eth0": {"mac": "00:11:22:33:44:55", "cidrs": ["192.0.2.10/24"], "routes": [], "table": 100}
        },
    }


def observed_link(*, name="eth0", mac="00:11:22:33:44:55", ifindex=2, addresses=None):
    """Return complete, configured native evidence for one restored interface.

    Args:
        name: Observed native interface name.
        mac: Observed hardware address.
        ifindex: Observed kernel interface index.
        addresses: Observed interface address rows, or the default IPv4 row.
    """
    return {
        "name": name,
        "mac": mac,
        "ifindex": ifindex,
        "configured": True,
        "up": True,
        "address_inventory_complete": True,
        "addresses": addresses if addresses is not None else [
            {
                "address": "192.0.2.10",
                "cidr": "192.0.2.10/24",
                "scope": "global",
                "source": "static",
                "dhcp4_lease": True,
                "state": "assigned",
            }
        ],
    }


def native_observation(*links, complete=True):
    """Wrap native link rows in the helper observation contract.

    Args:
        *links: Observed native interface rows.
        complete: Whether the full native inventory was collected.
    """
    return {"complete": complete, "links": list(links), "conflicts": []}


def test_restored_address_wait_resets_streak_until_dhcp_lease_is_stable(monkeypatch):
    """Require three consecutive ready samples after withdrawal and ACD checking.

    Args:
        monkeypatch: Pytest fixture for replacing sleep and observation calls.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    expected = observed_link()
    missing = observed_link(addresses=[])
    checking = observed_link(addresses=[{
        "address": "192.0.2.10", "cidr": "192.0.2.10/24", "scope": "global",
        "source": "static", "dhcp4_lease": True, "state": "checking",
    }])
    samples = iter([
        native_observation(expected),
        native_observation(missing),
        native_observation(checking),
        native_observation(expected),
        native_observation(expected),
        native_observation(expected),
    ])
    seen = []

    def observe():
        seen.append(True)
        return next(samples)

    monkeypatch.setattr(helper, "_network_address_observation", observe)

    evidence = helper._wait_restored_management_addresses(rollback_state(), attempts=6)

    assert evidence == {"stable_samples": 3, "addresses": ["192.0.2.10"]}
    assert len(seen) == 6


def test_restored_address_requires_exact_static_ipv4_ipv6_and_slaac_sources(monkeypatch):
    """Accept prior static addresses and a native SLAAC address on exact links.

    Args:
        monkeypatch: Pytest fixture for replacing the native observation.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    state = rollback_state(
        addresses=["192.0.2.10", "2001:db8::10", "2001:db8:1::10"],
        paths=[
            {"name": "eth0", "ipv4_method": "static", "ipv6_enabled": "true",
             "ipv6_cidr": "2001:db8::10/64"},
            {"name": "eth1", "ipv4_method": "", "ipv6_enabled": "true", "ipv6_cidr": ""},
        ],
        routing={
            "eth0": {
                "mac": "00:11:22:33:44:55",
                "cidrs": ["192.0.2.10/24", "2001:db8::10/64"],
                "routes": [],
                "table": 100,
            },
            "eth1": {"mac": "00:11:22:33:44:66", "cidrs": ["2001:db8:1::10/64"], "routes": [], "table": 200},
        },
    )
    links = [
        observed_link(addresses=[
            {"address": "192.0.2.10", "cidr": "192.0.2.10/24", "scope": "global",
             "source": "static", "state": "assigned"},
            {"address": "2001:db8::10", "cidr": "2001:db8::10/64", "scope": "global",
             "source": "static", "state": "assigned"},
        ]),
        observed_link(name="eth1", mac="00:11:22:33:44:66", ifindex=3, addresses=[
            {"address": "2001:db8:1::10", "cidr": "2001:db8:1::10/64", "scope": "global",
             "source": "NDisc", "state": "assigned"},
        ]),
    ]
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native_observation(*links))

    evidence = helper._wait_restored_management_addresses(state, attempts=3)

    assert evidence == {
        "stable_samples": 3,
        "addresses": sorted(["192.0.2.10", "2001:db8::10", "2001:db8:1::10"]),
    }


@pytest.mark.parametrize("invalid", [
    "missing-lease", "wrong-lease", "wrong-interface", "wrong-mac", "wrong-address",
    "wrong-prefix", "incomplete-observation", "incomplete-address-inventory", "configuring",
])
def test_restored_dhcp_address_rejects_missing_or_wrong_native_ownership(monkeypatch, invalid):
    """Do not accept an address without exact live DHCP and link identity evidence.

    Args:
        monkeypatch: Pytest fixture for replacing sleep and native observation.
        invalid: Ownership-evidence defect to inject into the native sample.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    link = observed_link()
    complete = True
    if invalid == "missing-lease":
        link["addresses"][0].pop("dhcp4_lease")
    elif invalid == "wrong-lease":
        link["addresses"][0]["dhcp4_lease"] = False
    elif invalid == "wrong-interface":
        link["name"] = "eth1"
    elif invalid == "wrong-mac":
        link["mac"] = "00:11:22:33:44:66"
    elif invalid == "wrong-address":
        link["addresses"][0]["address"] = "192.0.2.11"
        link["addresses"][0]["cidr"] = "192.0.2.11/24"
    elif invalid == "wrong-prefix":
        link["addresses"][0]["cidr"] = "192.0.2.10/25"
    elif invalid == "incomplete-observation":
        complete = False
    elif invalid == "incomplete-address-inventory":
        link["address_inventory_complete"] = False
    elif invalid == "configuring":
        link["configured"] = False
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native_observation(link, complete=complete))

    with pytest.raises(ValueError, match="did not acquire stable native ownership"):
        helper._wait_restored_management_addresses(rollback_state(), attempts=3)


@pytest.mark.parametrize("inventory_state", ["truncated", "malformed"])
def test_restored_address_rejects_incomplete_competing_link_inventory(monkeypatch, inventory_state):
    """An incomplete non-target link cannot be excluded from address uniqueness.

    Args:
        monkeypatch: Pytest fixture for replacing sleep and native observation.
        inventory_state: Whether the competing inventory is truncated or malformed.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    target = observed_link()
    rows = []
    if inventory_state == "truncated":
        rows = [
            {
                "address": f"203.0.113.{index}",
                "cidr": f"203.0.113.{index}/24",
                "scope": "global",
                "source": "static",
                "state": "assigned",
            }
            for index in range(1, 33)
        ]
    competing = observed_link(
        name="eth1", mac="00:11:22:33:44:66", ifindex=3, addresses=rows,
    )
    competing["address_inventory_complete"] = False
    observations = []

    def observe():
        observations.append(True)
        return native_observation(target, competing)

    monkeypatch.setattr(helper, "_network_address_observation", observe)

    with pytest.raises(ValueError, match="did not acquire stable native ownership"):
        helper._wait_restored_management_addresses(rollback_state(), attempts=3)
    assert len(observations) == 3


def test_restored_address_wait_stabilizes_only_after_competing_inventory_completes(monkeypatch):
    """Resume stability only after every observed link has a complete address list.

    Args:
        monkeypatch: Pytest fixture for replacing sleep and native observation.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    observations = []

    def observe():
        complete = len(observations) >= 2
        observations.append(complete)
        target = observed_link()
        competing = observed_link(
            name="eth1", mac="00:11:22:33:44:66", ifindex=3, addresses=[],
        )
        competing["address_inventory_complete"] = complete
        return native_observation(target, competing)

    monkeypatch.setattr(helper, "_network_address_observation", observe)

    evidence = helper._wait_restored_management_addresses(rollback_state(), attempts=5)

    assert evidence == {"stable_samples": 3, "addresses": ["192.0.2.10"]}
    assert observations == [False, False, True, True, True]


def test_restored_address_conflict_fails_immediately(monkeypatch):
    """A native conflict cannot become ready through repeated observations.

    Args:
        monkeypatch: Pytest fixture for replacing sleep and native observation.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    link = observed_link()
    link["addresses"][0]["state"] = "conflict"
    observations = []
    monkeypatch.setattr(
        helper, "_network_address_observation",
        lambda: observations.append(True) or native_observation(link),
    )

    with pytest.raises(ValueError, match="native conflict"):
        helper._wait_restored_management_addresses(rollback_state(), attempts=3)
    assert len(observations) == 1


def test_restored_address_index_change_resets_stability(monkeypatch):
    """A link identity change restarts the stable-sample streak.

    Args:
        monkeypatch: Pytest fixture for replacing sleep and native observation.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    indices = iter([2, 2, 3, 3, 3])
    observations = []

    def observe():
        index = next(indices)
        observations.append(index)
        return native_observation(observed_link(ifindex=index))

    monkeypatch.setattr(helper, "_network_address_observation", observe)

    evidence = helper._wait_restored_management_addresses(rollback_state(), attempts=5)

    assert evidence["stable_samples"] == 3
    assert observations == [2, 2, 3, 3, 3]


def test_restored_address_rejects_duplicate_owner_on_second_interface(monkeypatch):
    """The same restored listener address cannot be claimed by two prior links.

    Args:
        monkeypatch: Pytest fixture for replacing native observation.
    """
    helper = load_helper_module()
    state = rollback_state(
        routing={
            "eth0": {"mac": "00:11:22:33:44:55", "cidrs": ["192.0.2.10/24"], "routes": [], "table": 100},
            "eth1": {"mac": "00:11:22:33:44:66", "cidrs": ["192.0.2.10/24"], "routes": [], "table": 200},
        },
        paths=[
            {"name": "eth0", "ipv4_method": "dhcp", "ipv6_enabled": "false", "ipv6_cidr": ""},
            {"name": "eth1", "ipv4_method": "dhcp", "ipv6_enabled": "false", "ipv6_cidr": ""},
        ],
    )
    monkeypatch.setattr(
        helper, "_network_address_observation",
        lambda: pytest.fail("ambiguous immutable ownership must fail before probing"),
    )

    with pytest.raises(ValueError, match="ownership is ambiguous"):
        helper._wait_restored_management_addresses(state, attempts=1)


@pytest.mark.parametrize("state", [
    {},
    {"previous_management_addresses": ["192.0.2.10"]},
    {"previous_management_addresses": ["192.0.2.10"], "previous_management_routing": {"eth0": {
        "mac": "00:11:22:33:44:55", "cidrs": ["192.0.2.10/24"],
    }}},
    {"previous_management_addresses": ["192.0.2.10"], "previous_management_paths": [{
        "name": "eth0", "ipv4_method": "dhcp", "ipv6_enabled": "false", "ipv6_cidr": "",
    }]},
])
def test_restored_address_requires_immutable_interface_ownership_snapshot(monkeypatch, state):
    """Legacy/incomplete journal metadata cannot guess which link owned DHCP.

    Args:
        monkeypatch: Pytest fixture for rejecting any native observation.
        state: Incomplete rollback snapshot to validate.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_network_address_observation", lambda: pytest.fail("must fail before probing"))

    with pytest.raises(
        ValueError,
        match="ownership snapshot is missing|identity snapshot is missing|snapshot is incomplete",
    ):
        helper._wait_restored_management_addresses(state, attempts=1)


def test_recovery_keeps_journal_and_skips_routes_and_nginx_when_address_is_unready(
    monkeypatch, tmp_path, capsys,
):
    """Supported recovery retains its marker and does not activate nginx without old ownership.

    Args:
        monkeypatch: Pytest fixture for replacing recovery dependencies.
        tmp_path: Isolated directory for the marker and networkd fixture.
        capsys: Pytest fixture for checking bounded recovery diagnostics.
    """
    helper = load_helper_module()
    state = rollback_state()
    state.update({
        "snapshots": [],
        "previous_route_domain_service": {"active": False, "enabled": False},
        "previous_route_domain_rules": [],
        "previous_management_routing": {
            "eth0": {"mac": "00:11:22:33:44:55", "cidrs": ["192.0.2.10/24"], "routes": [], "table": 100}
        },
        "listener_service_states": {"dns": {"active": True, "enabled": True}},
    })
    marker = tmp_path / "state.json"
    marker.write_text(json.dumps(state), encoding="utf-8")
    marker_before = marker.read_bytes()
    networkd = tmp_path / "networkd"
    networkd.mkdir()
    monkeypatch.setattr(helper, "MANAGEMENT_HANDOFF_STATE_PATH", marker)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", networkd / "00-atlaso-mgmt.network")
    monkeypatch.setattr(helper, "NAT_RUNTIME_CONFIG_PATH", tmp_path / "missing-nat.conf")
    monkeypatch.setattr(helper, "_quiesce_management_handoff_apply", lambda: {"quiesced": True})
    monkeypatch.setattr(helper, "_capture_management_handoff_lease_updates", lambda _state: None)
    monkeypatch.setattr(helper, "_stop_route_domains_for_restore", lambda _state: None)
    monkeypatch.setattr(helper, "_quiesce_management_handoff_firewall", lambda *_args: None)
    monkeypatch.setattr(helper, "_restore_management_handoff_resolver", lambda *_args: None)
    events = []
    monkeypatch.setattr(helper, "_restore_management_handoff_links", lambda *_args: events.append("links"))
    monkeypatch.setattr(
        helper, "_wait_restored_management_addresses",
        lambda _state: events.append("address-check") or (_ for _ in ()).throw(ValueError("lease unavailable")),
    )
    monkeypatch.setattr(helper, "_restored_legacy_route_baseline", lambda _state: True)
    monkeypatch.setattr(helper, "_restore_legacy_route_domain_sources", lambda *_args: events.append("legacy-routes"))
    monkeypatch.setattr(helper, "_restore_route_domains", lambda *_args: events.append("routes"))
    monkeypatch.setattr(
        helper, "_restore_management_handoff_listener_services",
        lambda *_args: events.append("listeners"),
    )
    monkeypatch.setattr(helper, "_restore_management_handoff_wan", lambda *_args: None)
    monkeypatch.setattr(helper, "_restore_management_handoff_firewall", lambda *_args: None)
    monkeypatch.setattr(helper, "_nginx_binary", lambda: events.append("nginx-binary") or "/usr/sbin/nginx")
    monkeypatch.setattr(
        helper, "_nginx_test_command",
        lambda: events.append("nginx-test") or subprocess.CompletedProcess(["nginx", "-t"], 0, "", ""),
    )
    commands = []
    monkeypatch.setattr(
        helper, "_run",
        lambda command: commands.append(command) or subprocess.CompletedProcess(command, 0, "", ""),
    )
    monkeypatch.setattr(
        helper, "_clear_management_handoff_state",
        lambda **_kwargs: pytest.fail("cleared failed rollback journal"),
    )

    result = helper._recover_management_handoff()

    assert result == 1
    assert events == ["links", "address-check", "address-check"]
    assert not any(command[:2] == ["systemctl", "reload-or-restart"] and command[-1] == "nginx.service"
                   for command in commands)
    assert not any(name in events for name in ("legacy-routes", "routes", "listeners", "nginx-test", "nginx-binary"))
    assert marker.exists()
    assert marker.read_bytes() == marker_before
    error = json.loads(capsys.readouterr().err)
    assert error["management_handoff"] == "rollback incomplete"
    assert error["failing_layer"] == "interruption recovery"


def test_recovery_waits_for_restored_lease_before_route_listener_and_nginx_activation(
    monkeypatch, tmp_path, capsys,
):
    """Successful supported recovery retains its journal through native and HTTP checks.

    Args:
        monkeypatch: Pytest fixture for replacing recovery dependencies.
        tmp_path: Isolated directory for the marker and networkd fixture.
        capsys: Pytest fixture for checking bounded recovery output.
    """
    helper = load_helper_module()
    state = rollback_state()
    state.update({
        "snapshots": [],
        "previous_route_domain_service": {"active": False, "enabled": False},
        "previous_route_domain_rules": [],
        "previous_management_routing": {
            "eth0": {"mac": "00:11:22:33:44:55", "cidrs": ["192.0.2.10/24"], "routes": [], "table": 100}
        },
        "listener_service_states": {"dns": {"active": True, "enabled": True}},
    })
    state_dir = tmp_path / "management-handoff"
    state_dir.mkdir()
    marker = state_dir / "state.json"
    marker.write_text(json.dumps(state), encoding="utf-8")
    marker_before = marker.read_bytes()
    networkd = tmp_path / "networkd"
    networkd.mkdir()
    monkeypatch.setattr(helper, "MANAGEMENT_HANDOFF_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "MANAGEMENT_HANDOFF_STATE_PATH", marker)
    monkeypatch.setattr(helper, "MANAGEMENT_HANDOFF_COMMIT_PATH", state_dir / "last-commit.json")
    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", networkd)
    monkeypatch.setattr(helper, "NETWORKD_MGMT_CONFIG_PATH", networkd / "00-atlaso-mgmt.network")
    monkeypatch.setattr(helper, "NAT_RUNTIME_CONFIG_PATH", tmp_path / "missing-nat.conf")
    monkeypatch.setattr(helper, "_quiesce_management_handoff_apply", lambda: {"quiesced": True})
    monkeypatch.setattr(helper, "_capture_management_handoff_lease_updates", lambda _state: None)
    monkeypatch.setattr(helper, "_stop_route_domains_for_restore", lambda _state: None)
    monkeypatch.setattr(helper, "_quiesce_management_handoff_firewall", lambda *_args: None)
    monkeypatch.setattr(helper, "_restore_management_handoff_resolver", lambda *_args: None)
    events = []
    monkeypatch.setattr(helper, "_restore_management_handoff_links", lambda *_args: events.append("links"))
    observations = 0

    def observe():
        """Withdraw the DHCP address once, then expose its stable native lease."""
        nonlocal observations
        observations += 1
        events.append(f"native-{observations}")
        if observations == 1:
            return native_observation(observed_link(addresses=[]))
        return native_observation(observed_link())

    monkeypatch.setattr(helper, "_network_address_observation", observe)
    original_wait = helper._wait_restored_management_addresses

    def wait_without_mutating_snapshot(current_state, **kwargs):
        """Run the waiter and prove it leaves journal state untouched.

        Args:
            current_state: Rollback snapshot passed to the real waiter.
            **kwargs: Waiter options forwarded to the real implementation.
        """
        before = copy.deepcopy(current_state)
        evidence = original_wait(current_state, **kwargs)
        assert current_state == before
        events.append("addresses-ready")
        return evidence

    monkeypatch.setattr(helper, "_wait_restored_management_addresses", wait_without_mutating_snapshot)
    monkeypatch.setattr(helper, "_restored_legacy_route_baseline", lambda _state: True)
    monkeypatch.setattr(helper, "_restore_legacy_route_domain_sources", lambda *_args: events.append("legacy-routes"))
    monkeypatch.setattr(helper, "_restore_route_domains", lambda *_args: events.append("routes"))
    monkeypatch.setattr(
        helper, "_restore_management_handoff_listener_services",
        lambda *_args: events.append("listeners"),
    )
    monkeypatch.setattr(helper, "_restore_management_handoff_wan", lambda *_args: None)
    monkeypatch.setattr(helper, "_restore_route_domain_rules", lambda *_args: events.append("route-rules"))
    monkeypatch.setattr(helper, "_retire_transition_routes", lambda *_args, **_kwargs: events.append("retire-seeds"))
    monkeypatch.setattr(helper, "_restore_management_handoff_firewall", lambda *_args: None)
    monkeypatch.setattr(helper, "_nginx_binary", lambda: events.append("nginx-binary") or "/usr/sbin/nginx")
    monkeypatch.setattr(
        helper, "_nginx_test_command",
        lambda: events.append("nginx-validation") or subprocess.CompletedProcess(["nginx", "-t"], 0, "", ""),
    )

    def run(command):
        """Record required systemd activation and return successful completion.

        Args:
            command: System command issued by the recovery helper.
        """
        if command[:2] == ["systemctl", "start"] or command[:2] == ["systemctl", "reload-or-restart"]:
            events.append(" ".join(command))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(
        helper, "_management_handoff_readiness",
        lambda *_args, **_kwargs: events.append("old-path-http-readiness") or {"stable_samples": 3},
    )
    original_clear = helper._clear_management_handoff_state

    def clear_after_checks(**kwargs):
        """Verify the original marker remains until every readiness layer passed.

        Args:
            **kwargs: Marker-clear options forwarded to the real implementation.
        """
        assert marker.exists()
        assert marker.read_bytes() == marker_before
        assert "nginx-validation" in events
        assert "systemctl reload-or-restart nginx.service" in events
        assert "old-path-http-readiness" in events
        events.append("clear-journal")
        original_clear(**kwargs)

    monkeypatch.setattr(helper, "_clear_management_handoff_state", clear_after_checks)

    result = helper._recover_management_handoff()

    assert result == 0
    assert events.index("native-4") < events.index("legacy-routes")
    assert events.index("addresses-ready") < events.index("legacy-routes")
    assert events.index("legacy-routes") < events.index("routes") < events.index("listeners")
    assert events.index("addresses-ready", events.index("listeners")) < events.index("nginx-validation")
    assert events.index("nginx-validation") < events.index("systemctl reload-or-restart nginx.service")
    assert events.index("systemctl reload-or-restart nginx.service") < events.index("old-path-http-readiness")
    assert events.index("old-path-http-readiness") < events.index("clear-journal")
    assert not marker.exists()
    output = json.loads(capsys.readouterr().out)
    assert output["management_handoff"] == "rolled back after interruption"
