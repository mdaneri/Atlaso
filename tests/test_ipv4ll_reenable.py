"""Re-enable fallback from an intentionally unaddressed DHCP baseline."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from atlaso.app.models import PhysicalInterface
from atlaso.app.services.networking import render_network_config
from tests.test_appliance_helper import load_helper_module

KERNEL_IPV6_MULTICAST = {
    "type": "multicast", "dst": "ff00::/8", "table": "local", "protocol": "kernel",
    "scope": "global", "metric": 256, "flags": [], "pref": "medium",
}


@pytest.fixture
def reenable(tmp_path, monkeypatch):
    """Model the real transaction and route capture without host operations.

    Args:
        tmp_path: Originally owned pytest output directory.
        monkeypatch: Replace appliance paths, durability and native observations.
    """
    helper = load_helper_module()
    networkd = tmp_path / "networkd"
    networkd.mkdir()
    transaction = tmp_path / "transaction"
    transaction.mkdir()
    monkeypatch.setattr(helper, "NETWORKD_CONFIG_DIR", networkd)
    for name, path in {
        "NETWORK_TRANSACTION_DIR": transaction,
        "NETWORKD_MGMT_CONFIG_PATH": networkd / "00-atlaso-mgmt.network",
        "ROUTE_DOMAIN_CONFIG_PATH": tmp_path / "route-domains.json",
        "ROUTE_DOMAIN_SERVICE_PATH": tmp_path / "route-domains.service",
    }.items():
        monkeypatch.setattr(helper, name, path)
    monkeypatch.setattr(helper, "_read_existing_management_network_values",
                        lambda *_args: {"Name": ["eth0"], "DNS": [], "Domains": [], "Gateway": []})
    interface = PhysicalInterface(name="eth0", mac_address="02:00:00:00:10:77", role="management",
                                  mode="access", admin_state="up", oper_state="up", mtu=1500,
                                  ipv4_method="dhcp", ipv6_enabled=False, check_duplicate_ip_addresses=True)
    native = {"addresses": [], "routes": [], "mac": interface.mac_address,
              "route_reads": [], "runtime_address_reads": []}

    def observe(command, **_kwargs):
        """Return a complete empty native baseline, or an injected refusal case.

        Args:
            command: Exact address or route query.
            **_kwargs: Bounded command options.
        """
        if "address" in command:
            rows = [{"ifname": "eth0", "address": native["mac"]}]
            if native["addresses"] is not None:
                rows[0]["addr_info"] = native["addresses"]
        else:
            native["route_reads"].append(command)
            family = 6 if "-6" in command else 4
            rows = native.get("routes_by_family", {}).get(family, native["routes"])
        return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

    def run_native(command, **kwargs):
        """Allow the Linux runtime-address read while refusing every mutation.

        Args:
            command: Exact read-only address query from the production renderer.
            **kwargs: Options forwarded to the native observation fixture.
        """
        if command != ["ip", "-j", "address", "show", "dev", "eth0"]:
            pytest.fail("No old route may be invented")
        native["runtime_address_reads"].append(command)
        return observe(command, **kwargs)

    # Exercise the iproute2-present branch on every platform without consulting
    # host interfaces or weakening the assertion against native route writes.
    monkeypatch.setattr(helper, "shutil", SimpleNamespace(**{
        **vars(helper.shutil), "which": lambda name: "/fixture/bin/ip" if name == "ip" else None,
    }))
    monkeypatch.setattr(helper, "_run", run_native)
    config = tmp_path / "network.conf"
    config.write_text(render_network_config(interfaces=[interface], vlans=[],
                                            ipv4_link_local_fallback_enabled=False))
    files, _, _ = helper._systemd_networkd_files(config)
    old = networkd / "00-atlaso-mgmt.network"
    old.write_text(files[old.name])
    config.write_text(render_network_config(interfaces=[interface], vlans=[],
                                            ipv4_link_local_fallback_enabled=True))

    state = {}
    events = []
    monkeypatch.setattr(helper, "_network_observation_command", observe)
    monkeypatch.setattr(helper, "_preflight_route_domains", lambda: None)
    monkeypatch.setattr(helper, "_preflight_route_domain_capacity", lambda _path: None)
    monkeypatch.setattr(helper, "_management_handoff_candidate_links", lambda *_args, **_kwargs: ([], [], {}))
    monkeypatch.setattr(helper, "_snapshot_route_domain_service", lambda: {"active": False})
    monkeypatch.setattr(helper, "_snapshot_route_domain_rules", lambda: [])
    monkeypatch.setattr(helper, "_snapshot_transition_source_guard", lambda: False)
    monkeypatch.setattr(helper, "_network_transaction_state", lambda: dict(state))
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write",
                        lambda value, _path: state.update(value))
    monkeypatch.setattr(helper, "_finish_network_transaction", lambda *_args: True)
    monkeypatch.setattr(helper, "_restore_network_transaction", lambda *_args: events.append("rollback"))
    monkeypatch.setattr(helper, "_fsync_file", lambda *_args: None)
    monkeypatch.setattr(helper, "_fsync_directory", lambda *_args: None)
    return helper, config, old, native, state, events


def test_reenable_snapshots_empty_old_domain_without_inventing_routes(reenable):
    """A real disable/enable-only transaction can proceed to candidate acquisition.

    Args:
        reenable: Real rendered files and native observation model.
    """
    helper, config, _old, native, state, events = reenable
    bindings = [{"name": "eth0", "mac": native["mac"], "table": 100}]
    with helper._network_apply_transaction(config):
        helper._seed_transition_routes(state, bindings, config.parent / "state.json")
    assert events == []
    assert native["runtime_address_reads"]
    assert len(native["route_reads"]) == 2
    assert state["previous_management_routing"]["eth0"] == {
        "mac": native["mac"], "table": 100, "cidrs": [], "ipv4ll_cidrs": [], "routes": [],
    }
    assert state["transition_seed_routes"] == []
    # The scoped admission cannot leak into an unrelated later transition.
    with pytest.raises(ValueError, match="assigned addresses are missing"):
        helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})


@pytest.mark.parametrize("explicit_device", [False, True])
@pytest.mark.parametrize("table", ["local", "255", 255])
def test_reenable_accepts_only_inert_kernel_local_multicast(reenable, explicit_device, table):
    """Reproduce Photon's real disabled-boot inventory without inventing old routes.

    Args:
        reenable: Real transaction and native observation model.
        explicit_device: iproute2 may omit the device already selected by the query.
        table: Equivalent native names for the kernel local table.
    """
    helper, config, _old, native, state, events = reenable
    route = {**KERNEL_IPV6_MULTICAST, "table": table}
    if explicit_device:
        route["dev"] = "eth0"
    native["routes_by_family"] = {4: [], 6: [route]}
    with helper._network_apply_transaction(config):
        helper._seed_transition_routes(state, [{"name": "eth0", "table": 100}], config.parent / "state.json")
    assert events == []
    assert state["previous_management_routing"]["eth0"]["routes"] == []
    assert state["transition_seed_routes"] == []
    assert len(native["route_reads"]) == 2
    with pytest.raises(ValueError, match="assigned addresses are missing"):
        helper._snapshot_management_handoff_routing(["eth0"], {"eth0": 100})


@pytest.mark.parametrize("change", [
    {"type": "unicast"}, {"dst": "ff02::/16"}, {"table": "main"}, {"protocol": "static"},
    {"scope": "link"}, {"metric": 512}, {"flags": ["linkdown"]}, {"pref": "high"},
    {"dev": "eth1"}, {"gateway": "fe80::1"}, {"from": "2001:db8::/64"}, {"nhid": 7},
    {"multipath": []}, {"encap": {}}, {"unexpected": True},
    {"table": []}, {"table": None}, {"table": 255.0}, {"metric": 256.0}, {"flags": None},
])
def test_reenable_refuses_altered_multicast_inventory(reenable, change):
    """Do not turn the one native local-route exception into a routing exemption.

    Args:
        reenable: Real transaction and native observation model.
        change: Routed, ambiguous or unsupported native evidence.
    """
    helper, config, _old, native, state, events = reenable
    native["routes_by_family"] = {6: [{**KERNEL_IPV6_MULTICAST, **change}]}
    with pytest.raises(ValueError, match="existing routing-domain routes"):
        with helper._network_apply_transaction(config):
            helper._seed_transition_routes(state, [{"name": "eth0", "table": 100}], config.parent / "state.json")
    assert events == ["rollback"]


@pytest.mark.parametrize("missing", list(KERNEL_IPV6_MULTICAST))
def test_reenable_refuses_incomplete_multicast_inventory(reenable, missing):
    """A partial local-route observation cannot establish an inert native row.

    Args:
        reenable: Real transaction and native observation model.
        missing: Required native attribute omitted from the observation.
    """
    helper, config, _old, native, state, events = reenable
    route = dict(KERNEL_IPV6_MULTICAST)
    del route[missing]
    native["routes_by_family"] = {6: [route]}
    with pytest.raises(ValueError, match="existing routing-domain routes"):
        with helper._network_apply_transaction(config):
            helper._seed_transition_routes(state, [{"name": "eth0", "table": 100}], config.parent / "state.json")
    assert events == ["rollback"]


@pytest.mark.parametrize("family,routes", [
    (4, [KERNEL_IPV6_MULTICAST]),
    (6, [KERNEL_IPV6_MULTICAST, KERNEL_IPV6_MULTICAST]),
    (6, [KERNEL_IPV6_MULTICAST, {"dst": "2001:db8::/64", "table": 100}]),
])
def test_reenable_refuses_extra_or_wrong_family_routes(reenable, family, routes):
    """Require a complete empty unicast domain, with no hidden companion route.

    Args:
        reenable: Real transaction and native observation model.
        family: Native family inventory containing the unexpected evidence.
        routes: Wrong-family, duplicate or additional routed entries.
    """
    helper, config, _old, native, state, events = reenable
    native["routes_by_family"] = {family: routes}
    with pytest.raises(ValueError, match="existing routing-domain routes"):
        with helper._network_apply_transaction(config):
            helper._seed_transition_routes(state, [{"name": "eth0", "table": 100}], config.parent / "state.json")
    assert events == ["rollback"]


@pytest.mark.parametrize("change", [
    "other-edit", "already-enabled", "missing-pin", "missing-inventory", "tentative", "route", "global-no-route",
])
def test_reenable_refuses_unproven_empty_baseline(reenable, change):
    """Missing old state is not a generic exemption from route preservation.

    Args:
        reenable: Real transaction and native observation model.
        change: Unrelated intent change or incomplete/nonempty old state.
    """
    helper, config, old, native, state, events = reenable
    if change == "other-edit":
        old.write_text(old.read_text().replace("DHCP=ipv4", "DHCP=no"))
    elif change == "already-enabled":
        old.write_text(old.read_text().replace("enabled=false", "enabled=true"))
    elif change == "missing-pin":
        config.write_text(config.read_text().replace(helper.NETWORK_IDENTITY_PIN_MARKER, ""))
    elif change == "missing-inventory":
        native["addresses"] = None
    elif change == "tentative":
        native["addresses"] = [{"local": "192.0.2.10", "scope": "global", "prefixlen": 24,
                                "flags": ["tentative"]}]
    elif change == "global-no-route":
        native["addresses"] = [{"local": "192.0.2.10", "scope": "global", "prefixlen": 24}]
    else:
        native["routes"] = [{"dst": "192.0.2.0/24", "dev": "eth0", "table": 100}]
    with pytest.raises(ValueError):
        with helper._network_apply_transaction(config):
            helper._seed_transition_routes(state, [{"name": "eth0", "table": 100}], config.parent / "state.json")
    assert events == ["rollback"]


@pytest.mark.parametrize("multicast", [False, True])
def test_reenable_still_requires_native_candidate_acquisition(reenable, monkeypatch, multicast):
    """Allowing an empty previous domain cannot accept an empty candidate.

    Args:
        reenable: Real candidate intent and transaction model.
        monkeypatch: Provide complete but unaddressed candidate evidence.
        multicast: Retain the exact inert route observed on a disabled native boot.
    """
    helper, config, _old, native, state, _events = reenable
    if multicast:
        native["routes_by_family"] = {6: [KERNEL_IPV6_MULTICAST]}
    observation = {"complete": True, "links": [{"name": "eth0", "mac": native["mac"],
                   "configured": True, "up": True, "carrier": True, "addresses": []}], "conflicts": []}
    monkeypatch.setattr(helper, "_network_address_observation", lambda: observation)
    monkeypatch.setattr(helper, "_retain_network_conflicts", lambda *_args: None)
    with pytest.raises(ValueError, match="Unable to verify candidate addresses"):
        with helper._network_apply_transaction(config):
            helper._seed_transition_routes(state, [{"name": "eth0", "table": 100}], config.parent / "state.json")
            helper._wait_network_addresses(config, attempts=1)
