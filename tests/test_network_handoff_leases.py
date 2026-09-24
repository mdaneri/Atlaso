"""Verify independent lease evidence for same-address management handoffs."""

import copy
import json
import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module


def native_link():
    """Return networkd Describe evidence for a live same-address DHCP lease."""
    return {
        "Index": 2, "Name": "eth0", "AdministrativeState": "configured",
        "DHCPv4Client": {"Lease": {"LeaseTimestampUSec": 1000000, "Timeout2USec": 10000000}},
        "Addresses": [{"Address": [192, 0, 2, 10], "PrefixLength": 24, "ConfigSource": "static"}],
        "Routes": [{"Destination": [192, 0, 2, 1], "DestinationPrefixLength": 32,
                    "PreferredSource": [192, 0, 2, 10], "ConfigProvider": [192, 0, 2, 1],
                    "Scope": 253, "ConfigSource": "DHCPv4", "ConfigState": "configured"}],
    }


def set_clock(helper, monkeypatch, tmp_path):
    """Supply Linux boot-clock and lease-file evidence on every test host.

    Args:
        helper: Isolated privileged helper module.
        monkeypatch: Reversible clock replacement.
        tmp_path: Isolated native lease directory.
    """
    monkeypatch.setattr(helper.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(helper.time, "clock_gettime", lambda _clock: 5, raising=False)
    monkeypatch.setattr(helper, "SYSTEMD_NETWORK_LEASE_DIR", tmp_path)
    (tmp_path / "2").write_text(
        "ADDRESS=192.0.2.10\nNETMASK=255.255.255.0\nSERVER_ADDRESS=192.0.2.1\n", encoding="utf-8"
    )


@pytest.mark.parametrize("invalid", [
    "none", "wrong-link", "configuring", "no-client", "no-lease", "expired", "future",
    "missing-time", "static-route", "pending-route", "wrong-address", "wrong-server",
    "no-provider", "no-source", "boolean-index", "no-file", "duplicate-field", "bad-mask",
])
def test_same_address_lease_requires_live_identity_bound_proof(monkeypatch, tmp_path, invalid):
    """A retained address or stale lease cannot impersonate current DHCP ownership.

    Args:
        monkeypatch: Supply deterministic boot-clock evidence.
        tmp_path: Isolated native lease directory.
        invalid: Independently absent, stale, mismatched, or pending evidence field.
    """
    helper = load_helper_module()
    set_clock(helper, monkeypatch, tmp_path)
    link = native_link()
    route = link["Routes"][0]
    if invalid == "wrong-link":
        link["Index"] = 3
    elif invalid == "configuring":
        link["AdministrativeState"] = "configuring"
    elif invalid == "no-client":
        link.pop("DHCPv4Client")
    elif invalid == "no-lease":
        link["DHCPv4Client"].clear()
    elif invalid == "expired":
        link["DHCPv4Client"]["Lease"]["Timeout2USec"] = 4000000
    elif invalid == "future":
        link["DHCPv4Client"]["Lease"]["LeaseTimestampUSec"] = 6000000
    elif invalid == "missing-time":
        link["DHCPv4Client"]["Lease"].pop("LeaseTimestampUSec")
    elif invalid == "static-route":
        route["ConfigSource"] = "static"
    elif invalid == "pending-route":
        route["ConfigState"] = "requesting"
    elif invalid == "wrong-address":
        route["PreferredSource"] = [192, 0, 2, 11]
    elif invalid == "wrong-server":
        route["ConfigProvider"] = [192, 0, 2, 2]
    elif invalid == "no-file":
        (tmp_path / "2").unlink()
    elif invalid == "duplicate-field":
        with (tmp_path / "2").open("a", encoding="utf-8") as stream:
            stream.write("ADDRESS=192.0.2.11\n")
    elif invalid == "bad-mask":
        (tmp_path / "2").write_text("ADDRESS=192.0.2.10\nNETMASK=invalid\nSERVER_ADDRESS=192.0.2.1\n")
    elif invalid == "no-provider":
        route.pop("ConfigProvider")
    elif invalid == "no-source":
        route.pop("PreferredSource")
    result = helper._native_dhcp4_cidrs(link, True if invalid == "boolean-index" else 2)
    assert result == ({"192.0.2.10/24"} if invalid == "none" else set())


@pytest.mark.parametrize("prefix", [24, 25])
def test_observation_preserves_static_source_and_exact_lease_prefix(monkeypatch, tmp_path, prefix):
    """A live lease adds independent evidence without relabeling static holdovers.

    Args:
        monkeypatch: Replace bounded native reads and clock.
        tmp_path: Isolated native lease directory.
        prefix: Kernel prefix, matching or differing from the live lease.
    """
    helper = load_helper_module()
    set_clock(helper, monkeypatch, tmp_path)
    monkeypatch.setattr(helper, "_read_retained_network_conflicts", lambda: [])
    link = native_link()
    link["Addresses"][0]["PrefixLength"] = prefix
    rows = [{"ifname": "eth0", "ifindex": 2, "address": "00:11:22:33:44:55",
             "link_type": "ether", "flags": ["UP", "LOWER_UP"],
             "addr_info": [{"local": "192.0.2.10", "prefixlen": prefix}]}]

    def command(args, **_kwargs):
        """Return only the selected command's sanitized fixture.

        Args:
            args: Fixed native observation command.
            **_kwargs: Required command timeout bounds.
        """
        payload = rows if args[0] == "ip" else {"Interfaces": [link]}
        return subprocess.CompletedProcess(args, 0, "" if args[0] == "journalctl" else json.dumps(payload), "")

    monkeypatch.setattr(helper, "_network_observation_command", command)
    result = helper._network_address_observation()
    record = result["links"][0]["addresses"][0]
    assert result["complete"]
    assert record["source"] == "static"
    assert record["dhcp4_lease"] is (prefix == 24)


@pytest.mark.parametrize("valid", [True, False])
def test_handoff_accepts_retained_address_only_with_proven_lease(tmp_path, monkeypatch, valid):
    """Readiness and listener discovery agree without accepting a stale static address.

    Args:
        tmp_path: Isolated transaction evidence root.
        monkeypatch: Provide native address and DHCP observations.
        valid: Whether independent current lease proof is present.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "NETWORK_APPLY_DIR", tmp_path)
    row = {"name": "eth0", "role": "management", "ipv4_method": "dhcp", "ipv6_enabled": "false"}
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([row], [], []))
    native = {"complete": True, "links": [{"name": "eth0", "configured": True, "address_inventory_complete": True,
              "addresses": [{"address": "192.0.2.10", "cidr": "192.0.2.10/24", "scope": "global",
                             "source": "static", "state": "assigned", "dhcp4_lease": valid}]}], "conflicts": []}
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native)
    ip_rows = [{"addr_info": [{"local": "192.0.2.10", "family": "inet", "scope": "global"}]}]
    monkeypatch.setattr(helper, "_run", lambda args: subprocess.CompletedProcess(args, 0, json.dumps(ip_rows), ""))
    path = tmp_path / "network.conf"
    if not valid:
        with pytest.raises(ValueError, match="Unable to verify"):
            helper._wait_network_addresses(path, attempts=1)
        with pytest.raises(ValueError, match="DHCP|dynamic|address"):
            helper._management_handoff_addresses(path, previous_addresses={"192.0.2.10"},
                                                  address_observation=native, discovery_attempts=1)
        return
    observed = helper._wait_network_addresses(path, attempts=1)
    assert helper._management_handoff_addresses(path, previous_addresses={"192.0.2.10"},
                                                address_observation=observed, discovery_attempts=1) == ["192.0.2.10"]
    conflict = copy.deepcopy(native)
    conflict["links"][0]["addresses"][0]["state"] = "conflict"
    monkeypatch.setattr(helper, "_network_address_observation", lambda: conflict)
    with pytest.raises(ValueError, match="IP conflict"):
        helper._wait_network_addresses(path, attempts=1)


@pytest.mark.parametrize("finishes", [True, False])
def test_retirement_waits_for_stable_address_after_reconfigure(tmp_path, monkeypatch, finishes):
    """A stale ready sample cannot authorize routing during asynchronous ACD.

    Args:
        tmp_path: Isolated transaction evidence root.
        monkeypatch: Provide observations around networkd reconfiguration.
        finishes: Whether three consecutive ready samples eventually arrive.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "NETWORK_APPLY_DIR", tmp_path)
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    row = {"name": "eth0", "ip_cidr": "192.0.2.10/24", "ipv6_enabled": "false"}
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([row], [], []))
    states = iter([True, False, True, True, finishes])
    observed = []

    def observation():
        """Expose the native configured state and record each bounded sample."""
        configured = next(states)
        observed.append(configured)
        return {"complete": True, "conflicts": [], "links": [{"name": "eth0", "configured": configured,
                "addresses": [{"address": "192.0.2.10", "cidr": "192.0.2.10/24",
                               "source": "static", "state": "assigned"}]}]}

    monkeypatch.setattr(helper, "_network_address_observation", observation)
    if finishes:
        helper._wait_network_addresses(tmp_path / "network.conf", attempts=5, stable_samples=3)
    else:
        with pytest.raises(ValueError, match="Unable to verify"):
            helper._wait_network_addresses(tmp_path / "network.conf", attempts=5, stable_samples=3)
    assert observed == [True, False, True, True, finishes]


@pytest.mark.parametrize("proven", [False, True])
def test_status_tracks_only_independently_proven_static_overlap_as_dhcp(proven):
    """Keep UI lease history aligned with helper evidence during static overlap.

    Args:
        proven: Whether the helper independently verified current DHCP ownership.
    """
    from atlaso.app.services.network_address_status import project_status
    from tests.test_network_address_status import observation, resource

    native = observation()
    native["links"][0]["addresses"][0].update(source="static", cidr="192.0.2.10/24", dhcp4_lease=proven)
    desired = {**resource(desired=""), "desired": [], "dhcp4": True}
    projected = project_status(native, {}, [desired])["rows"]["physical:1"]
    assert projected["active_addresses"] == ["192.0.2.10"]
    assert projected["dhcp4_addresses"] == (["192.0.2.10"] if proven else [])
