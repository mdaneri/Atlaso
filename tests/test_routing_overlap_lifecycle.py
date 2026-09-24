"""Reject unsafe routing-overlap fixture topology before any guest mutation."""

import copy
import hashlib
import ipaddress
import json

import pytest
import yaml

from scripts.interop.routing_overlap import (
    FixtureOwner,
    OverlapPrerequisiteError,
    admit_topology,
    server_configuration,
    verify_expired_sources,
    verify_source_rules,
)


@pytest.fixture
def topology_inputs():
    """Supply independent synthetic receipts, provider adapters, and guest links."""
    owner = FixtureOwner("task", "mdaneri/Atlaso", "a" * 40, 868, "E:/owned/lab")
    segments, receipts = {}, {}
    for purpose, tail in (("management", "01"), ("lab", "02")):
        provider = f"52 00 00 00 00 00 00 00-00 00 00 00 00 00 00 {tail}"
        name = f"Atlaso-PR-868-routing-overlap-{purpose}"
        receipt = {"schema": 1, "creation_id": "b" * 32, "name": name, "pvn_id": provider,
                   **owner.__dict__}
        raw = json.dumps(receipt).encode()
        segments[purpose] = {"id": provider, "name": name, "receipt_sha256": hashlib.sha256(raw).hexdigest()}
        receipts[purpose] = raw
    mapping = [("appliance", 0, "management"), ("appliance", 1, "lab"),
               ("client-a", 0, "control"), ("client-a", 1, "management"),
               ("client-b", 0, "control"), ("client-b", 1, "lab")]
    nics, guests = [], []
    for index, (role, adapter, network) in enumerate(mapping):
        mac = f"00:50:56:00:00:{index + 1:02x}"
        nics.append({"role": role, "adapter": adapter, "mac": mac,
                     "network_type": "custom" if network == "control" else "pvn",
                     "network_id": "VMnet8" if network == "control" else segments[network]["id"]})
        guests.append({"role": role, "interface": f"eth{adapter}", "mac": mac})
    return {"owner": owner, "segments": segments, "receipt_bytes": receipts, "provider_nics": nics,
            "guest_links": guests, "control_network": "VMnet8", "control_prefixes": ["192.168.167.0/24"]}


def test_private_server_configuration(topology_inputs):
    """Keep DHCP/RA on the independently matched private management NIC.

    Args:
        topology_inputs: Synthetic ownership and topology evidence.
    """
    topology = admit_topology(**topology_inputs)
    config = server_configuration(topology)
    assert config["private_interface"] == "eth1"
    assert config["control_interface"] == "eth0"
    assert "\ninterface=eth1\n" in config["dnsmasq"]
    assert "\nexcept-interface=eth0\n" in config["dnsmasq"]
    assert "00:50:56:00:00:01,192.0.2.10,2m" in config["dnsmasq"]
    assert "interface eth1" in config["radvd"] and "eth0" not in config["radvd"]
    assert "AdvValidLifetime 60;" in config["radvd"]
    assert "port=0" in config["dnsmasq"]


@pytest.mark.parametrize("fault", ["receipt-hash", "owner", "reused", "shared-id", "shared-network", "extra-nic",
                                   "missing-nic", "mac-mismatch", "duplicate-mac", "ambiguous-guest", "extra-guest", "interface",
                                   "ipv4-control-overlap", "ipv6-control-overlap", "missing-control-prefix"])
def test_topology_refuses_unproven_isolation(topology_inputs, fault):
    """Fail admission without making provider or guest calls.

    Args:
        topology_inputs: Synthetic topology evidence.
        fault: One missing or conflicting ownership/isolation fact.
    """
    inputs = copy.deepcopy(topology_inputs)
    if fault == "receipt-hash":
        inputs["receipt_bytes"]["management"] += b" "
    elif fault == "owner":
        inputs["owner"] = FixtureOwner("other", "mdaneri/Atlaso", "a" * 40, 868, "E:/owned/lab")
    elif fault == "reused":
        inputs["segments"]["management"]["receipt_sha256"] = ""
    elif fault == "shared-id":
        inputs["segments"]["lab"] = inputs["segments"]["management"]
        inputs["receipt_bytes"]["lab"] = inputs["receipt_bytes"]["management"]
    elif fault == "shared-network":
        inputs["provider_nics"][0].update(network_type="custom", network_id="VMnet8")
    elif fault == "extra-nic":
        inputs["provider_nics"].append(copy.deepcopy(inputs["provider_nics"][0]))
    elif fault == "missing-nic":
        inputs["provider_nics"].pop()
    elif fault == "mac-mismatch":
        inputs["guest_links"][0]["mac"] = "00:50:56:00:01:ff"
    elif fault == "duplicate-mac":
        inputs["provider_nics"][1]["mac"] = inputs["provider_nics"][0]["mac"]
    elif fault == "ambiguous-guest":
        inputs["guest_links"].append(copy.deepcopy(inputs["guest_links"][0]))
    elif fault == "extra-guest":
        inputs["guest_links"].append({"role": "appliance", "interface": "eth2", "mac": "00:50:56:00:01:ff"})
    elif fault == "interface":
        inputs["guest_links"][0]["interface"] = "eth0;reboot"
    elif fault == "ipv4-control-overlap":
        inputs["control_prefixes"] = ["192.0.2.0/24"]
    elif fault == "ipv6-control-overlap":
        inputs["control_prefixes"] += ["fd74:1::/64"]
    else:
        inputs["control_prefixes"] = []
    with pytest.raises(OverlapPrerequisiteError):
        admit_topology(**inputs)


def terminal_rows(family):
    """Return the terminal guard and narrow main-table escape rules.

    Args:
        family: IPv4 or IPv6 policy-rule family.
    """
    prefixes = (("0.0.0.0/32", "169.254.0.0/16", "127.0.0.0/8") if family == 4
                else ("::/128", "fe80::/10", "::1/128"))
    rows = []
    for offset, prefix in enumerate(prefixes):
        network = ipaddress.ip_network(prefix)
        rows.append({"priority": 6000 + offset, "src": str(network.network_address),
                     "srclen": network.prefixlen, "iif": "lo", "table": "254", "protocol": "2"})
    destination = ipaddress.ip_network("169.254.0.0/16" if family == 4 else "fe80::/10")
    rows.append({"priority": 6003, "dst": str(destination.network_address),
                 "dstlen": destination.prefixlen, "iif": "lo", "table": "254", "protocol": "2"})
    rows.append({"priority": 6004, "src": "all", "srclen": 0, "iif": "lo",
                 "action": "7", "protocol": "2"})
    return rows


def source_evidence():
    """Return dual-family exact source isolation observations."""
    addresses = {"192.0.2.10": 100, "192.0.2.20": 200, "fd74:1::10": 100, "fd74:1::20": 200}
    rules = {4: [], 6: []}
    for source, table in addresses.items():
        family = 6 if ":" in source else 4
        rules[family].extend([{"src": source, "table": table, "priority": 5570, "iif": "lo", "protocol": "2"},
                              {"src": source, "action": "7", "priority": 5571, "iif": "lo", "protocol": "2"}])
    for family in (4, 6):
        rules[family].extend(terminal_rows(family))
    return addresses, rules


def test_dual_family_exact_sources():
    """Accept Photon numeric unreachable actions for both separate domains."""
    addresses, rules = source_evidence()
    assert verify_source_rules(addresses, rules) == addresses


def test_source_proof_rejects_missing_unbound_escape():
    """A terminal guard without source-selection escape is not native acceptance."""
    addresses, rules = source_evidence()
    rules[4] = [row for row in rules[4] if row.get("priority") != 6000]
    with pytest.raises(OverlapPrerequisiteError, match="escape"):
        verify_source_rules(addresses, rules)


def test_recorded_photon_rules_match_source_isolation_contract():
    """Accept the actual IPv4/IPv6 JSON shape recorded on the #741 appliance."""
    addresses = {"192.168.167.172": 100, "192.168.167.254": 200,
                 "fd42:741::172": 100, "fd42:741::254": 200}
    rules = {
        4: [{"priority": 5570, "src": "192.168.167.172", "iif": "lo", "table": "100", "protocol": "2"},
            {"priority": 5571, "src": "192.168.167.172", "iif": "lo", "action": "7", "protocol": "2"},
            {"priority": 5780, "src": "192.168.167.254", "iif": "lo", "table": "200", "protocol": "2"},
            {"priority": 5781, "src": "192.168.167.254", "iif": "lo", "action": "7", "protocol": "2"},
            *terminal_rows(4)],
        6: [{"priority": 5314, "src": "fd42:741::254", "iif": "lo", "table": "200", "protocol": "2"},
            {"priority": 5315, "src": "fd42:741::254", "iif": "lo", "action": "7", "protocol": "2"},
            {"priority": 5552, "src": "fd42:741::172", "iif": "lo", "table": "100", "protocol": "2"},
            {"priority": 5553, "src": "fd42:741::172", "iif": "lo", "action": "7", "protocol": "2"},
            *terminal_rows(6)],
    }
    assert verify_source_rules(addresses, rules) == addresses


@pytest.mark.parametrize("enabled", [False, True])
def test_client_seed_installs_fixture_tools_only_when_requested(enabled):
    """Keep ordinary clients unchanged and never start private servers in seeds.

    Args:
        enabled: Whether the wrapper requested the dedicated fixture tools.
    """
    from argparse import Namespace

    from scripts.interop.create_nocloud_seed_iso import cloud_init_files

    files = cloud_init_files(Namespace(hostname="fixture", user="alpine", public_key="synthetic-public-key",
                                      password="", routing_overlap_guest=enabled))
    data = files["user-data"]
    config = yaml.safe_load(data)
    commands = config["runcmd"]
    assert (config.get("ssh") == {"emit_keys_to_console": False}) == enabled
    assert all(isinstance(command, str) for command in commands)
    for package in ("dnsmasq", "radvd", "python3", "nftables", "ethtool", "sudo",
                    "open-vm-tools", "open-vm-tools-openrc", "open-vm-tools-vix"):
        assert (f"  - {package}\n" in data) == enabled
    for command in ("rc-update add open-vm-tools default", "rc-service open-vm-tools start",
                    "ethtool -K eth0 lro off", "ethtool -K eth1 lro off"):
        assert (f"  - {command}\n" in data) == enabled
        assert f"{command} || true" not in data
    assert "rc-service dnsmasq" not in data and "rc-service radvd" not in data
    assert "rc-update add dnsmasq" not in data and "rc-update add radvd" not in data
    assert "NOPASSWD:ALL" in data
    datasource_files = [item for item in config["write_files"]
                        if item["path"] == "/etc/cloud/cloud.cfg.d/99-atlaso-fixture-datasources.cfg"]
    assert len(datasource_files) == int(enabled)
    forwarding_files = [item for item in config["write_files"]
                        if item["path"] == "/etc/ssh/sshd_config.d/99-atlaso-private-fixture.conf"]
    assert len(forwarding_files) == int(enabled)
    assert ("/usr/local/sbin/atlaso-private-fixture-sshd" in commands) == enabled
    if enabled:
        assert "AllowTcpForwarding local" in forwarding_files[0]["content"]
        assert "PermitOpen 192.0.2.10:22 192.0.2.10:443" in forwarding_files[0]["content"]
        assert commands[0] == "/usr/local/sbin/atlaso-private-fixture-sshd"
        assert datasource_files[0]["content"].strip() == "datasource_list: [ NoCloud, None ]"
        assert "  - /usr/local/sbin/atlaso-refresh-test-dhcp" not in data
        assert "  eth1:\n    dhcp4: false\n    dhcp6: false\n    accept-ra: false" in files["network-config"]
        assert "eth2:" not in files["network-config"]
    else:
        assert "  - /usr/local/sbin/atlaso-refresh-test-dhcp" in data
        assert "  eth1:\n    dhcp4: true" in files["network-config"]


@pytest.mark.parametrize("fault", ["broad", "wrong-table", "missing-fallback", "wrong-order", "ingress-only",
                                   "missing-terminal", "wrong-terminal",
                                   "missing-family", "wrong-protocol", "wrong-band", "missing-iif"])
def test_source_proof_rejects_incomplete_isolation(fault):
    """Reject a route proof that could still select the other domain.

    Args:
        fault: Invalid rule evidence.
    """
    addresses, rules = source_evidence()
    if fault == "broad":
        rules[4][0]["src"] = "192.0.2.0/24"
    elif fault == "wrong-table":
        rules[4][0]["table"] = 200
    elif fault == "missing-fallback":
        rules[4].pop(1)
    elif fault == "wrong-order":
        rules[4][1]["priority"] = 999
    elif fault == "ingress-only":
        rules[4][0]["iif"] = "eth0"
    elif fault == "wrong-protocol":
        rules[4][0]["protocol"] = "99"
    elif fault == "wrong-band":
        rules[4][0]["priority"] = 4999
    elif fault == "missing-iif":
        del rules[4][0]["iif"]
    elif fault == "missing-terminal":
        rules[4].pop()
    elif fault == "wrong-terminal":
        rules[6][-1]["iif"] = "eth0"
    else:
        del rules[6]
    with pytest.raises(OverlapPrerequisiteError):
        verify_source_rules(addresses, rules)


def test_expiry_requires_kernel_address_and_rule_removal():
    """Retained lease addresses or stale routing rules cannot prove expiry."""
    verify_expired_sources(["192.0.2.10", "fd74:1::10"], ["192.0.2.20"], {4: [], 6: []})
    with pytest.raises(OverlapPrerequisiteError, match="remains active"):
        verify_expired_sources(["192.0.2.10"], ["192.0.2.10"], {4: [], 6: []})
    with pytest.raises(OverlapPrerequisiteError, match="rule remains"):
        verify_expired_sources(["fd74:1::10"], [], {4: [], 6: [{"src": "fd74:1::10/128"}]})


@pytest.mark.parametrize("fault", [None, "wrong-table", "wrong-interface", "wrong-source", "missing-source", "multiple"])
def test_native_lookup_proves_selected_domain(fault):
    """Rule presence alone cannot substitute for actual kernel route selection.

    Args:
        fault: Conflicting or incomplete native route lookup.
    """
    from scripts.interop.routing_overlap import verify_route_selection

    rows = [{"table": 200, "dev": "eth1", "from": "192.0.2.20", "dst": "192.0.2.1"}]
    if fault == "wrong-table":
        rows[0]["table"] = 100
    elif fault == "wrong-interface":
        rows[0]["dev"] = "eth0"
    elif fault == "wrong-source":
        rows[0]["from"] = "192.0.2.10"
    elif fault == "missing-source":
        del rows[0]["from"]
    elif fault == "multiple":
        rows.append(dict(rows[0]))
    if fault:
        with pytest.raises(OverlapPrerequisiteError):
            verify_route_selection("192.0.2.20", 200, "eth1", rows)
    else:
        verify_route_selection("192.0.2.20", 200, "eth1", rows)
