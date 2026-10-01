"""Client-only NTP ingress isolation remains independent of firewall settings."""

import copy
import json
import subprocess

import pytest

from tests.test_appliance_helper import load_helper_module


def test_client_guard_blocks_requests_but_permits_upstream_responses(monkeypatch):
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "/usr/sbin/nft")
    calls = []

    def run(command, input_text, *, timeout):
        calls.append((command, input_text, timeout))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run_with_input", run)
    helper._ntpd_client_packet_guard("ntp_client")
    command, rules, timeout = calls[0]
    assert command == ["/usr/sbin/nft", "-f", "-"]
    assert timeout == 5
    assert rules.index('iifname "lo" return') < rules.index("udp dport 123 @th,64,8")
    assert "@th,64,8 & 0x07 == 0x04 return" in rules
    assert rules.index("upstream replies") < rules.index("udp dport 123 drop")
    assert "ct state" not in rules
    assert "flush ruleset" not in rules
    assert "delete table inet atlaso_time_sync" in rules


@pytest.mark.parametrize("mode", ["ntp_server", "vmware_tools", "disabled"])
def test_other_modes_release_only_time_client_guard(monkeypatch, mode):
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "/usr/sbin/nft")
    calls = []

    def run(command, input_text, *, timeout):
        calls.append(input_text)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run_with_input", run)
    helper._ntpd_client_packet_guard(mode)
    assert calls == ["add table inet atlaso_time_sync\ndelete table inet atlaso_time_sync\n"]


@pytest.mark.parametrize("failure", ["absent", "rejected", "timeout"])
def test_unproven_packet_guard_blocks_clock_activation(monkeypatch, failure):
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda _name: None if failure == "absent" else "/usr/sbin/nft")

    def run(command, input_text, *, timeout):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, timeout)
        return subprocess.CompletedProcess(command, 1, "", "unsupported rule")

    monkeypatch.setattr(helper, "_run_with_input", run)
    with pytest.raises(RuntimeError):
        helper._ntpd_client_packet_guard("ntp_client")


@pytest.mark.parametrize("drift", [None, "early_accept", "wrong_mode", "wrong_priority", "absent"])
def test_client_guard_health_checks_effective_rules(monkeypatch, drift):
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "/usr/sbin/nft")
    port = {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 123}}
    chain = {"name": "input", "hook": "input", "type": "filter", "prio": -200, "policy": "accept"}
    rules = [
        {"chain": "input", "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"return": None}]},
        {"chain": "input", "expr": [port, {"match": {"op": "==", "left": {"&": [{"payload": {"base": "th", "offset": 64, "len": 8}}, 7]}, "right": 4}}, {"return": None}]},
        {"chain": "input", "expr": [port, {"drop": None}]},
    ]
    rules = copy.deepcopy(rules)
    if drift == "early_accept":
        rules.insert(0, {"chain": "input", "expr": [{"accept": None}]})
    elif drift == "wrong_mode":
        rules[1]["expr"][1]["match"]["right"] = 3
    elif drift == "wrong_priority":
        chain["prio"] = 10
    document = {"nftables": [{"chain": chain}, *[{"rule": rule} for rule in rules]]}
    monkeypatch.setattr(helper, "_run", lambda command, **_kwargs: subprocess.CompletedProcess(
        command, 1 if drift == "absent" else 0, json.dumps(document), "",
    ))
    status = helper._ntpd_client_packet_guard_status()
    assert status["active"] is (drift is None)


def test_client_guard_health_accepts_nft_normalized_mode_bits(monkeypatch):
    """The live nft rule renders the NTP mode as the exact @th bit range."""
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "/usr/sbin/nft")
    port = {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 123}}
    document = {
        "nftables": [
            {"metainfo": {"version": "1.1.6", "release_name": "Commodore Bullmoose #7", "json_schema_version": 1}},
            {"table": {"family": "inet", "name": "atlaso_time_sync", "handle": 14}},
            {"chain": {"family": "inet", "table": "atlaso_time_sync", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": -200, "policy": "accept"}},
            {"rule": {"family": "inet", "table": "atlaso_time_sync", "chain": "input", "handle": 2, "comment": "Atlaso time-sync local diagnostics", "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"return": None},
            ]}},
            {"rule": {"family": "inet", "table": "atlaso_time_sync", "chain": "input", "handle": 3, "comment": "Atlaso time-sync upstream replies", "expr": [
                port, {"match": {"op": "==", "left": {"payload": {"base": "th", "offset": 69, "len": 3}}, "right": 4}}, {"return": None},
            ]}},
            {"rule": {"family": "inet", "table": "atlaso_time_sync", "chain": "input", "handle": 4, "comment": "Atlaso time-sync client-only", "expr": [port, {"drop": None}]}},
        ]
    }
    monkeypatch.setattr(helper, "_run", lambda command, **_kwargs: subprocess.CompletedProcess(
        command, 0, json.dumps(document), "",
    ))

    status = helper._ntpd_client_packet_guard_status()

    assert status["active"] is True


@pytest.mark.parametrize("drift", ["wrong_offset", "wrong_length", "early_return", "wrong_order"])
def test_client_guard_rejects_malformed_normalized_mode_rules(monkeypatch, drift):
    helper = load_helper_module()
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "/usr/sbin/nft")
    port = {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 123}}
    chain = {"name": "input", "hook": "input", "type": "filter", "prio": -200, "policy": "accept"}
    rules = [
        {"chain": "input", "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"return": None}]},
        {"chain": "input", "expr": [port, {"match": {"op": "==", "left": {"payload": {"base": "th", "offset": 69, "len": 3}}, "right": 4}}, {"return": None}]},
        {"chain": "input", "expr": [port, {"drop": None}]},
    ]
    if drift == "wrong_offset":
        rules[1]["expr"][1]["match"]["left"]["payload"]["offset"] = 68
    elif drift == "wrong_length":
        rules[1]["expr"][1]["match"]["left"]["payload"]["len"] = 8
    elif drift == "early_return":
        rules.insert(0, {"chain": "input", "expr": [{"return": None}]})
    elif drift == "wrong_order":
        rules[1], rules[2] = rules[2], rules[1]
    document = {"nftables": [{"chain": chain}, *[{"rule": rule} for rule in rules]]}
    monkeypatch.setattr(helper, "_run", lambda command, **_kwargs: subprocess.CompletedProcess(
        command, 0, json.dumps(document), "",
    ))

    status = helper._ntpd_client_packet_guard_status()

    assert status["active"] is False


@pytest.mark.parametrize("mode", ["ntp_client", "ntp_server", "vmware_tools"])
def test_firewall_replace_preserves_only_applied_client_guard(monkeypatch, tmp_path, mode):
    helper = load_helper_module()
    applied = tmp_path / "ntp.conf"
    applied.write_text(
        f"# Managed by Atlaso. Local changes may be overwritten.\n# Atlaso time mode: {mode}\n# Atlaso NTP enabled: {'true' if mode == 'ntp_server' else 'false'}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", applied)
    program = "flush ruleset\ntable inet atlaso {}\n"
    guarded = helper._ntpd_preserve_client_packet_guard(program)
    assert ("table inet atlaso_time_sync" in guarded) is (mode == "ntp_client")
    assert guarded.startswith(program)
    # A table-scoped NAT update must neither replace nor weaken the guard.
    nat = "flush table ip atlaso_nat\n"
    assert helper._ntpd_preserve_client_packet_guard(nat) == nat


def test_nft_file_and_stdin_paths_publish_guard_in_same_transaction(monkeypatch, tmp_path):
    helper = load_helper_module()
    applied = tmp_path / "ntp.conf"
    applied.write_text("# Atlaso NTP enabled: false\n# Atlaso time mode: ntp_client\n", encoding="utf-8")
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", applied)
    firewall = tmp_path / "firewall.nft"
    firewall.write_text("flush ruleset\n", encoding="utf-8")
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper.subprocess, "run", run)
    helper._run(["nft", "-f", str(firewall)])
    helper._run_with_input(["/usr/sbin/nft", "-f", "-"], "flush ruleset\n")
    assert len(calls) == 2
    for command, kwargs in calls:
        assert command[-1] == "-"
        assert "flush ruleset\n" in kwargs["input"]
        assert "udp dport 123 drop" in kwargs["input"]
    assert firewall.read_text(encoding="utf-8") == "flush ruleset\n"
