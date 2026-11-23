"""Exercise native diagnostic argument and result boundaries."""

import json
from types import SimpleNamespace

import pytest

from atlaso.app.services import network_diagnostics as diagnostics
from atlaso.monitor_native import ObservationUnavailable


@pytest.fixture(autouse=True)
def enable_native_checks(monkeypatch):
    """Exercise the real-mode dispatch without allowing a native process."""
    monkeypatch.setattr(diagnostics, "get_settings", lambda: SimpleNamespace(dry_run_system_adapters=False))

    def unexpected(*args):
        pytest.fail(f"Unexpected native invocation: {args!r}")

    monkeypatch.setattr(diagnostics, "run_native", unexpected)


@pytest.mark.parametrize("target", ["-Ieth0", "example.org;id", "example.org\nlocalhost", "192.0.2.999",
                                    "224.0.0.1", "255.255.255.255", "::", "fe80::1%eth0", "::ffff:127.0.0.1"])
def test_invalid_targets_never_reach_native_commands(target):
    assert diagnostics.run_check("ping", target, "", "auto").state == "invalid_target"


def test_ping_uses_numeric_hostname_answer_and_reports_loss_and_rtt(monkeypatch):
    calls = []

    def native(args, _deadline):
        calls.append(args)
        if args[0] == "getent":
            return 0, "2001:db8::5 STREAM example.test\n192.0.2.5 STREAM\n192.0.2.5 DGRAM\n"
        if args[0] == "ip":
            return 0, '[{"dev":"eth1","prefsrc":"192.0.2.2"}]'
        return 1, (
            "64 bytes from 192.0.2.5: icmp_seq=2 ttl=64 time=0.314 ms\n"
            "3 packets transmitted, 1 received, 66.6667% packet loss, time 2040ms\n"
            "rtt min/avg/max/mdev = 0.314/0.314/0.314/0.000 ms\n"
        )

    monkeypatch.setattr(diagnostics, "run_native", native)
    result = diagnostics.run_check("ping", "example.test", "", "4")
    assert result.state == "reply"
    assert result.source == "192.0.2.2"
    assert result.rows == [diagnostics.ResultRow(2, "192.0.2.5", "0.314", "Reply")]
    assert "66.6667% loss" in result.message and "0.314/0.314/0.314 ms" in result.message
    assert calls == [
        ["getent", "-A", "ahosts", "example.test"],
        ["ip", "-j", "-4", "route", "get", "192.0.2.5", "ipproto", "icmp"],
        ["ping", "-4", "-n", "-c", "3", "-w", "6", "-I", "192.0.2.2", "192.0.2.5"],
    ]


def test_traceroute_checks_live_source_and_preserves_hop_timeouts(monkeypatch):
    calls = []

    def native(args, _deadline):
        calls.append(args)
        if args[2] == "address":
            return 0, json.dumps([{"ifname": "eth1", "addr_info": [{"local": "2001:db8::1"}]}])
        if args[0] == "ip":
            return 0, '[{"dev":"eth1"}]'
        return 0, "traceroute to 2001:db8::5\n 1  fe80::20%eth1  0.255 ms\n 2  *\n 3  2001:db8::5  1.433 ms\n"

    monkeypatch.setattr(diagnostics, "run_native", native)
    result = diagnostics.run_check("traceroute", "2001:db8::5", "2001:db8::1", "auto")
    assert result.state == "reply"
    assert result.source == "2001:db8::1"
    assert result.rows == [
        diagnostics.ResultRow(1, "fe80::20", "0.255", "Reply"),
        diagnostics.ResultRow(2, status="Timed out"),
        diagnostics.ResultRow(3, "2001:db8::5", "1.433", "Reply"),
    ]
    assert calls[-1] == ["traceroute", "-6", "-n", "-m", "12", "-q", "1", "-N", "1", "-w", "1",
                         "-s", "2001:db8::1", "2001:db8::5"]
    calls.clear()
    assert diagnostics.run_check("traceroute", "2001:db8::5", "2001:db8::9", "auto").state == "invalid_source"
    assert calls == [["ip", "-j", "address", "show", "up"]]


def test_dns_deduplicates_answers_without_sending_a_connectivity_probe(monkeypatch):
    def resolve(args, _deadline):
        assert args == ["getent", "-A", "ahosts", "example.test"]
        return 0, "2001:db8::2 STREAM example.test\n2001:db8::2 STREAM\n192.0.2.2 STREAM\n"

    monkeypatch.setattr(diagnostics, "run_native", resolve)
    result = diagnostics.run_check("dns", "example.test", "", "auto")
    assert result.state == "resolved"
    assert result.rows == [
        diagnostics.ResultRow(1, "2001:db8::2", status="IPv6"),
        diagnostics.ResultRow(2, "192.0.2.2", status="IPv4"),
    ]


def test_distinguishes_missing_resolver_answer_no_ping_reply_and_unavailable(monkeypatch):
    def native(args, _deadline):
        if args[0] == "getent":
            return 2, ""
        if args[0] == "ip":
            return 0, '[{"prefsrc":"192.0.2.2"}]'
        if args[0] == "ping":
            return 1, "3 packets transmitted, 0 received, 100% packet loss, time 2040ms\n"
        raise ObservationUnavailable

    monkeypatch.setattr(diagnostics, "run_native", native)
    assert diagnostics.run_check("ping", "missing.test", "", "auto").state == "resolution_failed"
    assert diagnostics.run_check("ping", "192.0.2.5", "", "auto").state == "no_reply"
    assert diagnostics.run_check("traceroute", "192.0.2.5", "", "auto").state == "unavailable"
