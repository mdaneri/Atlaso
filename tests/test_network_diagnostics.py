"""Exercise native diagnostic argument and result boundaries."""

import json
from types import SimpleNamespace

import pytest

from atlaso.app.services import network_diagnostics as diagnostics
from atlaso.monitor_native import ObservationUnavailable


@pytest.fixture(autouse=True)
def enable_native_checks(monkeypatch):
    """Exercise the real-mode dispatch without allowing a native process.

    Args:
        monkeypatch: Fixture that enables dispatch and replaces the native runner.
    """
    monkeypatch.setattr(diagnostics, "get_settings", lambda: SimpleNamespace(dry_run_system_adapters=False))

    def unexpected(*args):
        """Fail if a test dispatches an unexpected native command.

        Args:
            *args: Executable name, arguments, and deadline passed to the runner.
        """
        pytest.fail(f"Unexpected native invocation: {args!r}")

    monkeypatch.setattr(diagnostics, "run_native", unexpected)


@pytest.mark.parametrize("target", ["-Ieth0", "example.org;id", "example.org\nlocalhost", "192.0.2.999",
                                    "224.0.0.1", "255.255.255.255", "::", "fe80::1%eth0", "::ffff:127.0.0.1"])
def test_invalid_targets_never_reach_native_commands(target):
    """Reject invalid probe destinations before invoking native tools.

    Args:
        target: Invalid destination under test.
    """
    assert diagnostics.run_check("ping", target, "", "auto").state == "invalid_target"


def test_ping_uses_numeric_hostname_answer_and_reports_loss_and_rtt(monkeypatch):
    """Bind the numeric target and report replies and statistics.

    Args:
        monkeypatch: Fixture that supplies resolver, route, and Ping output.
    """
    calls = []

    def native(command, args, _deadline):
        """Return the native output for each stage of the Ping request.

        Args:
            command: Fixed executable name.
            args: Arguments captured for assertions.
            _deadline: Unused native deadline.
        """
        calls.append([command, *args])
        if command == "getent":
            return 0, "2001:db8::5 STREAM example.test\n192.0.2.5 STREAM\n192.0.2.5 DGRAM\n"
        if command == "ip":
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
    """Check the requested source and keep missing hops visible.

    Args:
        monkeypatch: Fixture that supplies interface, route, and Traceroute output.
    """
    calls = []

    def native(command, args, _deadline):
        """Return the live-source inventory and a trace with a timed-out hop.

        Args:
            command: Fixed executable name.
            args: Arguments captured for assertions.
            _deadline: Unused native deadline.
        """
        calls.append([command, *args])
        if args[:2] == ["-j", "address"]:
            return 0, json.dumps([{"ifname": "eth1", "addr_info": [{"local": "2001:db8::1"}]}])
        if command == "ip":
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
    """Return unique addresses in resolver order.

    Args:
        monkeypatch: Fixture that replaces the native resolver.
    """
    def resolve(command, args, _deadline):
        """Return repeated and dual-stack resolver answers.

        Args:
            command: Fixed resolver executable name.
            args: Arguments checked for the single allowed query.
            _deadline: Unused native deadline.
        """
        assert (command, args) == ("getent", ["-A", "ahosts", "example.test"])
        return 0, "2001:db8::2 STREAM example.test\n2001:db8::2 STREAM\n192.0.2.2 STREAM\n"

    monkeypatch.setattr(diagnostics, "run_native", resolve)
    result = diagnostics.run_check("dns", "example.test", "", "auto")
    assert result.state == "resolved"
    assert result.rows == [
        diagnostics.ResultRow(1, "2001:db8::2", status="IPv6"),
        diagnostics.ResultRow(2, "192.0.2.2", status="IPv4"),
    ]


def test_distinguishes_missing_resolver_answer_no_ping_reply_and_unavailable(monkeypatch):
    """Keep three distinct failure outcomes visible to the operator.

    Args:
        monkeypatch: Fixture that supplies native failures and a valid route.
    """
    def native(command, _args, _deadline):
        """Simulate a missing answer, a probe with no reply, and an unavailable tool.

        Args:
            command: Fixed executable name that selects the response.
            _args: Unused native arguments.
            _deadline: Unused native deadline.
        """
        if command == "getent":
            return 2, ""
        if command == "ip":
            return 0, '[{"prefsrc":"192.0.2.2"}]'
        if command == "ping":
            return 1, "3 packets transmitted, 0 received, 100% packet loss, time 2040ms\n"
        raise ObservationUnavailable

    monkeypatch.setattr(diagnostics, "run_native", native)
    assert diagnostics.run_check("ping", "missing.test", "", "auto").state == "resolution_failed"
    assert diagnostics.run_check("ping", "192.0.2.5", "", "auto").state == "no_reply"
    assert diagnostics.run_check("traceroute", "192.0.2.5", "", "auto").state == "unavailable"
