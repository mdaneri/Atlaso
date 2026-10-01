"""Focused tests for pinned native clock-source lifecycle acceptance."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import struct
from pathlib import Path
from types import SimpleNamespace

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.interop import time_source_acceptance as acceptance


def _server_reply(transmit: bytes) -> bytes:
    packet = bytearray(48)
    packet[0] = (4 << 3) | 4
    packet[1] = 2
    packet[24:32] = transmit
    packet[40:48] = struct.pack("!II", 3_900_000_000, 1)
    return bytes(packet)


def _host_key() -> paramiko.Ed25519Key:
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem.decode("ascii")))


def test_pinned_host_key_policy_accepts_only_matching_ed25519_key():
    """Accept the pinned key and reject key-type or fingerprint changes."""
    key = _host_key()
    fingerprint = acceptance._fingerprint(key)
    client = paramiko.SSHClient()
    policy = acceptance.PinnedEd25519HostKeyPolicy("192.0.2.10", fingerprint)

    policy.missing_host_key(client, "192.0.2.10", key)

    assert client.get_host_keys().lookup("192.0.2.10")["ssh-ed25519"] == key
    with pytest.raises(paramiko.SSHException):
        policy.missing_host_key(client, "192.0.2.11", key)
    with pytest.raises(paramiko.SSHException):
        acceptance.PinnedEd25519HostKeyPolicy("192.0.2.10", "SHA256:" + "A" * 43).missing_host_key(
            client, "192.0.2.10", _host_key()
        )


def test_ntp_server_response_requires_matching_mode_health_endpoint_and_timestamps():
    """Validate the positive host query against NTP's response and endpoint fields."""
    request, transmit = acceptance.build_ntp_request()
    assert request[40:48] == transmit

    evidence = acceptance.validate_ntp_server_response(
        _server_reply(transmit), ("192.168.87.11", 123), "192.168.87.11", transmit
    )

    assert evidence == {
        "peer_address": "192.168.87.11",
        "peer_port": 123,
        "mode": 4,
        "version": 4,
        "stratum": 2,
        "leap_alarm": False,
        "originate_timestamp_matched": True,
        "transmit_timestamp_present": True,
    }


@pytest.mark.parametrize(
    ("packet_change", "peer", "expected_address", "expected_transmit"),
    [
        (lambda p: p[:47], ("192.168.87.11", 123), "192.168.87.11", b"12345678"),
        (lambda p: bytes([(p[0] & 0xF8) | 3]) + p[1:], ("192.168.87.11", 123), "192.168.87.11", b"12345678"),
        (lambda p: bytes([0xE4]) + p[1:], ("192.168.87.11", 123), "192.168.87.11", b"12345678"),
        (lambda p: bytes([p[0]]) + bytes([16]) + p[2:], ("192.168.87.11", 123), "192.168.87.11", b"12345678"),
        (lambda p: p[:24] + b"xxxxxxxx" + p[32:], ("192.168.87.11", 123), "192.168.87.11", b"12345678"),
        (lambda p: p[:40] + bytes(8), ("192.168.87.11", 123), "192.168.87.11", b"12345678"),
        (lambda p: p, ("192.168.87.12", 123), "192.168.87.11", b"12345678"),
        (lambda p: p, ("192.168.87.11", 1234), "192.168.87.11", b"12345678"),
    ],
)
def test_ntp_server_response_rejects_invalid_or_unowned_reply(
    packet_change, peer, expected_address, expected_transmit
):
    """Reject malformed, unsynchronized, mismatched, or unexpected replies."""
    with pytest.raises(acceptance.TimeSourceAcceptanceError):
        acceptance.validate_ntp_server_response(
            packet_change(_server_reply(b"12345678")), peer, expected_address, expected_transmit
        )


def test_client_probe_requires_capture_ready_and_proves_no_ntp_response(monkeypatch):
    """Send the exact UDP query only after guest capture is ready and reject replies."""
    calls: list[tuple[str, object]] = []

    class FakeSocket:
        def bind(self, address):
            calls.append(("bind", address))

        def getsockname(self):
            return "192.168.87.1", 40123

        def settimeout(self, timeout):
            calls.append(("timeout", timeout))

        def sendto(self, packet, address):
            calls.append(("send", address))
            assert len(packet) == 48

        def recvfrom(self, _size):
            raise acceptance.socket.timeout

        def close(self):
            calls.append(("close", None))

    class FakeGuest:
        def invoke(self, action, **kwargs):
            assert action == "client_capture"
            assert kwargs["peer_ip"] == "192.168.87.1"
            assert kwargs["peer_port"] == 40123
            kwargs["on_capture_ready"]()
            return {"probe_delivered_to_guest": True}

    monkeypatch.setattr(acceptance, "_host_source_address", lambda _host: "192.168.87.1")
    monkeypatch.setattr(acceptance.socket, "socket", lambda *_args, **_kwargs: FakeSocket())

    evidence = acceptance._probe_client_refusal(
        FakeGuest(), management_host="192.168.100.2", username="admin", password="test-only"
    )

    assert evidence == {"request_delivered": True, "ntp_response_received": False}
    assert ("send", ("192.168.100.2", 123)) in calls
    assert ("close", None) in calls


def test_server_probe_binds_to_verified_vmnet_source_instead_of_default_route(monkeypatch):
    """Use the verified site NIC explicitly when Wi-Fi owns the default route."""
    calls = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def bind(self, address):
            calls.append(("bind", address))

        def settimeout(self, timeout):
            calls.append(("timeout", timeout))

        def sendto(self, packet, address):
            calls.append(("send", address))
            self.transmit = packet[40:48]

        def recvfrom(self, _size):
            return _server_reply(self.transmit), ("192.168.87.11", 123)

    monkeypatch.setattr(acceptance.socket, "socket", lambda *_args, **_kwargs: FakeSocket())
    monkeypatch.setattr(
        acceptance,
        "_host_source_address",
        lambda _address: pytest.fail("The system default route must not choose the server probe interface."),
    )

    result = acceptance._probe_server(
        "192.168.87.11",
        ipaddress.IPv4Interface("192.168.87.1/24"),
        source_address="192.168.87.1",
    )

    assert ("bind", ("192.168.87.1", 0)) in calls
    assert ("send", ("192.168.87.11", 123)) in calls
    assert result["mode"] == 4


@pytest.mark.parametrize(("route_interface_index", "expected_success"), [(25, True), (7, False)])
def test_windows_fixture_neighbor_binds_route_to_vmnet_and_rejects_wifi_route(
    monkeypatch, route_interface_index, expected_success
):
    """Select the matching VMnet source and fail if route resolution leaves it for Wi-Fi."""
    captured = {}

    def fake_run(command, **kwargs):
        assert command[:3] == ["powershell.exe", "-NoProfile", "-NonInteractive"]
        captured["script"] = command[-1]
        captured["request"] = json.loads(kwargs["input"])
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "alias": "VMware Network Adapter VMnet1",
                    "source": "192.168.87.1",
                    "mac": "00:50:56:aa:bb:cc",
                    "state": "Reachable",
                    "interface_index": 25,
                    "local_interface_index": 25,
                    "route_interface_index": route_interface_index,
                    "route_source": "192.168.87.1",
                }
            ),
        )

    monkeypatch.setattr(acceptance, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(acceptance.subprocess, "run", fake_run)
    fixture = ipaddress.IPv4Interface("192.168.87.11/24")

    if expected_success:
        evidence = acceptance._windows_fixture_neighbor(
            str(fixture.ip), fixture, "VMnet1", "00:50:56:aa:bb:cc"
        )
        assert evidence["source_address"] == "192.168.87.1"
        assert evidence["interface_index"] == "25"
    else:
        with pytest.raises(acceptance.TimeSourceAcceptanceError):
            acceptance._windows_fixture_neighbor(
                str(fixture.ip), fixture, "VMnet1", "00:50:56:aa:bb:cc"
            )

    assert captured["request"] == {
        "address": "192.168.87.11",
        "network_address": "192.168.87.0",
        "prefix_length": 24,
        "site_network": "VMnet1",
    }
    assert "Get-NetAdapter -Name $expectedAlias" in captured["script"]
    assert "Find-NetRoute -LocalIPAddress $source.IPAddress -RemoteIPAddress $request.address" in captured["script"]
    assert "DestinationPrefix" in captured["script"]
    assert "route.InterfaceIndex -eq $adapter.InterfaceIndex" in captured["script"]
    assert "ping.exe -S $selected.IPAddress" in captured["script"]


@pytest.mark.parametrize(("sudo_status", "expected_prefix"), [(0, "sudo -n "), (1, "sudo -S -p '' ")])
def test_guest_channel_keeps_password_out_of_command_and_preserves_json_stdin(
    monkeypatch, sudo_status, expected_prefix
):
    """Use stdin for the fallback sudo password and avoid a stray line under NOPASSWD."""
    channels = []

    class FakeChannel:
        def __init__(self, status):
            self.status = status
            self.command = ""
            self.input = bytearray()
            self.closed = False

        def settimeout(self, _timeout):
            pass

        def exec_command(self, command):
            self.command = command

        def sendall(self, data):
            self.input.extend(data)

        def shutdown_write(self):
            pass

        def recv_ready(self):
            return self.command.endswith("guest.py") and not getattr(self, "sent", False)

        def recv(self, _size):
            self.sent = True
            return b'{"ok":true,"status":"ready"}\n'

        def recv_stderr_ready(self):
            return False

        def exit_status_ready(self):
            return True

        def recv_exit_status(self):
            return self.status

        def close(self):
            self.closed = True

    class FakeTransport:
        def is_authenticated(self):
            return True

        def open_session(self, timeout=0):
            del timeout
            channel = FakeChannel(sudo_status if not channels else 0)
            channels.append(channel)
            return channel

    class FakeClient:
        def get_transport(self):
            return FakeTransport()

    monkeypatch.setattr(acceptance, "GUEST_PYTHON", "/opt/atlaso/.venv/bin/python")
    guest = acceptance._PinnedGuest.__new__(acceptance._PinnedGuest)
    guest.username = "admin"
    guest.password = "ssh-secret"
    guest.client = FakeClient()
    guest._passwordless_sudo = None
    guest.remote_path = "/tmp/guest.py"

    result = guest.invoke(
        "boot_id",
        management_host="192.0.2.10",
        web_username="admin",
        web_password="web-secret",
    )

    assert result == {"status": "ready"}
    assert len(channels) == 2
    action_channel = channels[1]
    assert action_channel.command.startswith(expected_prefix)
    assert "ssh-secret" not in action_channel.command
    assert "web-secret" not in action_channel.command
    if sudo_status == 0:
        assert json.loads(action_channel.input) == {
            "action": "boot_id",
            "host": "192.0.2.10",
            "username": "admin",
        }
        assert b"ssh-secret" not in action_channel.input
    else:
        password, payload = bytes(action_channel.input).split(b"\n", 1)
        assert password == b"ssh-secret"
        assert json.loads(payload) == {
            "action": "boot_id",
            "host": "192.0.2.10",
            "username": "admin",
        }


class FakeGuest:
    """Record scenario actions and emulate verified reboot boundaries."""

    def __init__(self, expected_hash: str, expected_version: str) -> None:
        self.expected_hash = expected_hash
        self.expected_version = expected_version
        self.actions: list[str] = []
        self.events: list[str] = []
        self.boot_count = 0

    def invoke(self, action: str, **parameters):
        self.actions.append(action)
        self.events.append(action)
        if action == "deployment_identity":
            return {"helper_sha256": self.expected_hash, "installed_version": self.expected_version}
        if action == "fixture_identity":
            return {
                "fixture_address": "192.168.87.11",
                "fixture_interface": parameters["interface_name"],
                "fixture_mac": "00:50:56:AA:BB:CC",
            }
        if action == "apply":
            mode = parameters["mode"]
            return {
                "applied_mode": mode,
                "task_status": "succeeded",
                "remembered_time_source": "vmware_tools" if mode == "ntp_server" else mode,
                "clock": {"mode": mode, "healthy": True},
            }
        if action == "wait_status":
            return {"clock": {"mode": parameters["assert_mode"], "healthy": True}}
        if action == "conflict_enable":
            return {
                "clock": {
                    "mode": "ntp_client",
                    "healthy": False,
                    "conflicts": {"vmware_tools": {"active": True, "enabled": True}},
                }
            }
        if action == "ntpwait":
            return {"ntpwait": "unavailable"}
        if action == "boot_id":
            return {"boot_id": f"boot-{self.boot_count}"}
        if action == "reboot":
            return {"reboot_scheduled": True, "boot_id": f"boot-{self.boot_count}"}
        if action == "status":
            return {"clock": {"mode": "ntp_server", "healthy": True}}
        return {"ok": True}

    def wait_for_disconnect(self):
        self.events.append("disconnect")

    def reconnect_after_reboot(self):
        self.boot_count += 1
        self.events.append("reconnect")

    def _stage_program(self):
        self.events.append("restage")


def test_scenario_runs_all_modes_conflict_reboot_and_server_probe_in_order(monkeypatch):
    """Keep the complete mode-transition acceptance scenario ordered and bounded."""
    helper_path = Path(acceptance.__file__).resolve().parents[1] / "appliance" / "atlaso-helper"
    helper_hash = hashlib.sha256(helper_path.read_bytes()).hexdigest()
    project = json.loads(json.dumps({"version": "0.9.384"}))
    monkeypatch.setattr(acceptance.tomllib, "loads", lambda _value: {"project": project})
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: '[project]\nversion="0.9.384"\n')
    guest = FakeGuest(helper_hash, "0.9.384")
    probe_sources = []
    args = SimpleNamespace(
        appliance_ssh_host="192.168.100.2",
        appliance_ssh_user="admin",
        appliance_ssh_password="ssh-secret",
        appliance_ssh_hostkey="SHA256:" + "A" * 43,
        username="admin",
        password="web-secret",
        site_interface="eth1",
        site_cidr="192.168.87.11/24",
        time_source_site_network="VMnet1",
    )
    runner = acceptance._AcceptanceRunner(
        args,
        guest,
        progress=lambda _line: None,
        client_probe=lambda *_args, **_kwargs: {
            "request_delivered": True,
            "ntp_response_received": False,
        },
        server_probe=lambda address, network, source_address: (
            probe_sources.append(source_address)
            or {
                "peer_address": address,
                "peer_port": 123,
                "mode": 4,
                "version": 4,
                "stratum": 2,
                "leap_alarm": False,
                "originate_timestamp_matched": True,
                "transmit_timestamp_present": True,
            }
        ),
        fixture_neighbor=lambda *_args, **_kwargs: {"interface": "VMnet1", "source_address": "192.168.87.1", "guest_mac": "00:50:56:aa:bb:cc"},
    )

    result = runner.run()

    assert result["status"] == "passed"
    names = [item["name"] for item in result["steps"]]
    assert names == [
        "deployed-source-identity",
        "site-network-fixture",
        "packet-capture-tool",
        "apply-ntp-client",
        "client-udp-refusal-and-ingress",
        "restart-vmware-tools-in-client-mode",
        "client-health-after-tools-restart",
        "manual-vmware-time-conflict",
        "bounded-ntpwait-diagnostic",
        "reapply-ntp-client-after-conflict",
        "apply-vmware-tools",
        "vmware-tools-mode-reboot",
        "restart-vmware-tools-after-reboot",
        "vmware-tools-health-after-restart",
        "apply-ntp-server-with-remembered-tools-choice",
        "verify-site-fixture-address-ownership",
        "positive-host-ntp-server-probe",
        "server-unselected-management-refusal-and-ingress",
        "ntp-server-mode-reboot",
        "verify-site-fixture-after-reboot",
        "positive-host-ntp-server-probe-after-reboot",
        "server-unselected-management-refusal-after-reboot",
        "restore-vmware-tools-selection",
        "apply-final-ntp-client",
        "final-client-mode-reboot",
        "final-client-udp-refusal-and-ingress",
    ]
    assert guest.actions.count("reboot") == 3
    assert guest.events.count("disconnect") == 3
    assert guest.events.count("reconnect") == 3
    assert probe_sources == ["192.168.87.1", "192.168.87.1"]
    assert "ssh-secret" not in json.dumps(result)
    assert "web-secret" not in json.dumps(result)


def test_site_fixture_requires_private_address_and_host_reachable_vmnet():
    """Reject a fixture that could overlap management or lack host-side routing."""
    with pytest.raises(acceptance.TimeSourceAcceptanceError):
        acceptance._site_settings(
            SimpleNamespace(site_interface="eth0", site_cidr="192.168.87.11/24", time_source_site_network="VMnet1")
        )
    with pytest.raises(acceptance.TimeSourceAcceptanceError):
        acceptance._site_settings(
            SimpleNamespace(site_interface="eth1", site_cidr="192.168.87.11/24", time_source_site_network="lan:test")
        )
    assert acceptance._site_settings(
        SimpleNamespace(site_interface="eth1", site_cidr="192.168.87.11/24", time_source_site_network="VMnet1")
    )[3].network == ipaddress.IPv4Network("192.168.87.0/24")
