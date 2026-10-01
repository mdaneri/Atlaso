"""Run pinned native acceptance for Atlaso clock-source modes."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import time
import tomllib
from pathlib import Path
from typing import Any, Callable

import paramiko

GUEST_PYTHON = "/opt/atlaso/.venv/bin/python"
MAX_GUEST_OUTPUT = 65_536
_ACTION_TIMEOUTS = {
    "deployment_identity": 20,
    "prepare_server_interface": 360,
    "install_probe_tools": 120,
    "apply": 360,
    "client_capture": 25,
    "tools_restart": 80,
    "wait_status": 150,
    "conflict_enable": 35,
    "ntpwait": 45,
    "status": 35,
    "fixture_identity": 20,
    "server_probe": 20,
    "boot_id": 15,
    "reboot": 25,
}
_WEB_ACTIONS = {
    "prepare_server_interface",
    "apply",
    "client_capture",
    "wait_status",
    "conflict_enable",
    "status",
    "server_probe",
}


class TimeSourceAcceptanceError(RuntimeError):
    """Fixed public failure from a bounded time-source acceptance action."""


def _fail(message: str) -> None:
    raise TimeSourceAcceptanceError(message)


def _fingerprint(key: paramiko.PKey) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")


class PinnedEd25519HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Accept one exact Ed25519 host-key fingerprint for one address."""

    def __init__(self, host: str, fingerprint: str) -> None:
        self.host = host
        self.fingerprint = fingerprint
        if not fingerprint.startswith("SHA256:") or len(fingerprint) != 50:
            _fail("The appliance SSH host-key fingerprint is missing or invalid.")

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        if hostname != self.host or key.get_name() != "ssh-ed25519" or _fingerprint(key) != self.fingerprint:
            raise paramiko.SSHException("Pinned appliance host-key verification failed.")
        client.get_host_keys().add(self.host, key.get_name(), key)


def build_ntp_request() -> tuple[bytes, bytes]:
    """Build an NTPv4 request with a unique, current transmit timestamp."""
    packet = bytearray(48)
    packet[0] = 0x23
    now = time.time()
    seconds = int(now) + 2_208_988_800
    fraction = int((now % 1) * (1 << 32)) or 1
    fraction ^= int.from_bytes(secrets.token_bytes(4), "big")
    fraction = fraction or 1
    transmit = struct.pack("!II", seconds, fraction)
    packet[40:48] = transmit
    return bytes(packet), transmit


def validate_ntp_server_response(
    packet: bytes,
    peer: tuple[str, int],
    expected_address: str,
    expected_transmit: bytes,
) -> dict[str, Any]:
    """Validate a server response's endpoint, mode, clock state and timestamps."""
    try:
        expected = str(ipaddress.IPv4Address(expected_address))
        peer_address = str(ipaddress.IPv4Address(peer[0]))
    except (ValueError, TypeError, IndexError):
        _fail("The NTP server probe returned an invalid IPv4 endpoint.")
    if peer != (expected, 123) or peer_address != expected:
        _fail("The NTP response came from an unexpected endpoint.")
    if len(packet) < 48:
        _fail("The NTP response was shorter than its fixed header.")
    leap = packet[0] >> 6
    version = (packet[0] >> 3) & 0x07
    mode = packet[0] & 0x07
    stratum = packet[1]
    if mode != 4 or version not in {3, 4} or leap == 3 or not 1 <= stratum <= 15:
        _fail("The NTP response did not report a synchronized server at a valid stratum.")
    if len(expected_transmit) != 8 or packet[24:32] != expected_transmit or not any(packet[40:48]):
        _fail("The NTP response timestamps did not match the unique probe request.")
    return {
        "peer_address": expected,
        "peer_port": 123,
        "mode": mode,
        "version": version,
        "stratum": stratum,
        "leap_alarm": False,
        "originate_timestamp_matched": True,
        "transmit_timestamp_present": True,
    }


def _site_settings(args: Any) -> tuple[str, str, str, ipaddress.IPv4Interface]:
    try:
        interface = str(args.site_interface)
        fixture = ipaddress.IPv4Interface(str(args.site_cidr))
        site_network = str(args.time_source_site_network)
    except (AttributeError, ValueError, TypeError):
        _fail("The focused site interface, CIDR, or VMware network is invalid.")
    if (
        not interface
        or interface == "eth0"
        or not site_network
        or not site_network.lower().startswith("vmnet")
        or not site_network[5:].isdigit()
        or not fixture.ip.is_private
        or fixture.ip.is_loopback
        or fixture.ip.is_link_local
        or fixture.ip.is_multicast
        or fixture.ip.is_unspecified
    ):
        _fail("The focused acceptance requires a private eth1 address on a host-reachable VMware network.")
    return interface, site_network, str(fixture.ip), fixture


def _identity(args: Any) -> tuple[str, str, str, str, str, str]:
    host = str(getattr(args, "appliance_ssh_host", ""))
    username = str(getattr(args, "appliance_ssh_user", ""))
    ssh_password = str(getattr(args, "appliance_ssh_password", ""))
    web_username = str(getattr(args, "username", "admin"))
    web_password = str(getattr(args, "password", ""))
    fingerprint = str(getattr(args, "appliance_ssh_hostkey", ""))
    try:
        host = str(ipaddress.IPv4Address(host))
    except ValueError:
        _fail("The appliance management address must be an IPv4 literal.")
    if (
        not username
        or not re_full_username(username)
        or not re_full_username(web_username)
        or not ssh_password
        or "\n" in ssh_password
        or "\r" in ssh_password
        or not web_password
        or "\n" in web_password
        or "\r" in web_password
    ):
        _fail("The bounded lifecycle secret input is incomplete or invalid.")
    PinnedEd25519HostKeyPolicy(host, fingerprint)
    return host, username, ssh_password, web_username, web_password, fingerprint


def re_full_username(value: str) -> bool:
    return bool(value) and len(value) <= 64 and value.replace("_", "a").replace("-", "a").isalnum()


def _read_guest_program() -> bytes:
    path = Path(__file__).with_name("time_source_guest.py")
    try:
        payload = path.read_bytes()
    except OSError:
        _fail("The pinned guest acceptance program is unavailable.")
    if not payload or len(payload) > 65_536:
        _fail("The guest acceptance program exceeded its size bound.")
    return payload


class _PinnedGuest:
    """Run the checked-in guest program over one fingerprint-pinned SSH session."""

    def __init__(self, host: str, username: str, password: str, fingerprint: str) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.policy = PinnedEd25519HostKeyPolicy(host, fingerprint)
        self.client: paramiko.SSHClient | None = None
        self._passwordless_sudo: bool | None = None
        self.source = _read_guest_program()
        self.remote_path = "/tmp/atlaso-time-source-" + secrets.token_hex(16) + ".py"

    def connect(self, *, timeout: float = 10) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(self.policy)
        try:
            client.connect(
                self.host,
                username=self.username,
                password=self.password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            self.client = client
            self._passwordless_sudo = None
            self._stage_program()
        except (OSError, paramiko.SSHException, EOFError):
            client.close()
            self.client = None
            _fail("Pinned SSH connection to the appliance failed.")

    def _stage_program(self) -> None:
        if self.client is None:
            _fail("Pinned SSH transport is unavailable.")
        try:
            sftp = self.client.open_sftp()
            try:
                with sftp.file(self.remote_path, "wb") as remote:
                    remote.write(self.source)
                sftp.chmod(self.remote_path, 0o600)
            finally:
                sftp.close()
        except (OSError, EOFError, paramiko.SSHException):
            _fail("Guest acceptance program staging failed over pinned SSH.")

    def close(self) -> None:
        if self.client is None:
            return
        try:
            sftp = self.client.open_sftp()
            try:
                sftp.remove(self.remote_path)
            finally:
                sftp.close()
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            self.client.close()
            self.client = None

    def _sudo_without_password(self) -> bool:
        if self.username == "root":
            return True
        if self._passwordless_sudo is not None:
            return self._passwordless_sudo
        if self.client is None:
            _fail("Pinned SSH transport is unavailable.")
        channel: paramiko.Channel | None = None
        try:
            transport = self.client.get_transport()
            if transport is None or not transport.is_authenticated():
                _fail("Pinned SSH transport is not authenticated.")
            channel = transport.open_session(timeout=5)
            channel.settimeout(5)
            channel.exec_command("sudo -n true")
            deadline = time.monotonic() + 8
            while not channel.exit_status_ready() and time.monotonic() < deadline:
                if channel.recv_ready():
                    channel.recv(4096)
                if channel.recv_stderr_ready():
                    channel.recv_stderr(4096)
                time.sleep(0.025)
            if not channel.exit_status_ready():
                _fail("The bounded guest privilege check timed out.")
            if channel.recv_ready():
                channel.recv(4096)
            if channel.recv_stderr_ready():
                channel.recv_stderr(4096)
            self._passwordless_sudo = channel.recv_exit_status() == 0
            return self._passwordless_sudo
        except TimeSourceAcceptanceError:
            raise
        except (OSError, EOFError, paramiko.SSHException, TimeoutError):
            _fail("The bounded guest privilege check failed.")
        finally:
            if channel is not None:
                channel.close()

    def invoke(
        self,
        action: str,
        *,
        management_host: str,
        web_username: str,
        web_password: str,
        on_capture_ready: Callable[[], None] | None = None,
        **parameters: Any,
    ) -> dict[str, Any]:
        if self.client is None or action not in _ACTION_TIMEOUTS:
            _fail("Guest action is unavailable or unsupported.")
        payload: dict[str, Any] = {
            "action": action,
            "host": management_host,
            "username": web_username,
            **parameters,
        }
        if action in _WEB_ACTIONS:
            payload["password"] = web_password
        command = f"{GUEST_PYTHON} -I {self.remote_path}"
        if self.username != "root":
            if self._sudo_without_password():
                command = "sudo -n " + command
                input_bytes = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
            else:
                command = "sudo -S -p '' " + command
                input_bytes = (self.password + "\n" + json.dumps(payload, separators=(",", ":")) + "\n").encode()
        else:
            input_bytes = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
        channel: paramiko.Channel | None = None
        output = bytearray()
        pending = bytearray()
        stderr_size = 0
        capture_started = False
        deadline = time.monotonic() + _ACTION_TIMEOUTS[action]
        try:
            transport = self.client.get_transport()
            if transport is None or not transport.is_authenticated():
                _fail("Pinned SSH transport is not authenticated.")
            channel = transport.open_session(timeout=10)
            channel.settimeout(1)
            channel.exec_command(command)
            channel.sendall(input_bytes)
            channel.shutdown_write()
            while True:
                if channel.recv_ready():
                    chunk = channel.recv(8192)
                    output.extend(chunk)
                    pending.extend(chunk)
                    if len(output) > MAX_GUEST_OUTPUT:
                        _fail("Guest acceptance output exceeded its bound.")
                    while b"\n" in pending:
                        line, _, remainder = pending.partition(b"\n")
                        pending[:] = remainder
                        if not line:
                            continue
                        try:
                            message = json.loads(line)
                        except (ValueError, UnicodeDecodeError):
                            _fail("Guest acceptance returned malformed structured output.")
                        if not isinstance(message, dict):
                            _fail("Guest acceptance returned an invalid result object.")
                        if action == "client_capture" and message.get("capture_ready") is True:
                            if capture_started or on_capture_ready is None:
                                _fail("Guest packet capture readiness was unexpected.")
                            capture_started = True
                            on_capture_ready()
                            continue
                        if message.get("ok") is not True:
                            stage = message.get("stage")
                            if isinstance(stage, str) and re.fullmatch(r"[a-z-]{1,40}", stage):
                                _fail(f"Guest acceptance action failed at {stage}.")
                            _fail("Guest acceptance action reported a bounded failure.")
                        return {key: value for key, value in message.items() if key not in {"ok", "capture_ready"}}
                if channel.recv_stderr_ready():
                    stderr_size += len(channel.recv_stderr(8192))
                    if stderr_size > MAX_GUEST_OUTPUT:
                        _fail("Guest acceptance diagnostic output exceeded its bound.")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    _fail("Guest acceptance ended without a successful structured result.")
                if time.monotonic() >= deadline:
                    _fail("Guest acceptance action exceeded its bounded timeout.")
                time.sleep(0.025)
        except TimeSourceAcceptanceError:
            raise
        except (OSError, EOFError, paramiko.SSHException, TimeoutError):
            _fail("Pinned guest acceptance channel failed or timed out.")
        finally:
            if channel is not None:
                channel.close()

    def wait_for_disconnect(self, timeout: float = 90) -> None:
        if self.client is None:
            _fail("Pinned SSH transport is unavailable during reboot verification.")
        transport = self.client.get_transport()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if transport is None or not transport.is_active():
                self.client.close()
                self.client = None
                return
            time.sleep(0.25)
        _fail("The appliance SSH connection did not disconnect during reboot.")

    def reconnect_after_reboot(self) -> None:
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                self.connect(timeout=5)
                return
            except TimeSourceAcceptanceError:
                time.sleep(2)
        _fail("Pinned SSH did not recover within the bounded reboot deadline.")


def _host_source_address(destination: str) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((destination, 123))
            source = str(ipaddress.IPv4Address(probe.getsockname()[0]))
    except (OSError, ValueError, IndexError):
        _fail("The host has no usable IPv4 route to the appliance probe target.")
    if ipaddress.IPv4Address(source).is_unspecified or ipaddress.IPv4Address(source).is_loopback:
        _fail("The host probe selected an unusable source address.")
    return source


def _probe_client_refusal(
    guest: _PinnedGuest,
    *,
    management_host: str,
    username: str,
    password: str,
) -> dict[str, Any]:
    source_address = _host_source_address(management_host)
    packet, _transmit = build_ntp_request()
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind((source_address, 0))
        source_port = int(probe.getsockname()[1])
        probe.settimeout(2)
    except OSError:
        _fail("The host could not prepare the bounded client-only UDP probe.")
    sent = False

    def send_query_and_require_refusal() -> None:
        nonlocal sent
        try:
            probe.sendto(packet, (management_host, 123))
            sent = True
            try:
                _response, _peer = probe.recvfrom(512)
            except socket.timeout:
                return
            except OSError as exc:
                if isinstance(exc, ConnectionRefusedError) or getattr(exc, "winerror", None) == 10054:
                    return
                _fail("The host UDP request did not complete within the expected refusal path.")
            _fail("Client mode returned an NTP response to a host query.")
        except OSError:
            _fail("The host could not deliver the client-only UDP probe.")

    try:
        result = guest.invoke(
            "client_capture",
            management_host=management_host,
            web_username=username,
            web_password=password,
            on_capture_ready=send_query_and_require_refusal,
            peer_ip=source_address,
            peer_port=source_port,
        )
    finally:
        probe.close()
    if not sent or result.get("probe_delivered_to_guest") is not True:
        _fail("The host UDP query was not proven at guest ingress.")
    return {"request_delivered": True, "ntp_response_received": False}


def _probe_server(
    address: str,
    network: ipaddress.IPv4Interface,
    source_address: str | None = None,
) -> dict[str, Any]:
    if source_address is None:
        source_address = _host_source_address(address)
    try:
        source_address = str(ipaddress.IPv4Address(source_address))
    except ValueError:
        _fail("The host server query source address is invalid.")
    if ipaddress.IPv4Address(source_address) not in network.network:
        _fail("The host server query did not route through the selected site network.")
    packet, transmit = build_ntp_request()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind((source_address, 0))
            probe.settimeout(5)
            probe.sendto(packet, (address, 123))
            response, peer = probe.recvfrom(512)
    except (OSError, TimeoutError):
        _fail("The host NTP server query received no response before its timeout.")
    return validate_ntp_server_response(response, peer, address, transmit)


def _windows_fixture_neighbor(
    address: str,
    network: ipaddress.IPv4Interface,
    site_network: str,
    expected_mac: str,
) -> dict[str, str]:
    if os.name != "nt":
        _fail("Host-side fixture ownership verification requires Windows VMware networking.")
    script = r'''
$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadLine() | ConvertFrom-Json
<#
.SYNOPSIS
Checks whether an IPv4 address belongs to the selected site subnet.
.PARAMETER address
The IPv4 address to check.
.PARAMETER networkAddress
The site subnet's IPv4 network address.
.PARAMETER prefixLength
The site subnet prefix length.
#>
function Test-SiteNetwork($address, $networkAddress, $prefixLength) {
    $addressBytes = ([Net.IPAddress]::Parse($address)).GetAddressBytes()
    $networkBytes = ([Net.IPAddress]::Parse($networkAddress)).GetAddressBytes()
    for ($index = 0; $index -lt 4; $index++) {
        $bits = [Math]::Min(8, [Math]::Max(0, $prefixLength - (8 * $index)))
        if ($bits -gt 0) {
            $mask = [int](256 - [Math]::Pow(2, 8 - $bits))
            if (($addressBytes[$index] -band $mask) -ne ($networkBytes[$index] -band $mask)) { return $false }
        }
    }
    return $true
}
$expectedAlias = "VMware Network Adapter $($request.site_network)"
$adapter = Get-NetAdapter -Name $expectedAlias -ErrorAction Stop
if ($adapter.Status -ne 'Up') { exit 2 }
$sources = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object { $_.PrefixLength -eq $request.prefix_length -and $_.AddressState -eq 'Preferred' -and
        (Test-SiteNetwork $_.IPAddress $request.network_address $request.prefix_length) }
if ($null -eq $sources) { exit 3 }
$selected = $null
$selectedRoute = $null
$selectedLocalAddress = $null
foreach ($source in $sources) {
    $routeResults = @(Find-NetRoute -LocalIPAddress $source.IPAddress -RemoteIPAddress $request.address)
    $localAddress = $routeResults | Where-Object {
        $_.PSObject.Properties['IPAddress'] -and $_.IPAddress -eq $source.IPAddress
    } | Select-Object -First 1
    $route = $routeResults | Where-Object {
        $_.PSObject.Properties['DestinationPrefix']
    } | Select-Object -First 1
    if ($null -ne $localAddress -and $null -ne $route -and
        $localAddress.InterfaceIndex -eq $adapter.InterfaceIndex -and
        $route.InterfaceIndex -eq $adapter.InterfaceIndex) {
        $selected = $source
        $selectedLocalAddress = $localAddress
        $selectedRoute = $route
        break
    }
}
if ($null -eq $selected) { exit 4 }
& ping.exe -S $selected.IPAddress -n 1 -w 1000 $request.address | Out-Null
$neighbor = Get-NetNeighbor -InterfaceIndex $adapter.InterfaceIndex -IPAddress $request.address -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $neighbor) { exit 5 }
[ordered]@{ alias=$adapter.Name; source=$selected.IPAddress; mac=$neighbor.LinkLayerAddress; state=[string]$neighbor.State;
    interface_index=[int]$adapter.InterfaceIndex; local_interface_index=[int]$selectedLocalAddress.InterfaceIndex;
    route_interface_index=[int]$selectedRoute.InterfaceIndex; route_source=$selectedLocalAddress.IPAddress } | ConvertTo-Json -Compress
'''
    request = json.dumps(
        {
            "address": address,
            "network_address": str(network.network.network_address),
            "prefix_length": network.network.prefixlen,
            "site_network": site_network,
        },
        separators=(",", ":"),
    ) + "\n"
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            input=request,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("Host-side fixture neighbor lookup failed or timed out.")
    if completed.returncode != 0 or len(completed.stdout) > 16_384:
        _fail("Host-side fixture neighbor ownership could not be confirmed.")
    try:
        observation = json.loads(completed.stdout)
        alias = str(observation["alias"])
        source = str(ipaddress.IPv4Address(observation["source"]))
        mac = str(observation["mac"]).replace("-", ":").lower()
        neighbor_state = str(observation["state"]).lower()
        interface_index = int(observation["interface_index"])
        local_interface_index = int(observation["local_interface_index"])
        route_interface_index = int(observation["route_interface_index"])
        route_source = str(ipaddress.IPv4Address(observation["route_source"]))
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        _fail("Host-side fixture neighbor response was invalid.")
    expected_alias = f"VMware Network Adapter {site_network}"
    if (
        alias.casefold() != expected_alias.casefold()
        or ipaddress.IPv4Address(source) not in network.network
        or interface_index <= 0
        or local_interface_index != interface_index
        or route_interface_index != interface_index
        or route_source != source
        or mac != expected_mac.replace("-", ":").lower()
        or neighbor_state not in {"reachable", "stale", "delay", "probe"}
    ):
        _fail("Host route or neighbor MAC does not match the selected VMware site fixture.")
    return {
        "interface": site_network,
        "source_address": source,
        "guest_mac": mac,
        "interface_index": str(interface_index),
        "route_interface_index": str(route_interface_index),
    }


class _AcceptanceRunner:
    """Coordinate the three clock modes and independent packet probes."""

    def __init__(
        self,
        args: Any,
        guest: Any,
        *,
        progress: Callable[[str], None] = print,
        client_probe: Callable[..., dict[str, Any]] = _probe_client_refusal,
        server_probe: Callable[..., dict[str, Any]] = _probe_server,
        fixture_neighbor: Callable[..., dict[str, str]] = _windows_fixture_neighbor,
    ) -> None:
        self.args = args
        self.guest = guest
        self.progress = progress
        self.client_probe = client_probe
        self.server_probe = server_probe
        self.fixture_neighbor = fixture_neighbor
        self.host, self.ssh_user, self.ssh_password, self.web_user, self.web_password, _pin = _identity(args)
        self.interface, self.site_network, self.server_address, self.site = _site_settings(args)
        self.steps: list[dict[str, Any]] = []
        self.fixture_source_address: str | None = None

    def _action(self, action: str, **parameters: Any) -> dict[str, Any]:
        return self.guest.invoke(
            action,
            management_host=self.host,
            web_username=self.web_user,
            web_password=self.web_password,
            **parameters,
        )

    def _step(self, name: str, operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        self.progress(f"[time-source] {name}")
        try:
            evidence = operation()
        except TimeSourceAcceptanceError:
            raise
        except Exception:  # noqa: BLE001 - sanitize every guest/channel exception before lifecycle evidence.
            _fail(f"Time-source acceptance failed during {name}.")
        if not isinstance(evidence, dict):
            _fail("Time-source acceptance step returned invalid evidence.")
        self.steps.append({"name": name, "status": "passed", "evidence": evidence})
        return evidence

    def _apply(self, mode: str) -> dict[str, Any]:
        evidence = self._action("apply", mode=mode, server_interface=self.interface, expected_health="healthy")
        if evidence.get("applied_mode") != mode or evidence.get("task_status") != "succeeded":
            _fail("Global Appliance Apply did not establish the requested clock mode.")
        clock = evidence.get("clock")
        if not isinstance(clock, dict) or clock.get("mode") != mode or clock.get("healthy") is not True:
            _fail("The requested clock mode did not become healthy after Apply.")
        if mode == "ntp_server" and evidence.get("remembered_time_source") != "vmware_tools":
            _fail("Enabling NTP server mode did not preserve the remembered VMware Tools selection.")
        return {"mode": mode, "healthy": True, "remembered_time_source": evidence.get("remembered_time_source")}

    def _wait_status(self, mode: str) -> dict[str, Any]:
        evidence = self._action("wait_status", assert_mode=mode, expected_health="healthy")
        clock = evidence.get("clock")
        if not isinstance(clock, dict) or clock.get("mode") != mode or clock.get("healthy") is not True:
            _fail("Clock health did not recover in the requested mode.")
        return {"mode": mode, "healthy": True}

    def _verify_fixture_identity(self) -> dict[str, str]:
        observed = self._action("fixture_identity", interface_name=self.interface, fixture_cidr=str(self.site))
        mac = str(observed.get("fixture_mac", "")).replace("-", ":").lower()
        if (
            observed.get("fixture_address") != self.server_address
            or observed.get("fixture_interface") != self.interface
            or not _valid_mac(mac)
        ):
            _fail("The guest did not report the requested site-interface address and MAC.")
        ownership = self.fixture_neighbor(self.server_address, self.site, self.site_network, mac)
        source_address = ownership.get("source_address")
        if not isinstance(source_address, str):
            _fail("The selected VMware site route did not provide a source address.")
        try:
            source_address = str(ipaddress.IPv4Address(source_address))
        except ValueError:
            _fail("The selected VMware site route returned an invalid source address.")
        if ipaddress.IPv4Address(source_address) not in self.site.network:
            _fail("The selected VMware site route source is outside the site subnet.")
        self.fixture_source_address = source_address
        return ownership

    def _reboot(self, expected_mode: str) -> dict[str, Any]:
        old = self._action("boot_id").get("boot_id")
        if not isinstance(old, str) or not old:
            _fail("The pre-reboot guest boot identity is unavailable.")
        scheduled = self._action("reboot")
        if scheduled.get("reboot_scheduled") is not True or scheduled.get("boot_id") != old:
            _fail("The guest did not confirm the bounded reboot request.")
        self.guest.wait_for_disconnect()
        self.guest.reconnect_after_reboot()
        new = self._action("boot_id").get("boot_id")
        if not isinstance(new, str) or not new or new == old:
            _fail("A new guest boot identity was not observed after the reboot.")
        status = self._wait_status(expected_mode)
        return {"boot_id_changed": True, "health": status["healthy"], "mode": expected_mode}

    def run(self) -> dict[str, Any]:
        helper_path = Path(__file__).resolve().parents[1] / "appliance" / "atlaso-helper"
        try:
            expected_helper_sha256 = hashlib.sha256(helper_path.read_bytes()).hexdigest()
            project = tomllib.loads((Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8"))
            expected_version = str(project["project"]["version"])
        except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError):
            _fail("The admitted helper or project version could not be verified locally.")
        try:
            identity = self._step("deployed-source-identity", lambda: self._action("deployment_identity"))
            if identity.get("helper_sha256") != expected_helper_sha256 or identity.get("installed_version") != expected_version:
                _fail("The running helper or application version differs from the admitted source.")
            self._step(
                "site-network-fixture",
                lambda: self._action(
                    "prepare_server_interface", interface_name=self.interface, fixture_cidr=str(self.site)
                ),
            )
            self._step("packet-capture-tool", lambda: self._action("install_probe_tools"))
            self._step("apply-ntp-client", lambda: self._apply("ntp_client"))
            refusal = self._step(
                "client-udp-refusal-and-ingress",
                lambda: self.client_probe(
                    self.guest,
                    management_host=self.host,
                    username=self.web_user,
                    password=self.web_password,
                ),
            )
            if refusal.get("request_delivered") is not True or refusal.get("ntp_response_received") is not False:
                _fail("Client-mode UDP refusal was not confirmed after guest ingress capture.")
            self._step("restart-vmware-tools-in-client-mode", lambda: self._action("tools_restart"))
            self._step("client-health-after-tools-restart", lambda: self._wait_status("ntp_client"))
            conflict = self._step("manual-vmware-time-conflict", lambda: self._action("conflict_enable"))
            clock = conflict.get("clock")
            conflicts = clock.get("conflicts") if isinstance(clock, dict) else None
            vmtools = conflicts.get("vmware_tools") if isinstance(conflicts, dict) else None
            if (
                not isinstance(clock, dict)
                or clock.get("mode") != "ntp_client"
                or clock.get("healthy") is not False
                or not isinstance(vmtools, dict)
                or vmtools.get("active") is not True
                or vmtools.get("enabled") is not True
            ):
                _fail("The competing VMware Tools controller was not reported as an unhealthy conflict.")
            ntpwait = self._step("bounded-ntpwait-diagnostic", lambda: self._action("ntpwait"))
            if ntpwait.get("ntpwait") not in {"synchronized", "bounded_timeout_or_failure", "unavailable"}:
                _fail("The bounded ntpwait diagnostic returned an unsupported outcome.")
            self._step("reapply-ntp-client-after-conflict", lambda: self._apply("ntp_client"))
            self._step("apply-vmware-tools", lambda: self._apply("vmware_tools"))
            self._step("vmware-tools-mode-reboot", lambda: self._reboot("vmware_tools"))
            self._step("restart-vmware-tools-after-reboot", lambda: self._action("tools_restart"))
            self._step("vmware-tools-health-after-restart", lambda: self._wait_status("vmware_tools"))
            server = self._step("apply-ntp-server-with-remembered-tools-choice", lambda: self._apply("ntp_server"))
            if server.get("remembered_time_source") != "vmware_tools":
                _fail("The server transition lost the remembered VMware Tools selection.")
            self._step("verify-site-fixture-address-ownership", self._verify_fixture_identity)
            self._step("positive-host-ntp-server-probe", lambda: self._probe_server_and_health())
            self._step("ntp-server-mode-reboot", lambda: self._reboot("ntp_server"))
            self._step("verify-site-fixture-after-reboot", self._verify_fixture_identity)
            self._step("positive-host-ntp-server-probe-after-reboot", lambda: self._probe_server_and_health())
            self._step("restore-vmware-tools-selection", lambda: self._apply("vmware_tools"))
            self._step("apply-final-ntp-client", lambda: self._apply("ntp_client"))
            final_reboot = self._step("final-client-mode-reboot", lambda: self._reboot("ntp_client"))
            final_refusal = self._step(
                "final-client-udp-refusal-and-ingress",
                lambda: self.client_probe(
                    self.guest,
                    management_host=self.host,
                    username=self.web_user,
                    password=self.web_password,
                ),
            )
            if final_refusal.get("request_delivered") is not True or final_refusal.get("ntp_response_received") is not False:
                _fail("Final client-mode UDP refusal was not confirmed after guest ingress capture.")
            return {
                "scenario": "time-source-native-acceptance",
                "status": "passed",
                "source_identity": {"helper_sha256": expected_helper_sha256, "application_version": expected_version},
                "client_udp_refusal": refusal,
                "ntpwait_diagnostic": ntpwait,
                "ntp_server_probe": {"status": "passed", "after_reboot": True},
                "final_reboot": final_reboot,
                "steps": self.steps,
            }
        except TimeSourceAcceptanceError:
            raise
        except Exception:  # noqa: BLE001 - keep host OS and guest diagnostics out of public evidence.
            _fail("Time-source native acceptance failed; detailed diagnostics were suppressed.")

    def _probe_server_and_health(self) -> dict[str, Any]:
        if self.fixture_source_address is None:
            _fail("The VMware site route was not verified before the server probe.")
        response = self.server_probe(self.server_address, self.site, self.fixture_source_address)
        if (
            response.get("peer_address") != self.server_address
            or response.get("peer_port") != 123
            or response.get("mode") != 4
            or response.get("version") not in {3, 4}
            or response.get("leap_alarm") is not False
            or response.get("stratum", 0) not in range(1, 16)
            or response.get("originate_timestamp_matched") is not True
            or response.get("transmit_timestamp_present") is not True
        ):
            _fail("The host NTP server response did not satisfy the positive-probe contract.")
        status = self._action("status", assert_mode="ntp_server", expected_health="healthy")
        clock = status.get("clock")
        if not isinstance(clock, dict) or clock.get("mode") != "ntp_server" or clock.get("healthy") is not True:
            _fail("The NTP server controller was not healthy during the host probe.")
        return {
            "peer_address": response["peer_address"],
            "peer_port": response["peer_port"],
            "response_mode": response["mode"],
            "response_version": response["version"],
            "stratum": int(response["stratum"]),
            "leap_alarm": response["leap_alarm"],
            "originate_timestamp_matched": response["originate_timestamp_matched"],
            "transmit_timestamp_present": response["transmit_timestamp_present"],
            "clock_healthy": True,
        }


def _valid_mac(value: str) -> bool:
    parts = value.split(":")
    return len(parts) == 6 and all(len(part) == 2 and all(char in "0123456789abcdef" for char in part) for part in parts)


def run_time_source_acceptance(args: Any) -> dict[str, Any]:
    """Run the bounded clock-source scenario over pinned SSH and the normal UI.

    The canonical lifecycle caller passes credentials populated from its
    validated secret-stdin envelope. Passwords are sent only on the SSH
    authentication API or the SSH channel's stdin, never in command arguments
    or evidence.
    """
    host, ssh_user, ssh_password, _web_user, _web_password, fingerprint = _identity(args)
    _site_settings(args)
    guest = _PinnedGuest(host, ssh_user, ssh_password, fingerprint)
    runner: _AcceptanceRunner | None = None
    try:
        guest.connect()
        runner = _AcceptanceRunner(args, guest)
        return runner.run()
    except TimeSourceAcceptanceError:
        raise
    except Exception:  # noqa: BLE001 - public boundary must suppress transport and credential diagnostics.
        _fail("Time-source native acceptance failed; detailed diagnostics were suppressed.")
    finally:
        guest.close()
