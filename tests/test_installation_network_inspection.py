"""Private-console network observations and pinned public HTTPS acceptance."""

import base64
import hashlib
import json
import shlex
import socket
import ssl
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scripts.installation import inspection, network_inspection

_ISO = "a" * 64
_MAC = "00:0c:29:12:34:56"
_CERT = b"public certificate DER fixture"


def _report(**changes):
    """Build a public network record with one admitted adapter.

    Args:
        **changes: Independent malformed or mismatched fields.
    """
    return {"schema": 1, "kind": "network", "iso_sha256": _ISO, "interface": "eth0", "mac": _MAC,
            "address": "192.168.84.20", "prefixlen": 24, "default_routes_absent": True,
            "certificate_sha256": hashlib.sha256(_CERT).hexdigest(), **changes}


def test_network_report_requires_exact_original_adapter():
    """Valid public observations retain the original media, MAC and subnet."""
    report = _report()
    assert network_inspection.validate_network_report(json.dumps(report).encode(), _ISO, _MAC, "192.168.84.0", 24) == report


@pytest.mark.parametrize("mac", [_MAC, "00:0c:29:12:34:57"])
def test_network_cli_binds_native_adapter_and_never_emits_rejected_record(mac, monkeypatch, capsys):
    """The actual CLI retains its fixed non-disclosing refusal contract.

    Args:
        mac: Original native adapter identity or a mismatched adapter.
        monkeypatch: Set bounded public CLI inputs.
        capsys: Capture the validated public result or generic refusal.
    """
    report = base64.b64encode(json.dumps(_report()).encode()).decode()
    monkeypatch.setattr(sys, "argv", ["inspection", "validate-network", "--iso-sha256", _ISO,
                                     "--mac", mac, "--subnet", "192.168.84.0", "--prefixlen", "24", "--report", report])
    assert inspection.main() == (0 if mac == _MAC else 2)
    captured = capsys.readouterr()
    if mac == _MAC:
        assert json.loads(captured.out) == _report() and captured.err == ""
    else:
        assert captured.out == "" and captured.err == "Installed inspection could not validate its bounded inputs.\n"


@pytest.mark.parametrize("changes", [
    {"private": "private-sentinel"}, {"schema": True}, {"iso_sha256": "b" * 64},
    {"mac": "00:0c:29:12:34:57"}, {"mac": "01:0c:29:12:34:56"},
    {"address": "192.168.85.20"}, {"address": "192.168.84.0"}, {"address": "192.168.84.255"},
    {"address": "8.8.8.8"}, {"address": "127.0.0.1"}, {"address": "host.example.test"},
    {"prefixlen": True}, {"prefixlen": 16}, {"interface": "lo"}, {"interface": "private\nvalue"},
    {"certificate_sha256": "not-a-digest"}, {"default_routes_absent": False},
])
def test_network_report_refuses_unbound_or_private_fields(changes):
    """Only observations matching the native host-only admission may be emitted.

    Args:
        changes: Independently invalid record fields.
    """
    with pytest.raises(ValueError):
        network_inspection.validate_network_report(json.dumps(_report(**changes)).encode(), _ISO, _MAC, "192.168.84.0", 24)


@pytest.mark.parametrize("default_route", [False, True])
def test_guest_network_command_is_read_only_and_suppresses_raw_failures(default_route, monkeypatch, capsys):
    """Exercise the actual encoded producer with public network/TLS fixtures.

    Args:
        default_route: Whether an IPv4 default route invalidates isolation.
        monkeypatch: Substitute read-only process and TLS observations.
        capsys: Capture the bounded wire record or fixed failure stage.
    """
    command = network_inspection.guest_network_program(_ISO)
    assert len(command) <= 3500 and "ATLASO-INSPECTION" not in command
    decoded = []
    exec(shlex.split(command)[4], {"exec": decoded.append})
    compile(decoded[0], "<network-observation>", "exec")
    calls = []

    def run(arguments, **kwargs):
        """Return only fixed ip-address or route observations.

        Args:
            arguments: Actual producer command vector.
            **kwargs: Bounded subprocess options under test.
        """
        assert kwargs == {"capture_output": True, "timeout": 5, "check": True}
        calls.append(arguments)
        if "addr" in arguments:
            value = [{"ifname": "eth0",
                      "addr_info": [{"family": "inet", "scope": "global", "local": "192.168.84.20", "prefixlen": 24}]}]
            # Native ip -4 omits link-layer fields even when IPv4 is present.
            if "-4" not in arguments:
                value[0]["address"] = _MAC
        else:
            assert arguments in [["ip", "-j", "-4", "route", "show", "default"], ["ip", "-j", "-6", "route", "show", "default"]]
            value = [{"dst": "default", "private": "private-sentinel"}] if default_route else []
        return SimpleNamespace(stdout=json.dumps(value).encode(), stderr=b"")

    class Peer:
        """Fixed public TLS socket with no guest files or credentials."""

        def __enter__(self):
            return self

        def __exit__(self, *args):
            """Leave the controlled TLS connection without suppressing failures.

            Args:
                *args: Exception details supplied by the context-manager protocol.
            """
            return False

        def getpeercert(self, *, binary_form):
            """Return the fixture's public certificate bytes.

            Args:
                binary_form: Whether the caller requested the DER certificate.
            """
            assert binary_form is True
            return _CERT

    class Context:
        """Observe the producer's local certificate-read connection."""

        def __init__(self, protocol):
            """Require the producer's explicit TLS client protocol.

            Args:
                protocol: TLS protocol selected by the real producer.
            """
            assert protocol == ssl.PROTOCOL_TLS_CLIENT

        def wrap_socket(self, peer, *, server_hostname):
            """Wrap the controlled guest-local connection.

            Args:
                peer: Connected fixture socket passed to the TLS context.
                server_hostname: Optional SNI name, absent for this address probe.
            """
            assert isinstance(peer, Peer) and server_hostname is None
            return Peer()

    def connect(endpoint, *, timeout):
        """Require a bounded TLS read from the observed guest-local address.

        Args:
            endpoint: Producer's own observed address and fixed HTTPS port.
            timeout: Socket deadline in seconds.
        """
        assert endpoint == ("192.168.84.20", 443) and timeout == 3
        return Peer()

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl, "SSLContext", Context)
    exec(decoded[0], {})
    captured = capsys.readouterr()
    assert captured.err == "" and "private-sentinel" not in captured.out
    if default_route:
        assert captured.out == "ATLASO-INSPECTION-FAILED:system-network-routes\n"
    else:
        raw = base64.b64decode(captured.out.strip().removeprefix("ATLASO-INSPECTION:").removesuffix(":END"), validate=True)
        assert network_inspection.validate_network_report(raw, _ISO, _MAC, "192.168.84.0", 24) == _report()
        assert len(calls) == 3


@pytest.mark.parametrize("defect", [None, "certificate", "status", "version", "oversize", "content-type"])
def test_host_probe_pins_tls_before_http_and_bounds_public_schema(defect, monkeypatch):
    """A wrong TLS peer receives no HTTP request; invalid schemas fail closed.

    Args:
        defect: One independent peer or response failure.
        monkeypatch: Replace the HTTPS transport with a controlled public fixture.
    """
    calls = []

    class Connection:
        """Track the real probe's TLS, HTTP and close ordering."""

        def __init__(self, address, port, *, timeout, context):
            """Admit the probe's fixed endpoint and bounded TLS transport.

            Args:
                address: Observed guest address under test.
                port: HTTPS service port selected by the probe.
                timeout: Transport deadline in seconds.
                context: TLS context supplied by the real probe.
            """
            assert (address, port, timeout) == ("192.168.84.20", 443, 10)
            self.sock = SimpleNamespace(getpeercert=lambda **kwargs: b"different public certificate" if defect == "certificate" else _CERT)

        def connect(self):
            calls.append("tls")

        def request(self, method, path, *, headers):
            """Record only the expected unauthenticated OpenAPI request.

            Args:
                method: HTTP method submitted after TLS admission.
                path: Requested public endpoint.
                headers: Request headers checked for credential absence.
            """
            assert (method, path) == ("GET", "/openapi.json") and "Authorization" not in headers
            calls.append("http")

        def getresponse(self):
            raw = json.dumps({"openapi": "3.1.0", "info": {"version": "9.9.9" if defect == "version" else "0.9.465"},
                              "paths": {"/api/v1/health": {}}}).encode()
            return SimpleNamespace(status=503 if defect == "status" else 200,
                                   getheader=lambda *args: "text/html" if defect == "content-type" else "application/json",
                                   read=lambda size: b"x" * size if defect == "oversize" else raw)

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(network_inspection.http.client, "HTTPSConnection", Connection)
    if defect:
        with pytest.raises(ValueError):
            network_inspection.probe_openapi("192.168.84.20", hashlib.sha256(_CERT).hexdigest(), "0.9.465")
    else:
        result = network_inspection.probe_openapi("192.168.84.20", hashlib.sha256(_CERT).hexdigest(), "0.9.465")
        assert result["status"] == 200 and result["version"] == "0.9.465" and result["path_count"] == 1
    assert calls[-1] == "closed"
    assert ("http" not in calls) == (defect == "certificate")


@pytest.mark.parametrize("case", ["ready", "warming", "deadline", "late-ready", "changed-peer", "wrong-version", "forbidden"])
def test_host_readiness_requires_pinned_valid_api_before_deadline(case, monkeypatch):
    """Retry only transient upstream statuses and recheck the TLS peer each time.

    Args:
        case: Startup recovery or an independently fatal admission failure.
        monkeypatch: Replace transport and clock without waiting or opening sockets.
    """
    responses = {
        "ready": [(200, _CERT, "0.9.465")],
        "warming": [(502, _CERT, "0.9.465"), (503, _CERT, "0.9.465"), (504, _CERT, "0.9.465"), (200, _CERT, "0.9.465")],
        "deadline": [(502, _CERT, "0.9.465")] * 2,
        "late-ready": [(200, _CERT, "0.9.465")],
        "changed-peer": [(502, _CERT, "0.9.465"), (200, b"different public leaf", "0.9.465")],
        "wrong-version": [(502, _CERT, "0.9.465"), (200, _CERT, "9.9.9")],
        "forbidden": [(403, _CERT, "0.9.465")],
    }[case]
    clock = [0.0]
    calls = []

    def sleep(seconds):
        """Advance the controlled clock by the requested bounded delay.

        Args:
            seconds: Retry delay selected by the readiness loop.
        """
        assert 0 < seconds <= 1
        clock[0] += seconds

    class Connection:
        """Exercise real leaf and response validation over a sequenced transport."""

        def __init__(self, address, port, *, timeout, context):
            """Admit only the fixed public endpoint and transport deadline.

            Args:
                address: Originally observed private address.
                port: HTTPS listener selected by the real probe.
                timeout: Existing per-connection timeout.
                context: TLS configuration used for explicit public-leaf pinning.
            """
            assert (address, port, timeout) == ("192.168.84.20", 443, 10)
            assert context.verify_mode == ssl.CERT_NONE and not context.check_hostname
            self.index = len(calls)
            self.response = responses[self.index]
            calls.append([])
            self.sock = SimpleNamespace(getpeercert=lambda **kwargs: self.response[1])

        def connect(self):
            calls[self.index].append("tls")

        def request(self, method, path, *, headers):
            """Record an unauthenticated request after the real certificate check.

            Args:
                method: Public GET method.
                path: Exact OpenAPI path.
                headers: Bounded public headers without credentials.
            """
            assert (method, path) == ("GET", "/openapi.json") and "Authorization" not in headers
            calls[self.index].append("http")

        def getresponse(self):
            if case == "late-ready":
                clock[0] += 3
            raw = json.dumps({"openapi": "3.1.0", "info": {"version": self.response[2]}, "paths": {"/api/v1/health": {}}}).encode()
            return SimpleNamespace(status=self.response[0], getheader=lambda *args: "application/json", read=lambda size: raw)

        def close(self):
            calls[self.index].append("closed")

    monkeypatch.setattr(network_inspection.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(network_inspection.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(network_inspection.time, "sleep", sleep)
    if case in {"ready", "warming"}:
        result = network_inspection.wait_for_openapi("192.168.84.20", hashlib.sha256(_CERT).hexdigest(), "0.9.465", 5)
        assert result["status"] == 200 and result["version"] == "0.9.465"
        assert result["readiness_attempts"] == len(responses)
    else:
        with pytest.raises(ValueError):
            network_inspection.wait_for_openapi("192.168.84.20", hashlib.sha256(_CERT).hexdigest(), "0.9.465", 2)
    assert len(calls) == len(responses)
    assert all(call[0] == "tls" and call[-1] == "closed" for call in calls)
    assert ("http" not in calls[-1]) == (case == "changed-peer")


@pytest.mark.parametrize("bound", [0, 46, True, 1.5])
def test_readiness_refuses_invalid_bounds_before_transport(bound, monkeypatch):
    """An invalid readiness window never opens a transport.

    Args:
        bound: Invalid or non-integral caller-supplied deadline.
        monkeypatch: Reject any attempted transport before admission.
    """
    def unexpected(*args):
        """Refuse an unexpected transport call.

        Args:
            *args: Public probe arguments that must remain unused.
        """
        pytest.fail("invalid readiness bounds must not reach the network")

    monkeypatch.setattr(network_inspection, "probe_openapi", unexpected)
    with pytest.raises(ValueError, match="readiness bound is invalid"):
        network_inspection.wait_for_openapi("192.168.84.20", hashlib.sha256(_CERT).hexdigest(), "0.9.465", bound)


def test_readiness_cli_preserves_non_disclosing_failure(monkeypatch, capsys):
    """The actual readiness CLI suppresses private exceptions like other inspections.

    Args:
        monkeypatch: Select the readiness operation and replace its bounded probe.
        capsys: Capture only the CLI's public success or refusal contract.
    """
    def fail(*args):
        """Raise a synthetic detail that must remain private.

        Args:
            *args: Public readiness arguments supplied by the CLI.
        """
        raise ValueError("PrivateSyntheticReadinessDetail")

    monkeypatch.setattr(network_inspection, "wait_for_openapi", fail)
    monkeypatch.setattr(sys, "argv", ["inspection", "wait-openapi", "--address", "192.168.84.20",
                                    "--certificate-sha256", hashlib.sha256(_CERT).hexdigest(), "--version", "0.9.465"])
    assert inspection.main() == 2
    captured = capsys.readouterr()
    assert not captured.out and captured.err == "Installed inspection could not validate its bounded inputs.\n"
