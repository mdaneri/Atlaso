"""Rendered-form parsing regressions for native time-source acceptance."""

from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

from atlaso.app.adapters.system import AdapterResult
from scripts.interop import time_source_acceptance as host_acceptance
from tests.routers.ui.helpers import login


def _load_guest_module():
    """Load the isolated guest program without running its entry point."""
    path = Path(__file__).resolve().parents[1] / "scripts" / "interop" / "time_source_guest.py"
    spec = importlib.util.spec_from_file_location("time_source_guest_form_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_fixture_identity_reads_all_family_inventory_for_mac_and_ipv4_proof(monkeypatch):
    """The identity probe uses link inventory because IPv4-only output can omit MAC.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    guest = _load_guest_module()
    payload = {
        "action": "fixture_identity",
        "fixture_cidr": "192.0.2.87/24",
        "interface_name": "ens192",
    }
    ipv4_only_rows = [{
        "ifname": "ens192",
        "addr_info": [{"family": "inet", "local": "192.0.2.87", "prefixlen": 24}],
    }]
    all_family_rows = [{
        "ifname": "ens192",
        "address": "00:0c:29:2b:d2:52",
        "addr_info": [
            {"family": "inet", "local": "192.0.2.87", "prefixlen": 24},
            {"family": "inet6", "local": "fe80::20c:29ff:fe2b:d252", "prefixlen": 64},
        ],
    }]
    commands = []

    def check_output(command, *, timeout):
        """Return the mocked guest interface inventory for the requested ip command.

        Args:
            command: Command argument vector passed to the subprocess boundary.
            timeout: Bounded timeout in seconds for the request, probe, or channel operation.
        """
        commands.append((command, timeout))
        if command == ["ip", "-j", "-4", "addr", "show"]:
            return json.dumps(ipv4_only_rows).encode()
        assert command == ["ip", "-j", "addr", "show"]
        return json.dumps(all_family_rows).encode()

    monkeypatch.setattr(guest.subprocess, "check_output", check_output)

    identity = guest.run_action(payload)

    assert commands == [(["ip", "-j", "addr", "show"], 5)]
    assert identity == {
        "fixture_address": "192.0.2.87",
        "fixture_interface": "ens192",
        "fixture_mac": "00:0c:29:2b:d2:52",
    }


@pytest.mark.parametrize(
    ("interface_name", "fixture_cidr", "rows", "reason"),
    [
        (
            "ens224",
            "192.0.2.87/24",
            [{"ifname": "ens192", "address": "00:0c:29:2b:d2:52", "addr_info": [
                {"family": "inet", "local": "192.0.2.87", "prefixlen": 24}
            ]}],
            "address is not assigned",
        ),
        (
            "ens192",
            "192.0.2.87/24",
            [{"ifname": "ens192", "address": "00:0c:29:2b:d2:52", "addr_info": [
                {"family": "inet", "local": "192.0.2.88", "prefixlen": 24}
            ]}],
            "address is not assigned",
        ),
        (
            "ens192",
            "192.0.2.87/24",
            [{"ifname": "ens192", "address": "00:0c:29:2b:d2:52", "addr_info": [
                {"family": "inet", "local": "192.0.2.87", "prefixlen": 25}
            ]}],
            "address is not assigned",
        ),
        (
            "ens192",
            "192.0.2.87/24",
            [{"ifname": "ens192", "address": "not-a-mac", "addr_info": [
                {"family": "inet", "local": "192.0.2.87", "prefixlen": 24}
            ]}],
            "hardware identity is unavailable",
        ),
    ],
    ids=["wrong-interface", "wrong-address", "wrong-cidr-prefix", "invalid-mac"],
)
def test_fixture_identity_rejects_mismatched_guest_network_identity(
    monkeypatch, interface_name, fixture_cidr, rows, reason
):
    """A matching address, prefix, selected interface, and MAC are all required.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        interface_name: Name of the selected appliance interface.
        fixture_cidr: Expected IPv4 CIDR assigned to the selected guest interface.
        rows: Guest link-inventory rows returned by the mocked address command.
        reason: Expected safe failure detail or rejection reason for this case.

    """
    guest = _load_guest_module()
    commands = []

    def check_output(command, *, timeout):
        """Return the mocked guest interface inventory for the requested ip command.

        Args:
            command: Command argument vector passed to the subprocess boundary.
            timeout: Bounded timeout in seconds for the request, probe, or channel operation.
        """
        commands.append((command, timeout))
        assert command == ["ip", "-j", "addr", "show"]
        return json.dumps(rows).encode()

    monkeypatch.setattr(guest.subprocess, "check_output", check_output)

    with pytest.raises(guest.SafeFailure, match=reason):
        guest.run_action({
            "action": "fixture_identity",
            "fixture_cidr": fixture_cidr,
            "interface_name": interface_name,
        })

    assert commands == [(["ip", "-j", "addr", "show"], 5)]


def _enable_vmware_capability(monkeypatch) -> None:
    """Render VMware Tools as a selectable saved source in the real NTP page.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_capabilities",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ntpd", "capabilities"],
            dry_run=False,
            stdout=json.dumps({"nts": True, "vmware_tools": True}),
        ),
    )


def _save_vmware_choice(client, monkeypatch):
    """Persist VMware Tools through the real autosave route before rendering.

    Args:
        client: Application test client used to exercise the management UI.
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    _enable_vmware_capability(monkeypatch)
    login(client)
    page = client.get("/ui/management/ntp")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    saved = client.post(
        "/ui/management/ntp/settings",
        data={"time_source": "vmware_tools", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert saved.status_code == 200
    assert saved.json()["time_source"] == "vmware_tools"
    return csrf


def _guest_page_from_rendered_response(guest, page):
    """Make the guest parser consume the exact HTML returned by the app route.

    Args:
        guest: Guest action client or parsed guest module under test.
        page: Rendered management page response consumed by the guest form parser.

    """
    def read_page(_opener, path, **_kwargs):
        """Return the real rendered page through the guest request boundary.

        Args:
            _opener: HTTP opener accepted by the mocked page reader but intentionally unused.
            path: Management endpoint path or owned filesystem root used by this operation.
            **_kwargs: Unused keyword arguments accepted by the mocked request callback.
        """
        assert path == "/ntp"
        return page.status_code, page.url, page.headers, page.content

    guest.request = read_page
    return guest.ntp_page(object())


def test_form_parser_reads_selected_option_and_omits_disabled_select_controls():
    """Use selected option semantics while retaining successful-control rules."""
    guest = _load_guest_module()
    parser = guest.FormParser()
    parser.feed(
        '<form id="ntp-settings-form">'
        '<select name="time_source"><option value="ntp_client">NTP client</option>'
        '<option value="vmware_tools" selected>VMware Tools</option></select>'
        '<select name="disabled_choice" disabled><option value="ignored" selected>Ignored</option></select>'
        '</form>'
    )

    assert parser.fields == [("time_source", "vmware_tools")]


def test_non_web_boot_id_action_does_not_open_https_listener(monkeypatch):
    """A reboot check reads local guest state before nginx is ready.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    guest = _load_guest_module()
    stdout = io.StringIO()
    payload = {"action": "boot_id", "host": "192.168.100.2", "username": "admin"}
    monkeypatch.setattr(guest.sys, "stdin", io.StringIO(json.dumps(payload) + "\n"))
    monkeypatch.setattr(guest.sys, "stdout", stdout)
    monkeypatch.setattr(
        guest.subprocess,
        "check_output",
        lambda *_args, **_kwargs: b'[{"addr_info":[{"local":"192.168.100.2"}]}]',
    )
    monkeypatch.setattr(
        guest.ssl,
        "get_server_certificate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("A local boot identity action must not require HTTPS.")
        ),
    )
    observed = []
    monkeypatch.setattr(
        guest,
        "run_action",
        lambda request: observed.append(request["action"]) or {"boot_id": "boot-id"},
    )

    guest.main()

    assert observed == ["boot_id"]
    assert guest.TLS_CONTEXT is None
    assert json.loads(stdout.getvalue()) == {"ok": True, "boot_id": "boot-id"}


@pytest.mark.parametrize(
    ("action", "expected_timeout"),
    [("wait_status", 120), ("status", 15)],
)
def test_web_action_uses_action_specific_listener_recovery_budget(
    monkeypatch, action, expected_timeout
):
    """Allow post-reboot status polling to wait for HTTPS bootstrap.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        action: Time-source operation name dispatched to the isolated guest.
        expected_timeout: Expected listener-recovery timeout for the selected action.

    """
    guest = _load_guest_module()
    stdout = io.StringIO()
    payload = {"action": action, "host": "192.168.100.2", "username": "admin"}
    observed = []
    monkeypatch.setattr(guest.sys, "stdin", io.StringIO(json.dumps(payload) + "\n"))
    monkeypatch.setattr(guest.sys, "stdout", stdout)
    monkeypatch.setattr(
        guest.subprocess,
        "check_output",
        lambda *_args, **_kwargs: b'[{"addr_info":[{"local":"192.168.100.2"}]}]',
    )
    monkeypatch.setattr(
        guest,
        "initialize_tls_context",
        lambda host, *, timeout_seconds: observed.append((host, timeout_seconds))
        or object(),
    )
    monkeypatch.setattr(guest, "run_action", lambda _request: {"healthy": True})

    guest.main()

    assert observed == [("192.168.100.2", expected_timeout)]
    assert json.loads(stdout.getvalue()) == {"ok": True, "healthy": True}


def test_web_tls_initialization_retries_listener_recovery_within_deadline(monkeypatch):
    """Retry a transient closed listener, then trust the exact served leaf.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    guest = _load_guest_module()
    clock = [0.0]
    attempts = []

    class FakeContext:
        verify_flags = 0
        check_hostname = True

    context = FakeContext()

    def get_certificate(address, *, timeout):
        """Return a served certificate after the configured listener retries.

        Args:
            address: IPv4 address used as the NTP peer or fixture target.
            timeout: Bounded timeout in seconds for the request, probe, or channel operation.
        """
        attempts.append((address, timeout))
        if len(attempts) < 3:
            raise ConnectionRefusedError("transient listener startup detail")
        return "served-leaf"

    monkeypatch.setattr(guest.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(guest.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))
    monkeypatch.setattr(guest.ssl, "get_server_certificate", get_certificate)
    monkeypatch.setattr(guest.ssl, "create_default_context", lambda *, cadata: context)

    result = guest.initialize_tls_context("192.168.100.2", timeout_seconds=5)

    assert result is context
    assert len(attempts) == 3
    assert all(address == ("192.168.100.2", 443) for address, _ in attempts)
    assert all(timeout <= 5 for _, timeout in attempts)
    assert context.check_hostname is False


def test_web_tls_initialization_fails_safely_when_listener_never_recovers(monkeypatch):
    """Stop retrying at the deadline without exposing transport error details.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    guest = _load_guest_module()
    clock = [0.0]
    attempts = []
    monkeypatch.setattr(guest.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(guest.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))

    def refuse(_address, *, timeout):
        """Simulate a refused HTTPS listener connection.

        Args:
            _address: Address accepted by the mocked callback but intentionally unused.
            timeout: Bounded timeout in seconds for the request, probe, or channel operation.
        """
        attempts.append(timeout)
        raise ConnectionRefusedError("private socket detail")

    monkeypatch.setattr(guest.ssl, "get_server_certificate", refuse)

    with pytest.raises(guest.SafeFailure) as error:
        guest.initialize_tls_context("192.168.100.2", timeout_seconds=2)

    assert len(attempts) == 2
    assert "private socket detail" not in error.value.reason
    assert error.value.stage == "https-listener"


@pytest.mark.parametrize("ready_delay", [1, 85], ids=["brief-gateway-error", "slow-appliance-startup"])
def test_wait_status_login_retries_read_only_until_ready_then_posts_once(monkeypatch, ready_delay):
    """Wait through a transient gateway error before the single credential POST.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        ready_delay: Simulated delay before the appliance login endpoint becomes ready.

    """
    guest = _load_guest_module()
    guest.BASE = "https://192.168.100.2/ui/management"
    opens = []
    posts = []
    clock = [0.0]

    class Response:
        def __init__(self, status, body=b""):
            """Initialize the containing test double state.

            Args:
                status: Mocked HTTP status code returned by the response object.
                body: Response body bytes returned by the mocked HTTP endpoint.
            """
            self.status = status
            self.body = body
            self.url = "https://192.168.100.2/ui/management/login"
            self.headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            """Close the mocked response context without suppressing exceptions.

            Args:
                *_args: Unused positional arguments accepted by the response context-manager protocol.
            """
            return False

        def read(self, _limit):
            """Return the mocked response bytes within the requested read limit.

            Args:
                _limit: Maximum byte count requested by the mocked response reader.
            """
            return self.body

    class Opener:
        def open(self, request, *, timeout):
            """Return the mocked response or raise the configured listener error.

            Args:
                request: HTTP request object supplied to the mocked opener.
                timeout: Bounded timeout in seconds for the request, probe, or channel operation.
            """
            opens.append((request.data, timeout))
            if request.data is not None:
                posts.append(request.data)
                return Response(303)
            if clock[0] < ready_delay:
                raise HTTPError(request.full_url, 503, "gateway", None, io.BytesIO())
            return Response(200, b'<input name="csrf" value="ready-token">')

    opener = Opener()
    monkeypatch.setattr(guest, "build_opener", lambda *_args: opener)
    monkeypatch.setattr(guest.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(guest.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))

    result = guest.login("test-password", readiness_timeout=guest.WAIT_STATUS_LOGIN_READY_TIMEOUT_SECONDS)

    assert result is opener
    assert clock[0] == ready_delay
    assert len(opens) == ready_delay + 2
    assert all(data is None and timeout <= 5 for data, timeout in opens[:-1])
    assert opens[-1][1] == 20
    assert len(posts) == 1
    assert b"ready-token" in posts[0]


def test_wait_status_login_readiness_deadline_never_posts_credentials(monkeypatch):
    """Bound repeated transport failures to the readiness deadline.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    guest = _load_guest_module()
    guest.BASE = "https://192.168.100.2/ui/management"
    clock = [0.0]
    requests = []

    class Opener:
        def open(self, request, *, timeout):
            """Return the mocked response or raise the configured listener error.

            Args:
                request: HTTP request object supplied to the mocked opener.
                timeout: Bounded timeout in seconds for the request, probe, or channel operation.
            """
            requests.append((request.data, timeout))
            raise URLError("private transport detail")

    monkeypatch.setattr(guest, "build_opener", lambda *_args: Opener())
    monkeypatch.setattr(guest.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        guest.time,
        "sleep",
        lambda delay: clock.__setitem__(0, clock[0] + delay),
    )

    with pytest.raises(guest.SafeFailure) as error:
        guest.login("test-password", readiness_timeout=3)

    assert error.value.stage == "login-readiness"
    assert len(requests) == 3
    assert all(body is None and timeout <= 5 for body, timeout in requests)


def test_wait_status_login_nonretryable_http_error_never_posts_credentials(monkeypatch):
    """Fail closed on an authentication response rather than retrying or posting.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    guest = _load_guest_module()
    guest.BASE = "https://192.168.100.2/ui/management"
    requests = []

    class Opener:
        def open(self, request, *, timeout):
            """Return the mocked response or raise the configured listener error.

            Args:
                request: HTTP request object supplied to the mocked opener.
                timeout: Bounded timeout in seconds for the request, probe, or channel operation.
            """
            requests.append(request.data)
            raise HTTPError(request.full_url, 401, "unauthorized", None, io.BytesIO())

    monkeypatch.setattr(guest, "build_opener", lambda *_args: Opener())

    with pytest.raises(guest.SafeFailure) as error:
        guest.login("test-password", readiness_timeout=60)

    assert error.value.stage == "login-readiness"
    assert requests == [None]


def test_wait_status_host_budget_covers_web_listener_and_clock_recovery():
    """Keep the host channel above each bounded recovery and HTTP phase."""
    guest = _load_guest_module()
    minimum_seconds = (
        guest.WAIT_STATUS_TLS_TIMEOUT_SECONDS
        + guest.WAIT_STATUS_LOGIN_READY_TIMEOUT_SECONDS
        + 20
        + 90
        + 20
    )
    host_budget = host_acceptance._ACTION_TIMEOUTS["wait_status"]

    assert host_budget > minimum_seconds
    assert host_budget <= 600


def test_rendered_ntp_page_keeps_source_when_select_is_enabled_and_hidden_copy_disabled(
    client, monkeypatch
):
    """Read the selected source from real HTML when the hidden mirror is disabled.

    Args:
        client: Application test client used to exercise the management UI.
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    guest = _load_guest_module()
    _save_vmware_choice(client, monkeypatch)
    page = client.get("/ui/management/ntp")
    assert page.status_code == 200
    select = re.search(r'<select name="time_source"([^>]*)>(.*?)</select>', page.text, re.S)
    preserved = re.search(r'<input type="hidden" name="time_source"[^>]*>', page.text)
    assert select is not None and "disabled" not in select.group(1)
    assert re.search(r'<option value="vmware_tools" selected', select.group(2))
    assert preserved is not None and "disabled" in preserved.group(0)

    _parser, values, _csrf = _guest_page_from_rendered_response(guest, page)

    assert values["time_source"] == ["vmware_tools"]


def test_server_apply_preserves_choice_from_rendered_select_html(client, monkeypatch):
    """Post the prior VMware choice read from the real selected option to server mode.

    Args:
        client: Application test client used to exercise the management UI.
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    guest = _load_guest_module()
    csrf = _save_vmware_choice(client, monkeypatch)
    page = client.get("/ui/management/ntp")
    _parser, _values, parsed_csrf = _guest_page_from_rendered_response(guest, page)
    assert parsed_csrf == csrf
    submitted = []
    monkeypatch.setattr(
        guest,
        "request",
        lambda _opener, path, **_kwargs: (
            page.status_code,
            page.url,
            page.headers,
            page.content,
        )
        if path == "/ntp"
        else (_ for _ in ()).throw(AssertionError("Unexpected guest HTTP request.")),
    )
    original_ntp_page = guest.ntp_page

    def ntp_page_with_site_interface(opener):
        """Expose the rendered form with one eligible site interface.

        Args:
            opener: Authenticated HTTP opener used for management UI requests.
        """
        parser, values, token = original_ntp_page(opener)
        parser.interfaces = ["eth1"]
        return parser, values, token

    monkeypatch.setattr(guest, "ntp_page", ntp_page_with_site_interface)
    monkeypatch.setattr(
        guest,
        "post_form",
        lambda _opener, _path, fields, **_kwargs: (
            submitted.extend(fields) or (200, "", {}, b'{"valid":true}')
        ),
    )
    monkeypatch.setattr(guest, "apply_unit", lambda *_args: "job")
    monkeypatch.setattr(
        guest, "wait_status", lambda *_args: {"mode": "ntp_server", "healthy": True}
    )

    outcome = guest.apply_mode(object(), "ntp_server", "eth1", "healthy")

    assert ("time_source", "vmware_tools") in submitted
    assert ("enabled", "on") in submitted
    assert outcome["remembered_time_source"] == "vmware_tools"


def test_rendered_ntp_page_omits_disabled_select_but_keeps_enabled_hidden_choice(
    client, monkeypatch
):
    """Disabled selects stay unsuccessful while their enabled mirror is submitted.

    Args:
        client: Application test client used to exercise the management UI.
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.

    """
    guest = _load_guest_module()
    csrf = _save_vmware_choice(client, monkeypatch)
    enabled = client.post(
        "/ui/management/ntp/settings",
        data={"enabled": "on", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert enabled.status_code == 200
    page = client.get("/ui/management/ntp")
    select = re.search(r'<select name="time_source"([^>]*)>', page.text)
    preserved = re.search(r'<input type="hidden" name="time_source"[^>]*>', page.text)
    assert select is not None and "disabled" in select.group(1)
    assert preserved is not None and "disabled" not in preserved.group(0)

    _parser, values, _csrf = _guest_page_from_rendered_response(guest, page)

    assert values["time_source"] == ["vmware_tools"]


@pytest.mark.parametrize("guard", [False, None])
def test_native_server_assertion_rejects_unverified_listener_isolation(guard):
    """Even synchronized NTP cannot pass native acceptance with unproven isolation.

    Args:
        guard: Observed packet-guard state used by the server isolation assertion.

    """
    guest = _load_guest_module()
    clock = {
        "mode": "ntp_server", "healthy": True,
        "controller": {"name": "ntpd", "active": True, "enabled": True},
        "conflicts": {}, "server_packet_guard": guard,
    }
    with pytest.raises(guest.SafeFailure):
        guest.assert_clock(clock, "ntp_server", "healthy")

    clock["server_packet_guard"] = True
    guest.assert_clock(clock, "ntp_server", "healthy")


@pytest.mark.parametrize("guard, expected", [({"active": True}, True), (None, None), ("invalid", None)])
def test_native_status_preserves_server_isolation_proof(monkeypatch, guard, expected):
    """Only structured helper proof can satisfy the server acceptance guard.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        guard: Observed packet-guard state used by the server isolation assertion.
        expected: Expected value used to validate the parsed status result.

    """
    guest = _load_guest_module()
    payload = {"status": {"mode": "ntp_server", "server_packet_guard": guard}}
    monkeypatch.setattr(guest, "request", lambda *_args, **_kwargs: (200, {}, "", json.dumps(payload)))

    clock = guest.status(object())

    assert clock["server_packet_guard"] is expected
