"""Rendered-form parsing regressions for native time-source acceptance."""

from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
from pathlib import Path

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


def _enable_vmware_capability(monkeypatch) -> None:
    """Render VMware Tools as a selectable saved source in the real NTP page."""
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_capabilities",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ntpd", "capabilities"],
            dry_run=False,
            stdout=json.dumps({"nts": True, "vmware_tools": True}),
        ),
    )


def _save_vmware_choice(client, monkeypatch):
    """Persist VMware Tools through the real autosave route before rendering."""
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
    """Make the guest parser consume the exact HTML returned by the app route."""
    def read_page(_opener, path, **_kwargs):
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
    """A reboot check reads local guest state before nginx is ready."""
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


def test_web_tls_initialization_retries_listener_recovery_within_deadline(monkeypatch):
    """Retry a transient closed listener, then trust the exact served leaf."""
    guest = _load_guest_module()
    clock = [0.0]
    attempts = []

    class FakeContext:
        verify_flags = 0
        check_hostname = True

    context = FakeContext()

    def get_certificate(address, *, timeout):
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
    """Stop retrying at the deadline without exposing transport error details."""
    guest = _load_guest_module()
    clock = [0.0]
    attempts = []
    monkeypatch.setattr(guest.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(guest.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))

    def refuse(_address, *, timeout):
        attempts.append(timeout)
        raise ConnectionRefusedError("private socket detail")

    monkeypatch.setattr(guest.ssl, "get_server_certificate", refuse)

    with pytest.raises(guest.SafeFailure) as error:
        guest.initialize_tls_context("192.168.100.2", timeout_seconds=2)

    assert len(attempts) == 2
    assert "private socket detail" not in error.value.reason
    assert error.value.stage == "https-listener"


def test_wait_status_host_budget_covers_web_listener_and_clock_recovery():
    """Leave bounded time for HTTPS recovery, login, and the guest's 90s poll."""
    assert host_acceptance._ACTION_TIMEOUTS["wait_status"] == 150


def test_rendered_ntp_page_keeps_source_when_select_is_enabled_and_hidden_copy_disabled(
    client, monkeypatch
):
    """Read the selected source from real HTML when the hidden mirror is disabled."""
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
    """Post the prior VMware choice read from the real selected option to server mode."""
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
    """Disabled selects stay unsuccessful while their enabled mirror is submitted."""
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
