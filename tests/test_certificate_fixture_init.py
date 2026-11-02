"""Focused safety checks for first-run ISO fixture initialization."""

from __future__ import annotations

import hashlib
import html
import json
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_fixture_init as init  # noqa: E402 - Local interop entrypoint.

PEER = "192.168.77.1"
MAC = "00:50:56:aa:bb:cc"
CA = b"public-test-certificate"
TOKEN = "synthetic-csrf-token-must-not-be-recorded"


def page(name: str) -> str:
    """Create ordinary server-form fixtures, including unrelated controls.

    Args:
        name: Settings page whose one target form should be parsed.
    """
    action = {"dns": "dns/settings", "settings": "settings", "ntp": "ntp/settings"}[name]
    content = {
        "dns": '<input name="enabled" type="checkbox" checked><textarea name="upstream_servers"></textarea><input name="cache_size" value="1000">',
        "settings": '<input name="management_https_enabled" type="checkbox" checked><input name="root_ssh_enabled" type="checkbox" checked><input name="fqdn" value="core.example.test"><textarea name="external_dns_servers"></textarea>',
        "ntp": '<input name="enabled" type="checkbox" checked><input name="time_source" value="ntp_client"><input name="nts_server_key_path" value="opaque-private-selector"><input name="upstream_sources_json" value="' + html.escape(json.dumps([
            {"source": "time.example.test", "enabled": True, "use_nts": True, "description": "original"},
        ]), quote=True) + '">',
    }[name]
    return ('<form action="/unrelated" method="post"><input name="other" value="ignored"></form>'
            f'<form action="/ui/management/{action}" method="post"><input name="csrf" value="{TOKEN}">{content}</form>')


class FormsClient:
    def request(self, path: str):
        """Return only the requested synthetic server page.

        Args:
            path: Normal management page path.
        """
        return 200, page(path.rsplit("/", 1)[-1])


def test_preparation_preserves_other_controls_and_records_no_tokens():
    """Initialize isolated client prerequisites while preserving unrelated fields."""
    forms, public = init.prepare_forms(FormsClient(), PEER)
    settings = dict(forms["settings"][1])
    assert settings["root_ssh_enabled"] == "on" and settings["fqdn"] == "core.example.test"
    assert settings["external_dns_servers"] == PEER
    dns = dict(forms["dns"][1])
    assert dns["enabled"] == "" and dns["upstream_servers"] == PEER and dns["cache_size"] == "1000"
    ntp = dict(forms["ntp"][1])
    assert ntp["enabled"] == "" and ntp["nts_server_enabled"] == "" and ntp["time_source"] == "ntp_client"
    sources = json.loads(ntp["upstream_sources_json"])
    assert sources[0]["enabled"] is False and sources[0]["use_nts"] is True
    assert sources[0]["description"] == "original"
    assert [row["source"] for row in sources if row["enabled"]] == [PEER]
    assert sources[-1]["use_nts"] is False
    assert TOKEN not in json.dumps(public) and "opaque-private-selector" not in json.dumps(public)
    assert ntp["nts_server_key_path"] == "opaque-private-selector"


@pytest.mark.parametrize("body", [
    '<form action="/other" method="post"></form>',
    '<form action="/target" method="get"></form>',
    '<form action="/target" method="post"><input name="csrf" value="x"><input type="password" name="secret"></form>',
    '<form action="/target" method="post"><input name="csrf" value="x"></form>' * 2,
])
def test_form_selection_refuses_ambiguous_or_secret_controls(body):
    """Never submit an unrelated or ambiguous form.

    Args:
        body: Invalid synthetic settings form.
    """
    with pytest.raises(init.Refusal):
        init.FixtureForm(body, "/target")


@pytest.mark.parametrize("review", [
    {"active_task": {"id": "other"}, "units": []},
    {"units": [{"id": "ldap", "changed": True}]},
    {"units": [{"id": "wan", "changed": True}]},
    {"units": []},
])
def test_initialization_rejects_foreign_pending_work(review):
    """Initialization does not absorb unrelated desired-state work.

    Args:
        review: Review whose scope cannot be admitted.
    """
    with pytest.raises(init.Refusal):
        init.validate_review(review)


@pytest.mark.parametrize("extra", [None, "wan", "ldap"])
def test_apply_uses_only_the_reviewed_roots_and_safe_required_closure(extra):
    """Respect server-owned selection while refusing an unexpected dependency.

    Args:
        extra: Additional required dependency returned by the server.
    """
    submissions = []

    class Client:
        def request(self, _path):
            """Return a current form token.

            Args:
                _path: Physical interface page requested for the current token.
            """
            return 200, '<input name="csrf" value="x">'

        def json(self, path, form=None):
            """Model selection-specific review and its one submission.

            Args:
                path: Review or submission path.
                form: Explicit reviewed consent fields, when submitting.
            """
            if form is not None:
                submissions.append(form)
                return 202, {"job_id": "job-test", "status_url": "/tasks/job-test/status"}
            rows = [{"id": unit, "selected": True, "valid": True, "changed": unit == "ntpd"} for unit in init.ROOTS]
            if "?" in path and extra:
                rows.append({"id": extra, "selected": True, "valid": True, "changed": False})
            return 200, {"units": rows, "requested_units": sorted(init.ROOTS), "plan_token": "test-token"}

    if extra == "ldap":
        with pytest.raises(init.Refusal, match="scope_changed"):
            init.submit_initialization(Client())
        assert not submissions
    else:
        assert init.submit_initialization(Client()) == ("job-test", "/tasks/job-test/status")
        assert len(submissions) == 1 and set(submissions[0]["requested_units"]) == init.ROOTS
        assert submissions[0]["reviewed_plan"] == "test-token"


@pytest.mark.parametrize("scenario", ["unknown", "success", "late_monitor_failure", "state_changed"])
def test_initialization_transitions_are_journaled_and_never_resubmitted(tmp_path, monkeypatch, scenario):
    """Complete initialization or retain a truthful failure without another Apply.

    Args:
        tmp_path: Pytest-owned output directory.
        monkeypatch: Fake pinned transports and native observations.
        scenario: Successful or failed transition to exercise.
    """
    plan = {"task_id": "task", "source_commit": "a" * 40, "appliance_user": "admin",
            "current_address": "192.168.77.10", "baseline_address": "192.168.77.30", "static_candidate_address": "192.168.77.40",
            "appliance_ssh_host_key": "original-pin", "ca_path": "public-ca", "ca_sha256": hashlib.sha256(CA).hexdigest(),
            "fixture_initialization": {"peer_time_address": PEER},
            "peer_transport": {"host": "192.0.2.1", "user": "alpine", "ssh_public_key": "public-key",
                               "ssh_host_key": "peer-pin", "private_subnet": "192.168.77.0/24"}}
    fixture = {"appliance_mac": MAC}
    monkeypatch.setattr(init, "admit_initialization", lambda *args: (fixture, PEER))
    monkeypatch.setattr(init, "inspect_trusted_host", lambda _plan: {})

    executing = False

    @contextmanager
    def monitor(*args):
        """Keep the fake topology fixed throughout this unit scenario.

        Args:
            *args: Admitted plan and initial snapshot.
        """
        yield SimpleNamespace(check=lambda: None)
        if executing and scenario == "late_monitor_failure":
            raise RuntimeError("synthetic-private-monitor-error")

    class Session:
        def __init__(self, *args):
            """Accept fake pinned transport arguments.

            Args:
                *args: Original admitted connection selectors.
            """
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            """Close the fake session without native activity.

            Args:
                *args: Context-manager exception information.
            """
            pass

        def command(self, command):
            """Return only allowlisted fake public facts.

            Args:
                command: Fixed readback command selected by initialization.
            """
            if command == "cat /var/lib/misc/dnsmasq.leases":
                return f"{int(time.time())+1000} {MAC} 192.168.77.10 appliance *\n".encode()
            if "ntpq -pn" in command:
                return ("*" + PEER + " 192.0.2.8 3 u 1 64 377 0.1 0.1 0.1\n").encode()
            return MAC.encode() if command.endswith("/eth0/address") else CA

    calls = []
    original = {key: "" for key in init.saved_fields.__globals__["FIELDS"]}
    original.update(role="management", ipv4_method="dhcp", ipv6_enabled=False)

    class Client(FormsClient):
        def __init__(self, *args, **kwargs):
            """Accept the fake HTTPS client's pinned connection options.

            Args:
                *args: Positional HTTPS origin and CA arguments.
                **kwargs: Peer transport and exact target address.
            """
            pass

        def login(self, *args):
            """Accept the synthetic test-only login.

            Args:
                *args: Synthetic account and concealed credential.
            """
            pass

        def json(self, path, form=None):
            """Return scoped review or record a normal desired-form edit.

            Args:
                path: Fixed management endpoint.
                form: Browser form fields, when editing desired state.
            """
            if form is not None:
                calls.append(path)
                return 200, {"valid": True}
            return 200, {"units": [{"id": "ntpd", "changed": True}]}

        def interface(self, _name):
            """Return the original management interface unchanged.

            Args:
                _name: Management interface requested by the caller.
            """
            return dict(original), TOKEN

        def tls_identity(self):
            return {"sha256": "b" * 64, "ip_sans": []}

    monkeypatch.setattr(init, "watched_topology", monitor)
    monkeypatch.setattr(init, "PinnedPeerTransport", Session)
    monkeypatch.setattr(init, "PinnedApplianceSession", Session)
    monkeypatch.setattr(init, "verify_peer_isolation", lambda _peer: {})
    monkeypatch.setattr(init, "verify_peer_tunnel_scope", lambda *args: {})
    monkeypatch.setattr(init, "verify_peer_time", lambda *args: {"configuration_sha256": "c" * 64})
    monkeypatch.setattr(init, "guest_identity", lambda *args: {"source": "public", "route_snapshot": {"route_count": 0}})
    monkeypatch.setattr(init, "tls_name", lambda *args: "core.example.test")
    monkeypatch.setattr(init, "Client", Client)

    def uncertain(_client):
        """Model loss of the response after a possible Apply submission.

        Args:
            _client: Authenticated test-only client.
        """
        calls.append("submit")
        if scenario == "unknown":
            raise OSError("synthetic-private-response")
        return "fixture-job", "/tasks/fixture-job/status"

    monkeypatch.setattr(init, "submit_initialization", uncertain)
    secret = "synthetic-admin-secret"
    inspected = init.initialize(plan, tmp_path, secret, execute=False)
    assert inspected["success"] is True and not calls
    receipt = tmp_path / "fixture-initialization-inspection.json"
    plan["fixture_initialization_inspection"] = {"path": str(receipt), "sha256": hashlib.sha256(receipt.read_bytes()).hexdigest()}
    monkeypatch.setattr(init, "wait_task", lambda *args: ({"status": "succeeded"}, None))
    monkeypatch.setattr(init, "clean_baseline", lambda *args: None)
    monkeypatch.setattr(init, "dns_baseline", lambda *args: {"external_dns_servers": [PEER], "upstream_servers": [PEER]})
    monkeypatch.setattr(init, "wait_clock", lambda *args: {"mode": "ntp_client", "healthy": True})
    monkeypatch.setattr(init, "sudo_read", lambda *args: ("*" + PEER + " 192.0.2.8 3 u 1 64 377 0.1 0.1 0.1\n").encode())
    executing = True
    if scenario == "state_changed":
        monkeypatch.setattr(init, "guest_identity", lambda *args: {"source": "different"})
    if scenario == "success":
        assert init.initialize(plan, tmp_path, secret, execute=True)["success"] is True
    else:
        expected = {"unknown": OSError, "late_monitor_failure": RuntimeError, "state_changed": init.Refusal}[scenario]
        with pytest.raises(expected):
            init.initialize(plan, tmp_path, secret, execute=True)
    result = json.loads((tmp_path / "fixture-initialization-result.json").read_text())
    if scenario == "state_changed":
        assert calls == [] and not (tmp_path / "fixture-mutation-started.json").exists()
        assert result["success"] is False and result["recovery"] == "no_desired_mutation_started"
        return
    assert calls == ["/ui/management/dns/settings", "/ui/management/settings", "/ui/management/ntp/settings", "submit"]
    assert result["success"] is (scenario == "success")
    if scenario == "unknown":
        assert result["recovery"] == "preserve_unknown_apply_do_not_resubmit"
    elif scenario == "late_monitor_failure":
        assert result["recovery"] == "preserve_and_reconcile"
    assert (tmp_path / "fixture-mutation-started.json").is_file()
    with pytest.raises(init.Refusal, match="prior_execution_requires_reconciliation"):
        init.initialize(plan, tmp_path, secret, execute=True)
    assert calls.count("submit") == 1
    for path in tmp_path.glob("*.json"):
        text = path.read_text()
        assert all(value not in text for value in (TOKEN, secret, "synthetic-private-response", "opaque-private-selector"))
