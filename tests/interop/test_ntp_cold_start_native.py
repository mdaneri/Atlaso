"""Focused checks for NTP-only fixture desired state and native health readback."""

from __future__ import annotations

import hashlib
import html
import json
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_native as fixture  # noqa: E402 - Local interop entrypoint.

PEER = "192.168.77.1"
TEST_CANDIDATE = "192.168.77.11"
TOKEN = "synthetic-form-token-not-for-receipt"


def ntp_page(sources: list[dict[str, object]] | None = None) -> str:
    """Build a server-rendered NTP form with unrelated settings to preserve."""
    if sources is None:
        sources = [
            {"id": "disabled-ntp", "source": "192.0.2.44", "enabled": False,
             "use_nts": True, "description": "retained disabled row"},
            {"id": "old-peer", "source": PEER, "enabled": False,
             "use_nts": True, "description": "admitted peer metadata"},
        ]
    encoded_sources = html.escape(json.dumps(sources, separators=(",", ":")), quote=True)
    return (
        '<form id="ntp-settings-form" action="/ui/management/ntp/settings" method="post">'
        f'<input name="csrf" value="{TOKEN}">'
        '<input name="enabled" type="checkbox">'
        '<input name="nts_server_enabled" type="checkbox" checked>'
        '<input name="time_source" value="vmware_tools">'
        '<input name="listen_interfaces" value="eth2">'
        '<input name="listen_interfaces_present" value="1">'
        '<textarea name="upstream_servers">time.example.test</textarea>'
        f'<input name="upstream_sources_json" value="{encoded_sources}">'
        '<input form="ntp-settings-form" name="root_ssh_enabled" type="checkbox" checked>'
        '<input form="ntp-settings-form" name="external_dns_servers" value="192.0.2.53">'
        '</form>'
    )


class Client:
    """Record the one local form read and autosave without external I/O."""

    def __init__(self, body: str):
        self.body = body
        self.requests: list[str] = []
        self.submissions: list[tuple[str, list[tuple[str, str]], bool]] = []

    def request(self, path: str) -> tuple[int, str]:
        self.requests.append(path)
        return 200, self.body

    def json(self, path: str, fields: list[tuple[str, str]], *, autosave: bool) -> tuple[int, dict[str, bool]]:
        self.submissions.append((path, fields, autosave))
        return 200, {"valid": True}


@pytest.mark.parametrize(
    ("mode", "enabled", "server_interface"),
    [("ntp_client", "", None), ("ntp_server", "on", "eth1")],
    ids=["client-mode", "server-mode"],
)
def test_save_ntp_selects_only_the_exact_peer_and_preserves_existing_controls(
    mode: str, enabled: str, server_interface: str | None
) -> None:
    """NTP-only autosave retains unrelated fields and disabled source metadata."""
    client = Client(ntp_page())

    result = fixture.save_ntp(client, PEER, mode=mode)

    assert client.requests == ["/ui/management/ntp"]
    assert len(client.submissions) == 1
    action, submitted, autosave = client.submissions[0]
    fields = dict(submitted)
    assert action == "/ui/management/ntp/settings" and autosave is True
    assert fields["csrf"] == TOKEN
    assert fields["root_ssh_enabled"] == "on"
    assert fields["external_dns_servers"] == "192.0.2.53"
    assert fields["enabled"] == enabled
    assert fields["nts_server_enabled"] == ""
    assert fields["time_source"] == "ntp_client"
    assert fields["upstream_servers"] == PEER
    if server_interface is None:
        assert fields["listen_interfaces"] == "eth2"
    else:
        assert fields["listen_interfaces"] == server_interface
        assert fields["listen_interfaces_present"] == "1"
    rows = json.loads(fields["upstream_sources_json"])
    assert rows == [
        {"id": "disabled-ntp", "source": "192.0.2.44", "enabled": False,
         "use_nts": True, "description": "retained disabled row"},
        {"id": "old-peer", "source": PEER, "enabled": True,
         "use_nts": False, "description": "admitted peer metadata"},
    ]
    assert result == {"mode": mode, "source": PEER}


def test_save_ntp_adds_one_explicit_unreachable_private_test_candidate() -> None:
    """The negative candidate is added as one non-NTS source without enabling others."""
    client = Client(ntp_page([{
        "id": "factory-source", "source": "time.example.test", "enabled": True,
        "use_nts": True, "description": "existing factory row",
    }]))

    result = fixture.save_ntp(client, TEST_CANDIDATE)

    fields = dict(client.submissions[0][1])
    rows = json.loads(fields["upstream_sources_json"])
    assert rows == [
        {"id": "factory-source", "source": "time.example.test", "enabled": False,
         "use_nts": True, "description": "existing factory row"},
        {"id": "ntp-cold-start-peer", "source": TEST_CANDIDATE, "enabled": True,
         "use_nts": False, "description": "Isolated real NTP acceptance peer"},
    ]
    assert fields["upstream_servers"] == TEST_CANDIDATE
    assert result == {"mode": "ntp_client", "source": TEST_CANDIDATE}


@pytest.mark.parametrize(
    ("address", "mode"),
    [
        ("time.example.test", "ntp_client"),
        ("2001:db8::1", "ntp_client"),
        ("127.0.0.1", "ntp_client"),
        ("0.0.0.0", "ntp_client"),
        ("224.0.0.1", "ntp_client"),
        (PEER, "vmware_tools"),
    ],
    ids=["hostname", "ipv6", "loopback", "unspecified", "multicast", "unsupported-mode"],
)
def test_save_ntp_rejects_invalid_mode_or_non_unicast_address_before_form_read(address: str, mode: str) -> None:
    """Invalid endpoint or mode fails before reading or saving the UI form."""
    client = Client(ntp_page())

    with pytest.raises(fixture.Refusal):
        fixture.save_ntp(client, address, mode=mode)

    assert client.requests == []
    assert client.submissions == []


def native_status(**changes: object) -> dict[str, object]:
    """Return the sanitized helper fields plus deliberately raw diagnostic text."""
    payload: dict[str, object] = {
        "mode": "ntp_client",
        "synchronization": {"state": "synchronized", "healthy": True,
                            "detail": "raw-detail-must-not-return"},
        "selected_controller": {"name": "ntpd", "active": True, "enabled": True},
        "daemon_conflicts": {
            "chronyd": {"active": False, "enabled": False},
            "systemd_timesyncd": {"active": False, "enabled": False},
            "vmware_tools": {"active": False, "enabled": False},
        },
        "client_packet_guard": {"active": True},
        "server_packet_guard": {"active": True},
        "synchronization_evidence": {
            "healthy": True, "query": "ok", "leap": "leap_none", "source": "sync_ntp",
            "status": "0615", "stratum": 3,
            "selected": {"address": PEER, "stratum": "2", "reach": "377"},
        },
        "variables": {"stdout": "token=raw-native-diagnostic", "stderr": "raw-native-error"},
        "peers": {"stdout": "raw-peer-table", "stderr": "raw-peer-error"},
    }
    payload.update(changes)
    return payload


def fake_native_status(monkeypatch, payload: dict[str, object]) -> list[tuple[object, str, str]]:
    calls: list[tuple[object, str, str]] = []

    def sudo_read(session: object, command: str, password: str) -> str:
        calls.append((session, command, password))
        return json.dumps(payload)

    monkeypatch.setattr(fixture, "sudo_read", sudo_read)
    return calls


@pytest.mark.parametrize("mode", ["ntp_client", "ntp_server"], ids=["client", "server"])
def test_native_clock_requires_matching_synchronized_ntpd_and_returns_only_bounded_evidence(
    monkeypatch, mode: str
) -> None:
    """Health requires selected real peer, exclusive daemon, and mode packet guard."""
    payload = native_status(mode=mode)
    if mode == "ntp_client":
        payload["client_packet_guard"] = {"active": True}
    else:
        payload["server_packet_guard"] = {"active": True}
    session = object()
    password = "synthetic-test-credential"
    calls = fake_native_status(monkeypatch, payload)

    result = fixture.native_clock(session, password, PEER, mode=mode)

    assert calls == [(session, "/opt/atlaso/bin/atlaso-helper ntpd status --real", password)]
    assert result == {
        "mode": mode, "healthy": True, "leap": "leap_none", "source": "sync_ntp",
        "stratum": 3, "selected": {"address": PEER, "stratum": 2, "reach": "377"},
        "single_controller": True, "packet_guard": True,
    }
    serialized = json.dumps(result)
    for raw in ("raw-detail-must-not-return", "raw-native-diagnostic", "raw-native-error",
                "raw-peer-table", "raw-peer-error", password):
        assert raw not in serialized


@pytest.mark.parametrize(
    "defect",
    [
        "mode", "unhealthy", "query", "leap", "source", "stratum_zero", "stratum_high",
        "wrong_peer", "peer_stratum_zero", "peer_stratum_high", "zero_reach", "bad_reach",
        "controller_inactive", "controller_disabled", "conflict_active", "conflict_unknown",
        "missing_conflict", "guard_false", "guard_unknown",
    ],
)
def test_native_clock_refuses_unsynchronized_or_unproven_native_state(monkeypatch, defect: str) -> None:
    """Every native authority, selection, and packet-guard field must be proven."""
    payload = native_status()
    evidence = payload["synchronization_evidence"]
    controller = payload["selected_controller"]
    conflicts = payload["daemon_conflicts"]
    if defect == "mode":
        payload["mode"] = "vmware_tools"
    elif defect == "unhealthy":
        payload["synchronization"]["healthy"] = False
    elif defect == "query":
        evidence["query"] = "failed"
    elif defect == "leap":
        evidence["leap"] = "leap_alarm"
    elif defect == "source":
        evidence["source"] = "sync_unspec"
    elif defect == "stratum_zero":
        evidence["stratum"] = 0
    elif defect == "stratum_high":
        evidence["stratum"] = 16
    elif defect == "wrong_peer":
        evidence["selected"]["address"] = "192.168.77.10"
    elif defect == "peer_stratum_zero":
        evidence["selected"]["stratum"] = "0"
    elif defect == "peer_stratum_high":
        evidence["selected"]["stratum"] = "16"
    elif defect == "zero_reach":
        evidence["selected"]["reach"] = "0"
    elif defect == "bad_reach":
        evidence["selected"]["reach"] = "888"
    elif defect == "controller_inactive":
        controller["active"] = False
    elif defect == "controller_disabled":
        controller["enabled"] = False
    elif defect == "conflict_active":
        conflicts["chronyd"]["active"] = True
    elif defect == "conflict_unknown":
        conflicts["chronyd"]["enabled"] = None
    elif defect == "missing_conflict":
        del conflicts["chronyd"]
    elif defect == "guard_false":
        payload["client_packet_guard"]["active"] = False
    else:
        payload["client_packet_guard"]["active"] = None
    fake_native_status(monkeypatch, payload)

    with pytest.raises(fixture.Refusal, match="ntp_fixture_native_clock_unverified"):
        fixture.native_clock(object(), "synthetic-test-credential", PEER)


def orchestration_plan() -> dict[str, object]:
    """Return only the already admitted public fields consumed by run()."""
    return {
        "task_id": "test-task-ntp", "pr": 1121, "source_commit": "1" * 40,
        "appliance_ownership": {"path": "unused-test-ownership.json", "sha256": "6" * 64},
        "peer_transport": {"host": "192.168.77.1", "user": "alpine", "ssh_public_key": "ssh-ed25519 AAAA",
                           "ssh_host_key": "SHA256:peer", "private_subnet": "192.168.77.0/24"},
        "current_address": "192.168.77.10", "baseline_address": "192.168.77.30",
        "static_candidate_address": "192.168.77.40", "negative_address": TEST_CANDIDATE,
        "peer_address": PEER, "appliance_user": "admin", "appliance_ssh_host_key": "SHA256:appliance",
        "username": "admin", "ca_path": "unused-test-ca.pem",
        "ca_sha256": hashlib.sha256(b"synthetic-ca-placeholder").hexdigest(),
        "trusted_host": {"appliance_service_mac": "00:50:56:00:00:02"},
    }


class FakeTransport:
    """Context-managed peer transport placeholder with no network access."""

    topology_guard = None

    def __init__(self, *args: object):
        self.args = args

    def __enter__(self) -> "FakeTransport":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class FakeApplianceSession:
    """Context-managed appliance transport placeholder with no SSH access."""

    def __init__(self, *_args: object):
        pass

    def __enter__(self) -> "FakeApplianceSession":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def command(self, _command: str) -> bytes:
        return b"synthetic-ca-placeholder"


class FakeRunClient:
    """Minimal authenticated client fake used by the orchestration seam."""

    def __init__(self, *_args: object, **_kwargs: object):
        self.login_calls: list[tuple[object, object]] = []

    def login(self, username: object, password: object) -> None:
        self.login_calls.append((username, password))

    def tls_identity(self) -> dict[str, str]:
        return {"fingerprint": "sha256:stable-test-tls"}

    def interface(self, name: str) -> tuple[dict[str, str], dict[str, str]]:
        assert name == "eth0"
        return {"role": "management", "ipv4_method": "dhcp", "mac": "00:50:56:00:00:01"}, {}


@pytest.fixture
def fake_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, object]:
    """Replace every network/native boundary while retaining real orchestration journals."""
    calls: dict[str, object] = {"submissions": [], "waits": [], "desired": [], "native_modes": [],
                               "packets": [], "applied": [], "initial": "unmanaged",
                               "output_root": tmp_path.resolve()}

    @contextmanager
    def watch(_plan: dict):
        yield {"sha256": "3" * 64}, lambda: None

    monkeypatch.setattr(fixture, "admit_plan", lambda _plan: {})
    monkeypatch.setattr(fixture, "bound_json", lambda _reference: {"lab_root": str(calls["output_root"])})
    monkeypatch.setattr(fixture, "watched_topology", watch)
    monkeypatch.setattr(fixture, "PinnedPeerTransport", FakeTransport)
    monkeypatch.setattr(fixture, "PinnedApplianceSession", FakeApplianceSession)
    monkeypatch.setattr(fixture, "verify_peer_isolation", lambda _peer: {"isolated": True})
    monkeypatch.setattr(fixture, "verify_peer_tunnel_scope", lambda _peer, _addresses: {"scope": "fixed"})
    monkeypatch.setattr(fixture, "verify_peer_time", lambda *_args: {"synchronized": True})
    monkeypatch.setattr(fixture, "payload_identity", lambda *_args: {"payload_verified": True})
    monkeypatch.setattr(fixture, "tls_name", lambda *_args: "appliance.fixture.test")
    monkeypatch.setattr(fixture, "Client", FakeRunClient)
    baseline = {"role": "management", "ipv4_method": "dhcp", "mac": "00:50:56:00:00:01"}
    def prepare(_client: object, _plan: object) -> dict[str, str]:
        fixture.save_ntp(_client, PEER)
        return dict(baseline)

    monkeypatch.setattr(fixture, "prepare_baseline", prepare)
    monkeypatch.setattr(fixture, "saved_fields", lambda fields: dict(fields))
    monkeypatch.setattr(fixture, "clean_baseline", lambda _client: None)
    monkeypatch.setattr(fixture, "save_ntp", lambda _client, address, mode="ntp_client":
                        calls["desired"].append((address, mode)))
    monkeypatch.setattr(fixture, "native_clock", lambda _session, _password, _peer, mode="ntp_client":
                        calls["native_modes"].append(mode) or {"mode": mode, "healthy": True})
    monkeypatch.setattr(fixture, "packet_probe", lambda _session, _peer, _password, target, source, *, response_expected:
                        calls["packets"].append((target, source, response_expected)) or
                        {"target": target, "response_received": response_expected})
    monkeypatch.setattr(fixture, "journal_checkpoint", lambda *_args: {"checkpoint": "before-negative"})
    monkeypatch.setattr(fixture, "acquisition_failure", lambda *_args: {"failed": True, "recovered": True})
    prior = {"sha256": "4" * 64, "transaction_phase": "verified"}
    restored = {"sha256": "4" * 64, "transaction_phase": "verified"}
    calls["applied_values"] = [prior, restored]
    monkeypatch.setattr(fixture, "applied_config", lambda _session, _password:
                        calls["applied"].append(True) or calls["applied_values"].pop(0))

    def sudo_read(_session: object, command: str, _password: str) -> str:
        if "ntpd status" in command:
            assert command == "/opt/atlaso/bin/atlaso-helper ntpd status --real"
            conflicts = {
                name: {"active": False, "enabled": False}
                for name in ("ntpd", "chronyd", "systemd_timesyncd", "vmware_tools")
            }
            if calls["initial"] == "unknown_controller":
                conflicts["ntpd"]["active"] = None
            mode = "unmanaged" if calls["initial"] == "unknown_controller" else calls["initial"]
            return json.dumps({"mode": mode,
                               "selected_controller": {"active": calls["initial"] == "active"},
                               "daemon_conflicts": conflicts})
        return json.dumps({"state": "proven-absent"})

    monkeypatch.setattr(fixture, "sudo_read", sudo_read)
    calls.setdefault("statuses", ["succeeded", "succeeded", "failed"])

    def submit(_client: object) -> tuple[str, str]:
        submissions = calls["submissions"]
        index = len(submissions) + 1
        job = f"job-{index}"
        submissions.append(job)
        return job, f"/tasks/{job}/status"

    def wait(_clients: list[object], _path: str, _username: str, _password: str) -> tuple[dict[str, str], object]:
        waits = calls["waits"]
        index = len(waits)
        waits.append(index)
        return {"status": calls["statuses"][index]}, object()

    monkeypatch.setattr(fixture, "submit_initialization", submit)
    monkeypatch.setattr(fixture, "wait_task", wait)
    return calls


def test_run_executes_three_apply_phases_and_publishes_immutable_journals(
    tmp_path: Path, fake_run: dict[str, object],
) -> None:
    """Cold, server, and failed candidate each submit once and retain terminal evidence."""
    result = fixture.run(orchestration_plan(), tmp_path, "synthetic-test-credential")

    assert result["success"] is True
    assert result["cold_initial_state"]["clock_controllers_inactive"] is True
    assert fake_run["submissions"] == ["job-1", "job-2", "job-3"]
    assert fake_run["waits"] == [0, 1, 2]
    assert fake_run["desired"] == [(PEER, "ntp_client"), (PEER, "ntp_server"),
                                  (TEST_CANDIDATE, "ntp_server")]
    for name, status in (("cold", "succeeded"), ("server", "succeeded"), ("negative", "failed")):
        stem = f"ntp-native-{name}"
        assert json.loads((tmp_path / f"{stem}-submission-intent.json").read_text())["no_resubmission"] is True
        assert json.loads((tmp_path / f"{stem}-submitted.json").read_text())["job_id"].startswith("job-")
        assert json.loads((tmp_path / f"{stem}-terminal.json").read_text())["status"] == status
    assert result["negative_candidate"]["prior_configuration_restored"] is True
    assert json.loads((tmp_path / "ntp-native-result.json").read_text())["success"] is True


def test_run_does_not_retry_a_failed_cold_apply(tmp_path: Path, fake_run: dict[str, object]) -> None:
    fake_run["statuses"] = ["failed", "succeeded", "failed"]

    with pytest.raises(fixture.Refusal, match="ntp_fixture_acceptance_failed_preserve_and_reconcile"):
        fixture.run(orchestration_plan(), tmp_path, "synthetic-test-credential")

    assert fake_run["submissions"] == ["job-1"]
    result = json.loads((tmp_path / "ntp-native-result.json").read_text())
    assert result["stage"] == "cold_apply" and result["success"] is False
    assert (tmp_path / "ntp-native-cold-terminal.json").exists()
    assert not (tmp_path / "ntp-native-server-submission-intent.json").exists()


def test_first_global_apply_can_publish_its_applied_tls_leaf(tmp_path, fake_run, monkeypatch):
    """Setup may publish a leaf; later NTP-only transitions must preserve it."""
    leaves = iter([{"fingerprint": "bootstrap"}, {"fingerprint": "applied"}, {"fingerprint": "applied"}])
    monkeypatch.setattr(FakeRunClient, "tls_identity", lambda _: next(leaves))
    result = fixture.run(orchestration_plan(), tmp_path, "synthetic-test-credential")
    assert result["success"] is True
    assert result["original_tls"] != result["baseline_tls"] == result["final_tls"]


def test_ntp_only_tls_identity_drift_refuses_acceptance(tmp_path, fake_run, monkeypatch):
    """The acceptance result cannot hide a later unexpected leaf replacement."""
    leaves = iter([{"fingerprint": "bootstrap"}, {"fingerprint": "applied"}, {"fingerprint": "changed"}])
    monkeypatch.setattr(FakeRunClient, "tls_identity", lambda _: next(leaves))
    with pytest.raises(fixture.Refusal, match="preserve_and_reconcile"):
        fixture.run(orchestration_plan(), tmp_path, "synthetic-test-credential")
    assert json.loads((tmp_path / "ntp-native-result.json").read_text())["success"] is False


def test_root_ssh_and_web_authentication_use_distinct_credentials(tmp_path, fake_run, monkeypatch):
    """Root native reads use the root value while web Apply keeps administrator auth."""
    plan = orchestration_plan()
    plan["appliance_user"] = "root"
    web = "synthetic-web-credential"
    root = "synthetic-root-credential"
    authenticated = []
    logins = []

    class RootSession(FakeApplianceSession):
        def __init__(self, *args):
            authenticated.append((args[2], args[3]))

    original_read = fixture.sudo_read

    def read(session, command, password):
        assert password == root
        return original_read(session, command, password)

    monkeypatch.setattr(fixture, "PinnedApplianceSession", RootSession)
    monkeypatch.setattr(fixture, "sudo_read", read)
    monkeypatch.setattr(FakeRunClient, "login", lambda _, username, password: logins.append((username, password)))
    result = fixture.run(plan, tmp_path, web, appliance_password=root)
    assert result["success"] is True
    assert authenticated == [("root", root)] and logins == [("admin", web)]
    assert root not in json.dumps(result) and web not in json.dumps(result)


def test_run_unknown_wait_preserves_submission_without_terminal_or_resubmission(
    tmp_path: Path, fake_run: dict[str, object], monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "synthetic-password-and-native-stderr-must-not-leak"

    def unknown_wait(*_args: object) -> tuple[dict[str, str], object]:
        raise RuntimeError(secret)

    monkeypatch.setattr(fixture, "wait_task", unknown_wait)
    with pytest.raises(fixture.Refusal, match="ntp_fixture_acceptance_failed_preserve_and_reconcile"):
        fixture.run(orchestration_plan(), tmp_path, secret)

    assert fake_run["submissions"] == ["job-1"]
    result_path = tmp_path / "ntp-native-result.json"
    result = result_path.read_text()
    assert secret not in result
    assert json.loads(result)["stage"] == "cold_apply"
    assert (tmp_path / "ntp-native-cold-submitted.json").exists()
    assert not (tmp_path / "ntp-native-cold-terminal.json").exists()


def test_run_wrong_rollback_digest_never_claims_verified_restoration(
    tmp_path: Path, fake_run: dict[str, object],
) -> None:
    fake_run["applied_values"] = [
        {"sha256": "4" * 64, "transaction_phase": "verified"},
        {"sha256": "5" * 64, "transaction_phase": "verified"},
    ]

    with pytest.raises(fixture.Refusal, match="ntp_fixture_acceptance_failed_preserve_and_reconcile"):
        fixture.run(orchestration_plan(), tmp_path, "synthetic-test-credential")

    result = json.loads((tmp_path / "ntp-native-result.json").read_text())
    assert result["stage"] == "negative_candidate" and result["success"] is False
    assert "prior_configuration_restored" not in result


def test_run_refuses_an_existing_attempt_without_overwriting_it(
    tmp_path: Path, fake_run: dict[str, object],
) -> None:
    prior = tmp_path / "ntp-native-started.json"
    prior.write_text('{"original":"keep"}\n')
    before = prior.read_bytes()

    with pytest.raises(fixture.Refusal, match="ntp_fixture_prior_attempt_requires_reconciliation"):
        fixture.run(orchestration_plan(), tmp_path, "synthetic-test-credential")

    assert prior.read_bytes() == before
    assert fake_run["submissions"] == []


def test_run_refuses_a_result_root_outside_original_ownership(
    tmp_path: Path, fake_run: dict[str, object],
) -> None:
    """The journal namespace must resolve to the originally receipted lab root."""
    wrong_root = tmp_path / "other-output-root"

    with pytest.raises(fixture.Refusal, match="ntp_fixture_output_original_ownership_mismatch"):
        fixture.run(orchestration_plan(), wrong_root, "synthetic-test-credential")

    assert fake_run["submissions"] == []
    assert not wrong_root.exists()


@pytest.mark.parametrize("initial", ["active", "unknown_controller"], ids=["active", "unknown-state"])
def test_run_refuses_an_active_or_unknown_initial_controller_before_any_apply(
    tmp_path: Path, fake_run: dict[str, object], initial: str,
) -> None:
    fake_run["initial"] = initial

    with pytest.raises(fixture.Refusal, match="ntp_fixture_acceptance_failed_preserve_and_reconcile"):
        fixture.run(orchestration_plan(), tmp_path, "synthetic-test-credential")

    assert fake_run["submissions"] == []
    assert not (tmp_path / "ntp-native-cold-submission-intent.json").exists()
    result = json.loads((tmp_path / "ntp-native-result.json").read_text())
    assert result["stage"] == "admitted" and result["success"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "certificate-native-plan"),
        ("task_id", ""),
        ("repository", "other/repository"),
        ("pr", True),
        ("source_commit", "not-a-commit"),
        ("resource_source_commit", "2" * 40),
    ],
)
def test_admit_plan_rejects_malformed_identity_before_receipt_access(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object,
) -> None:
    """Reject incompatible source/task identity before opening any receipt."""
    plan = {
        "schema": 1, "kind": "ntp-cold-start-native-plan", "trust_model": "trusted-host", "task_id": "test-task-ntp",
        "repository": "mdaneri/Atlaso", "pr": 1121, "source_commit": "1" * 40,
        "resource_source_commit": "1" * 40,
    }
    plan[field] = value
    monkeypatch.setattr(fixture, "bound_json", lambda _reference: pytest.fail("receipt opened before identity admission"))

    with pytest.raises(fixture.Refusal, match="ntp_fixture_plan_invalid"):
        fixture.admit_plan(plan)
