"""Ensure certificate inspection refuses mutable peer evidence before authentication."""

from __future__ import annotations

import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from atlaso.app.ui_routes import is_protocol_path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
import certificate_handoff_native as handoff  # noqa: E402 - Local interop import after path setup.


@pytest.mark.parametrize("case", ["excluded", "covered", "wrong_ca"])
def test_public_leaf_download_uses_protocol_route_and_real_chain_ip_checks(tmp_path, case):
    """Exercise protocol ownership and actual OpenSSL verification using public fixtures.

    Args:
        tmp_path: Owned directory containing public certificates only.
        case: Expected uncovered address, covered address, or wrong trust anchor.
    """
    openssl = shutil.which("openssl")
    packaged = Path("C:/Program Files/Git/usr/bin/openssl.exe")
    if openssl is None and packaged.is_file():
        openssl = str(packaged)
    if openssl is None:
        pytest.skip("OpenSSL is required for real public-certificate validation")
    now = datetime.now(UTC)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture CA")])
    root_key = ec.generate_private_key(ec.SECP256R1())

    def root_certificate(key):
        """Return a short-lived public CA while its fixture key stays in memory.

        Args:
            key: In-memory test signing key, never serialized.
        """
        return (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))

    root = root_certificate(root_key)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "certificate-lab.test")]))
            .issuer_name(root_name).public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("192.0.2.30"))]), critical=False)
            .sign(root_key, hashes.SHA256()))
    ca = tmp_path / "public-ca.pem"
    if case == "wrong_ca":
        root = root_certificate(ec.generate_private_key(ec.SECP256R1()))
    ca.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    pem = leaf.public_bytes(serialization.Encoding.PEM).decode("ascii")
    paths = []

    def download(path):
        """Enforce the application's real protocol-plane ownership rule.

        Args:
            path: Authenticated public-leaf download request.
        """
        assert is_protocol_path(path)
        assert not path.startswith("/ui/")
        paths.append(path)
        return 200, pem

    address = "192.0.2.30" if case == "covered" else "192.0.2.10"
    arguments = (SimpleNamespace(request=download), 7, address, str(ca), tmp_path / "public-leaf.pem", openssl)
    if case == "excluded":
        assert handoff.public_certificate_excludes(*arguments) == leaf.fingerprint(hashes.SHA256()).hex()
    else:
        reason = "desired_certificate_chain_invalid" if case == "wrong_ca" else "desired_certificate_covers_negative_address"
        with pytest.raises(handoff.Refusal, match=reason):
            handoff.public_certificate_excludes(*arguments)
    assert paths == ["/certificate-authority/certificates/7/downloads/certificate.pem"]


@pytest.mark.parametrize("during_login", [False, True])
def test_task_polling_follows_candidate_after_old_peer_channel_retires(during_login):
    """A cutover must continue on its declared candidate without another submission.

    Args:
        during_login: Whether retirement happens during an ordinary session refresh.
    """
    calls = []
    task = {"id": "job_123456789abc", "type": "appliance-apply", "status": "succeeded"}

    class Retired:
        def json(self, _path):
            """Model the retired original socket or an expired HTTP session.

            Args:
                _path: The already submitted task's status path.
            """
            calls.append("old-status")
            if during_login:
                raise handoff.Refusal("http_401")
            raise handoff.PeerTransportRefusal("peer_private_channel_refused")

        def login(self, *_args):
            """Model retirement during a session refresh, never a new Apply.

            Args:
                *_args: Synthetic login values kept within this test.
            """
            assert during_login
            calls.append("old-login")
            raise handoff.PeerTransportRefusal("peer_private_channel_refused")

    candidate = SimpleNamespace(json=lambda _path: (200, {"task": task}))
    observed, origin = handoff.wait_task([Retired(), candidate], "/tasks/job_123456789abc/status", "fixture", "synthetic")
    assert observed == task and origin is candidate
    assert calls == ["old-status", *(["old-login"] if during_login else [])]


@pytest.mark.parametrize("reason", ["peer_transport_inactive", "target_outside_owned_private_subnet", "peer_host_key_changed"])
@pytest.mark.parametrize("during_login", [False, True])
def test_task_polling_does_not_hide_peer_trust_or_scope_refusals(reason, during_login):
    """Only an individual private-channel refusal permits origin failover.

    Args:
        reason: Fatal peer admission or lifetime failure.
        during_login: Whether the failure occurs while refreshing the HTTP session.
    """
    def status(_path):
        """Raise the selected refusal before any candidate can be trusted.

        Args:
            _path: Submitted task's status URL.
        """
        if during_login:
            raise handoff.Refusal("http_401")
        raise handoff.PeerTransportRefusal(reason)

    def login(*_args):
        """Raise the same fatal condition during reauthentication.

        Args:
            *_args: Unused synthetic login inputs.
        """
        raise handoff.PeerTransportRefusal(reason)

    candidate = SimpleNamespace(json=lambda _path: pytest.fail("candidate reached after fatal peer refusal"))
    with pytest.raises(handoff.PeerTransportRefusal, match=reason):
        handoff.wait_task([SimpleNamespace(json=status, login=login), candidate], "/tasks/job_123456789abc/status", "fixture", "synthetic")


def test_task_polling_keeps_deadline_when_all_admitted_origins_are_closed(monkeypatch):
    """Unavailable origins never authorize an indefinite wait or resubmission.

    Args:
        monkeypatch: Control only the deadline clock and sleeping.
    """
    times = iter([0, 0, 301])
    monkeypatch.setattr(handoff.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(handoff.time, "sleep", lambda _seconds: None)

    def status(_path):
        """Report a closed origin while retaining the exact original task.

        Args:
            _path: Submitted task status URL.
        """
        raise handoff.PeerTransportRefusal("peer_private_channel_refused")

    with pytest.raises(handoff.Refusal, match="task_timeout_do_not_resubmit"):
        handoff.wait_task([SimpleNamespace(json=status), SimpleNamespace(json=status)], "/tasks/job_123456789abc/status", "fixture", "synthetic")


@pytest.mark.parametrize("reason", ["peer_private_channel_refused", "peer_transport_inactive", "target_outside_owned_private_subnet"])
def test_restoration_uses_declared_live_origin_only_for_closed_channel(monkeypatch, reason):
    """Restoration can start at the candidate after the original address retires.

    Args:
        monkeypatch: Stop at the first desired-state edit to isolate origin choice.
        reason: Expected channel refusal or a fatal transport/scope failure.
    """
    class ReachedEditor(Exception):
        pass

    calls = []

    def unavailable(*_args):
        """Model the original origin's login outcome.

        Args:
            *_args: Synthetic credentials, never logged.
        """
        raise handoff.PeerTransportRefusal(reason)

    candidate = SimpleNamespace(login=lambda *_args: calls.append("candidate-login"))

    def edit(client, *_args):
        """Prove the editor receives only the admitted live candidate.

        Args:
            client: Selected client for restoration.
            *_args: Original desired fields and identity inputs.
        """
        assert client is candidate
        calls.append("edit")
        raise ReachedEditor()

    monkeypatch.setattr(handoff, "edit", edit)
    expected = ReachedEditor if reason == "peer_private_channel_refused" else handoff.PeerTransportRefusal
    with pytest.raises(expected):
        handoff.restore_original([SimpleNamespace(login=unavailable), candidate], {"interface": "eth0", "mac": "fixture"}, {}, {}, "fixture", "synthetic", {})
    assert calls == (["candidate-login", "edit"] if reason == "peer_private_channel_refused" else [])


@pytest.mark.parametrize(("include_dns", "dns_changed", "other_changed", "refused"), [
    (True, True, None, False),
    (True, False, None, False),
    (False, True, None, True),
    (True, True, "ntpd", True),
])
def test_interface_handoff_reviews_generated_dns_without_absorbing_other_work(
    include_dns, dns_changed, other_changed, refused,
):
    """Replay the disabled-DNS review shape observed on the native fixture.

    Args:
        include_dns: Consent from the controlled physical-interface transition.
        dns_changed: Whether the editor changed generated records after admission.
        other_changed: Independent pending component that must remain rejected.
        refused: Whether the review must stop without submitting a task.
    """
    roots = {"network", "ca", "firewall", "appliance_settings", "public_services"}
    posts = []

    class Client:
        def request(self, path):
            """Expose only the existing interface page's public CSRF control.

            Args:
                path: Existing UI inventory path requested by the harness.
            """
            assert path == "/ui/management/physical-interfaces"
            return 200, '<input name="csrf" value="test-csrf">'

        def json(self, path, form=None):
            """Model ordinary and selection-specific review plus one submission.

            Args:
                path: Reviewed UI path, including explicit selection roots.
                form: Consent fields for the final protected Apply request.
            """
            if form is not None:
                assert path == "/ui/management/appliance-apply"
                posts.append(form)
                return 202, {"job_id": "job_123456789abc", "status_url": "/tasks/job_123456789abc/status"}
            selected = parse_qs(urlsplit(path).query).get("selected_units")
            rows = [{"id": name, "changed": name == "network", "valid": True,
                     "selected": selected is not None and name in selected} for name in sorted(roots)]
            rows.append({"id": "dnsmasq", "changed": dns_changed, "valid": True,
                         "selected": selected is not None and "dnsmasq" in selected})
            if other_changed:
                rows.append({"id": other_changed, "changed": True, "valid": True, "selected": False})
            if selected is None:
                return 200, {"units": rows, "active_task": None}
            # The ordinary planner also replays unchanged routing/NAT dependencies.
            rows.extend({"id": name, "changed": False, "valid": True,
                         "selected": True, "required_dependency": True} for name in ("wan", "nat"))
            return 200, {"units": rows, "requested_units": selected, "plan_token": "test-reviewed-plan"}

    if refused:
        with pytest.raises(handoff.Refusal, match="unrelated_pending_units"):
            handoff.submit(Client(), include_generated_dns=include_dns)
        assert posts == []
        return
    assert handoff.submit(Client(), include_generated_dns=include_dns) == (
        "job_123456789abc", "/tasks/job_123456789abc/status",
    )
    assert len(posts) == 1
    expected = roots | ({"dnsmasq"} if dns_changed else set())
    assert set(posts[0]["requested_units"]) == expected
    assert set(posts[0]["selected_units"]) == expected | {"wan", "nat"}
    assert posts[0]["reviewed_plan"] == "test-reviewed-plan"


def test_inspect_admits_before_credential_or_peer_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Handle test inspect admits before credential or peer connection for certificate handoff verification.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated test overrides."""
    plan_path = tmp_path / "plan.json"
    evidence_path = tmp_path / "evidence.json"
    plan_path.write_text(json.dumps({"pr": 871, "source_commit": "a" * 40, "scenario": "static-success"}))
    monkeypatch.setattr(sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path)])
    monkeypatch.setattr(handoff, "admit_execution", lambda plan: (_ for _ in ()).throw(handoff.Refusal("peer_original_identity_mismatch")))
    monkeypatch.setattr(handoff, "admin_password", lambda: pytest.fail("admin credential read before admission"))
    monkeypatch.setattr(handoff, "PinnedPeerTransport", lambda *args: pytest.fail("network before admission"))
    with pytest.raises(SystemExit, match="1"):
        handoff.main()
    evidence = json.loads(evidence_path.read_text())
    assert evidence["success"] is False
    assert evidence["failure"] == "peer_original_identity_mismatch"


def test_live_address_ownership_precedes_http_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A changed private-LAN claim must stop before the admin password is sent.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated test overrides.
    """
    plan_path = tmp_path / "plan.json"
    evidence_path = tmp_path / "evidence.json"
    plan_path.write_text(json.dumps({
        "pr": 871, "source_commit": "a" * 40, "scenario": "static-success",
        "peer_transport": {"host": "peer", "user": "tester", "ssh_host_key": "key",
                           "ssh_public_key": "ssh-ed25519 " + "A" * 44, "private_subnet": "192.168.77.0/24",
                           "baseline_address": "192.168.77.10"},
    }))
    monkeypatch.setattr(sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path)])
    monkeypatch.setattr(handoff, "admit_execution", lambda _plan: {})
    monkeypatch.setattr(handoff, "admin_password", lambda: "test-admin-password")

    class Peer:
        def __init__(self, *_args):
            """Create a test-only peer transport.

            Args:
                *_args: Ignored transport constructor arguments.
            """
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            """Close the test-only peer transport.

            Args:
                *_args: Ignored context-manager exit arguments.
            """
            pass

    monkeypatch.setattr(handoff, "PinnedPeerTransport", Peer)
    monkeypatch.setattr(handoff, "admit_private_receipts", lambda _plan: (_ for _ in ()).throw(
        handoff.PeerProofRefusal("live ownership changed")))
    monkeypatch.setattr(handoff, "Client", lambda *_args, **_kwargs: pytest.fail("HTTP client before live ownership"))
    with pytest.raises(SystemExit, match="1"):
        handoff.main()
    assert json.loads(evidence_path.read_text())["failure"] == "private_live_preflight_unproven"


def test_admin_bridge_consumes_only_admin_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """Require the appliance bridge to consume only its designated password.

    Args:
        monkeypatch: Pytest fixture for isolated test overrides."""
    monkeypatch.setenv("ATLASO_NATIVE_ADMIN", "admin-password-123")
    assert handoff.admin_password() == "admin-password-123"


def test_admission_git_child_has_no_credential_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    """The head check must not pass either plaintext bridge value to Git.

    Args:
        monkeypatch: Isolated environment and Git subprocess replacement.
    """
    monkeypatch.setenv("ATLASO_NATIVE_ADMIN", "dummy-admin-password")
    monkeypatch.setenv("ATLASO_NATIVE_PEER", "dummy-peer-password")
    observed = []

    def refuse_after_environment_check(_command, **kwargs):
        """Stop after recording the Git child's scrubbed environment.

        Args:
            _command: Git invocation arguments, unused by this assertion.
            **kwargs: Subprocess options containing the child environment.
        """
        observed.append(kwargs["env"])
        raise RuntimeError("stop before reading plan artifacts")

    monkeypatch.setattr(handoff.subprocess, "run", refuse_after_environment_check)
    with pytest.raises(RuntimeError, match="stop before reading plan artifacts"):
        handoff.admit_execution({"deployed_commit": "a" * 40})
    assert len(observed) == 1
    assert "ATLASO_NATIVE_ADMIN" not in observed[0]
    assert "ATLASO_NATIVE_PEER" not in observed[0]


def test_interface_edit_accepts_vmware_mac_spelling_only_for_same_device() -> None:
    """The VMX uses hyphens while the authenticated UI inventory uses colons."""
    class Client:
        def __init__(self) -> None:
            self.posts: list[tuple[str, dict]] = []

        def interface(self, _name: str) -> tuple[dict, str]:
            """Handle interface for certificate handoff verification.

            Args:
                _name:  name used by this operation."""
            return {"id": 4, "mac_address": "00:50:56:AA:BB:CC"}, "csrf-value"

        def request(self, path: str, form: dict) -> None:
            """Handle request for certificate handoff verification.

            Args:
                path: Path to the resource being inspected.
                form: Form fields submitted to the appliance."""
            self.posts.append((path, form))

    client = Client()
    handoff.edit(client, "eth0", {"access_management_ui_enabled": False}, "00-50-56-aa-bb-cc")
    assert client.posts == [(
        "/ui/management/physical-interfaces/4/edit",
        {"access_management_ui_enabled": "off", "csrf": "csrf-value"},
    )]
    with pytest.raises(handoff.Refusal, match="interface_mac_changed"):
        handoff.edit(client, "eth0", {"access_management_ui_enabled": False}, "00-50-56-aa-bb-cd")
    assert len(client.posts) == 1


@pytest.mark.parametrize("changed", ["task_id", "vmx_path", "source_commit", "digest"])
def test_predeployment_snapshot_must_belong_to_exact_runtime(changed: str) -> None:
    """A clean snapshot from another lab cannot authorize this VM's mutation.

    Args:
        changed: Changed used by this operation."""
    plan = {"task_id": "task-a", "vmx_path": "owned-a.vmx",
            "predeployment_evidence": {"sha256": "a" * 64}}
    ownership = {"source_commit": "b" * 40}
    source = {"task_id": "task-a", "vmx_path": "owned-a.vmx", "source_commit": "b" * 40}
    runtime = {"predeployment_sha256": "a" * 64}
    handoff.admit_predeployment_binding(plan, ownership, source, runtime)
    if changed == "digest":
        runtime["predeployment_sha256"] = "c" * 64
    elif changed == "source_commit":
        source[changed] = "c" * 40
    else:
        source[changed] = "other"
    with pytest.raises(handoff.Refusal, match="predeployment_runtime_binding_mismatch"):
        handoff.admit_predeployment_binding(plan, ownership, source, runtime)


def test_trusted_host_source_and_deployed_commits_are_distinct_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A trusted-host plan checks the reviewed source head separately from deployed code.

    Args:
        monkeypatch: Isolated subprocess and receipt-reader replacements.
    """
    source_commit = "a" * 40
    deployed_commit = "b" * 40
    assert source_commit != deployed_commit

    class StopAfterHeadCheck(Exception):
        pass

    monkeypatch.setattr(
        handoff.subprocess, "run",
        lambda *_args, **_kwargs: type("Result", (), {"stdout": source_commit + "\n"})(),
    )

    def stop_at_original_receipt(_reference):
        """Stop after proving commit admission reached the first receipt read.

        Args:
            _reference: Receipt reference passed by admission; not inspected here.
        """
        raise StopAfterHeadCheck()

    monkeypatch.setattr(handoff, "bound_json", stop_at_original_receipt)
    plan = {
        "trust_model": "trusted-host", "source_commit": source_commit,
        "deployed_commit": deployed_commit, "vm_creation_intent": {},
    }
    with pytest.raises(StopAfterHeadCheck):
        handoff.admit_execution(plan)


def test_unrelated_resource_source_commit_fails_before_receipt_read_or_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resource source outside the harness ancestry is rejected before receipt admission.

    Args:
        monkeypatch: Isolated Git and receipt-reader replacements.
    """
    current_head = "a" * 40
    resource_source = "b" * 40
    calls: list[list[str]] = []

    def git_run(command, **_kwargs):
        """Return a current head and a failed ancestry result.

        Args:
            command: Git argument vector being exercised.
            **_kwargs: Subprocess settings unused by this fake.
        """
        calls.append(command)
        if command[-2:] == ["rev-parse", "HEAD"]:
            return type("Result", (), {"stdout": current_head + "\n", "returncode": 0})()
        return type("Result", (), {"stdout": "", "returncode": 1})()

    monkeypatch.setattr(handoff.subprocess, "run", git_run)
    monkeypatch.setattr(handoff, "bound_json", lambda _ref: pytest.fail("receipt read before ancestry admission"))
    plan = {
        "trust_model": "trusted-host", "source_commit": current_head,
        "resource_source_commit": resource_source, "deployed_commit": "c" * 40,
    }
    with pytest.raises(handoff.Refusal, match="resource_source_not_reviewed_ancestor"):
        handoff.admit_execution(plan)
    assert len(calls) == 2
    assert calls[1][-3:] == ["--is-ancestor", resource_source, current_head]


def test_reviewed_resource_source_ancestor_allows_initial_receipt_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid original resource ancestor passes the gate before the first receipt is read.

    Args:
        monkeypatch: Isolated Git and receipt-reader replacements.
    """
    current_head = "a" * 40
    resource_source = "b" * 40

    class StopAtReceiptRead(Exception):
        pass

    calls: list[list[str]] = []

    def git_run(command, **_kwargs):
        """Return a current head and successful ancestry result.

        Args:
            command: Git argument vector being exercised.
            **_kwargs: Subprocess settings unused by this fake.
        """
        calls.append(command)
        if command[-2:] == ["rev-parse", "HEAD"]:
            return type("Result", (), {"stdout": current_head + "\n", "returncode": 0})()
        return type("Result", (), {"stdout": "", "returncode": 0})()

    monkeypatch.setattr(handoff.subprocess, "run", git_run)

    def stop_at_receipt(_reference):
        """Raise a sentinel when admission starts reading original receipts.

        Args:
            _reference: First receipt reference passed by admission.
        """
        raise StopAtReceiptRead()

    monkeypatch.setattr(handoff, "bound_json", stop_at_receipt)
    plan = {
        "trust_model": "trusted-host", "source_commit": current_head,
        "resource_source_commit": resource_source, "deployed_commit": "c" * 40,
        "vm_creation_intent": {},
    }
    with pytest.raises(StopAtReceiptRead):
        handoff.admit_execution(plan)
    assert len(calls) == 2
    assert calls[1][-3:] == ["--is-ancestor", resource_source, current_head]


def test_topology_drift_blocks_desired_http_edit_before_request() -> None:
    """A changed host topology prevents the protected HTTP write from reaching the opener."""
    checked: list[str] = []

    def topology_guard() -> None:
        checked.append("drift")
        raise handoff.HostRefusal("trusted_host_topology_changed")

    class Peer:
        pass

    Peer.topology_guard = staticmethod(topology_guard)

    class Opener:
        def open(self, *_args, **_kwargs):
            """Refuse any HTTP request that gets past the topology guard.

            Args:
                *_args: Positional request arguments supplied to the opener.
                **_kwargs: Keyword request options supplied to the opener.
            """
            pytest.fail("HTTP desired-state edit reached the network after topology drift")

    client = handoff.Client.__new__(handoff.Client)
    client.url = "https://192.168.77.30"
    client.peer = Peer()
    client.opener = Opener()
    with pytest.raises(handoff.HostRefusal, match="trusted_host_topology_changed"):
        client.request("/ui/management/settings", {"hostname": "changed"})
    assert checked == ["drift"]


def _write_admission_receipt(root: Path, name: str, value: dict) -> dict[str, str]:
    """Write a real bounded receipt and return its independent digest reference.

    Args:
        root: Pytest-owned ordinary-file directory for the receipt.
        name: Receipt filename within the temporary directory.
        value: Public receipt fields to serialize.
    """
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path = root / name
    path.write_bytes(payload)
    return {"path": str(path), "sha256": handoff.hashlib.sha256(payload).hexdigest()}


def _ordinary_admission_fixture(tmp_path: Path, mode: str = "static") -> tuple[dict, dict, dict]:
    """Create real receipt files for the ordinary-CA admission contract.

    Args:
        tmp_path: Pytest-owned directory for exact digest-bound receipt files.
        mode: Static legacy baseline or explicit ordinary-CA DHCP mode.
    """
    task_id, commit, deployed = "task-ordinary-ca", "a" * 40, "a" * 40
    mac = "00:50:56:aa:bb:cc"
    lease, baseline, candidate = "192.168.77.10", "192.168.77.30", "192.168.77.40"
    selected_address = lease if mode == "dhcp" else baseline
    ca_path = tmp_path / "public-ca.pem"
    ca_path.write_bytes(b"public pinned CA bytes")
    ca_sha = handoff.hashlib.sha256(ca_path.read_bytes()).hexdigest()
    intent = {"schema": 1, "kind": "vm-creation-intent", "task_id": task_id}
    intent_ref = _write_admission_receipt(tmp_path, "original-intent.json", intent)
    ownership = {
        "schema": 1, "kind": "vm", "task_id": task_id, "repository": "mdaneri/Atlaso",
        "pr": 1118, "path": str(tmp_path / "appliance.vmx"), "root_path": str(tmp_path),
        "root_identity": ["directory-file-id"], "intent_sha256": intent_ref["sha256"],
        "source_commit": commit,
    }
    ownership_ref = _write_admission_receipt(tmp_path, "original-ownership.json", ownership)
    source = {
        "schema": 1, "phase": "before-certificate-validation", "task_id": task_id,
        "vmx_path": ownership["path"], "source_commit": commit,
        "routing_intent_state": "proven-absent", "routing_intent": None,
        "app_service": {"LoadState": "loaded", "ActiveState": "active"},
        "route_snapshot": {
            "schema": 1, "database": "/var/lib/atlaso/atlaso.db", "state": "proven-absent",
            "counts": {name: 0 for name in (
                "routes", "routing_rules", "nat_rules", "port_forwards", "wan_policies",
                "route_physical_interfaces", "route_vlan_interfaces",
            )},
            "settings": {name: False for name in (
                "routes_wan.routing_enabled", "routes_wan.wan_simulation_enabled",
                "routes_wan.nat_enabled", "traffic_publishing.nat_enabled",
            )},
            "routing_service": None, "probe_sha256": "b" * 64,
        },
    }
    source_ref = _write_admission_receipt(tmp_path, "predeployment.json", source)
    helper_sha = "c" * 64
    wheel_sha = "d" * 64
    runtime = {
        "schema": 1, "kind": "certificate-controlled-runtime", "vmx_path": ownership["path"],
        "vm_ownership_sha256": ownership_ref["sha256"], "deployed_commit": deployed,
        "url": f"https://{selected_address}", "interface": "eth0", "mac": mac,
        "wheel_sha256": wheel_sha, "helper_sha256": helper_sha, "helper_source_commit": commit,
        "address_ownership_state": "trusted-host-controlled",
        "predeployment_sha256": source_ref["sha256"],
        "address_proof_sha256": "e" * 64,
    }
    baseline_reference: dict[str, str]
    if mode == "dhcp":
        observation = {"kind": "certificate-dhcp-baseline-observation", "phase": "iso-dhcp-baseline-observed"}
        baseline_reference = _write_admission_receipt(tmp_path, "dhcp-observation.json", observation)
        runtime["dhcp_baseline_observation_sha256"] = baseline_reference["sha256"]
    else:
        baseline_reference = _write_admission_receipt(
            tmp_path, "rewired-runtime.json", {"kind": "certificate-rewired-runtime"},
        )
        runtime["rewired_runtime_sha256"] = baseline_reference["sha256"]
    fixture = {
        "appliance_vmx": ownership["path"], "peer_vmx": str(tmp_path / "peer.vmx"),
        "appliance_mac": mac, "appliance_ownership_sha256": ownership_ref["sha256"],
        "lease_address": lease, "lan_segment_receipt_sha256": "f" * 64,
    }
    reservation = {
        "schema": 1, "kind": "certificate-private-address-proof",
        "phase": "dhcp-baseline-preflight" if mode == "dhcp" else "static-baseline-preflight",
        "task_id": task_id, "vmx_path": ownership["path"], "peer_fixture_sha256": "9" * 64,
        "dhcp_baseline_observation_sha256" if mode == "dhcp" else "rewired_runtime_sha256": baseline_reference["sha256"],
        "lan_segment_receipt_sha256": fixture["lan_segment_receipt_sha256"], "ca_sha256": ca_sha,
        "peer_routed_baseline_https": "explicit-ca-and-ip-hostname-verified",
        "trust_model": "trusted-host", "address_ownership_state": "trusted-host-controlled",
        "trusted_host_topology": {"interfaces": []},
        "baseline_address": selected_address, "addresses": [candidate, lease],
        "dhcp_reservation": lease, "ordinary_ca_baseline_mode": "dhcp" if mode == "dhcp" else "static",
    }
    address_ref = _write_admission_receipt(tmp_path, "address-proof.json", reservation)
    runtime["address_proof_sha256"] = address_ref["sha256"]
    runtime_ref = _write_admission_receipt(tmp_path, "controlled-runtime.json", runtime)
    plan = {
        "trust_model": "trusted-host", "task_id": task_id, "pr": 1118,
        "source_commit": commit, "resource_source_commit": commit, "deployed_commit": deployed,
        "scenario": "ordinary-ca-rotation", "ordinary_ca_baseline_mode": mode,
        "vmx_path": ownership["path"], "vm_root_path": str(tmp_path),
        "vm_creation_intent": intent_ref, "vm_ownership": ownership_ref,
        "appliance_intent": intent_ref, "appliance_ownership": ownership_ref,
        "predeployment_evidence": source_ref, "runtime_evidence": runtime_ref,
        "address_evidence": address_ref, "peer_fixture": {"sha256": "9" * 64},
        "interface": "eth0", "mac": mac, "url": f"https://{selected_address}",
        "baseline_address": baseline, "current_address": lease, "expected_dhcp_address": lease,
        "static_candidate_address": candidate, "wheel_sha256": wheel_sha, "helper_sha256": helper_sha,
        "ca_path": str(ca_path),
        "peer_transport": {"private_subnet": "192.168.77.0/24", "baseline_address": baseline},
        "dhcp_baseline_observation": baseline_reference if mode == "dhcp" else None,
        "rewired_runtime": baseline_reference if mode == "static" else None,
    }
    return plan, fixture, reservation


def _admit_ordinary_plan(plan: dict, fixture: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub Git and independently admitted original resource/provider boundaries.

    Args:
        plan: Real receipt-bound ordinary CA plan passed to production admission.
        fixture: Original peer fixture returned by the private receipt producer.
        monkeypatch: Replace only the Git, VM, private-provider and topology boundaries.
    """
    head = plan["source_commit"]
    monkeypatch.setattr(handoff.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout=head + "\n"))
    monkeypatch.setattr(handoff, "original_vm", lambda *_args: {
        "source_commit": plan["source_commit"], "path": plan["vmx_path"],
    })
    monkeypatch.setattr(handoff, "admit_private_receipts", lambda _plan: (fixture, {}))
    monkeypatch.setattr(handoff, "reviewed_helper_identity", lambda _plan: {
        "helper_sha256": plan["helper_sha256"], "helper_source_commit": plan["source_commit"],
    })
    monkeypatch.setattr(handoff, "inspect_trusted_host", lambda _plan: {"interfaces": []})
    monkeypatch.setattr(handoff, "assert_same_topology", lambda *_args: None)


@pytest.mark.parametrize("mode", ["static", "dhcp"])
def test_ordinary_ca_admission_uses_mode_bound_baseline_and_candidate_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    """Admit static and DHCP baseline receipts without requiring baseline in proof addresses.

    Args:
        tmp_path: Pytest-owned directory for real digest-bound evidence receipts.
        monkeypatch: Replace only external Git, VM, private-provider and topology boundaries.
        mode: Static legacy or explicit DHCP ordinary-CA mode.
    """
    plan, fixture, reservation = _ordinary_admission_fixture(tmp_path, mode)
    _admit_ordinary_plan(plan, fixture, monkeypatch)

    result = handoff.admit_execution(plan)

    assert result["deployed_commit"] == plan["source_commit"]
    assert reservation["addresses"] == [plan["static_candidate_address"], fixture["lease_address"]]
    assert plan["baseline_address"] not in reservation["addresses"]


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("observation_hash", "controlled_runtime_proof_binding_mismatch"),
        ("phase", "task_address_ownership_unproven"),
        ("url", "peer_private_origin_mismatch"),
        ("lease", "task_address_ownership_unproven"),
    ],
)
def test_dhcp_ordinary_admission_refuses_observation_url_or_lease_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str, reason: str,
) -> None:
    """Refuse an observation ref, phase, origin URL, or lease that differs from admission.

    Args:
        tmp_path: Pytest-owned directory for real digest-bound evidence receipts.
        monkeypatch: Replace only external Git, VM, private-provider and topology boundaries.
        fault: Independent mismatch introduced into a copied receipt-bound plan.
        reason: Expected fixed production refusal marker.
    """
    plan, fixture, reservation = _ordinary_admission_fixture(tmp_path, "dhcp")
    if fault == "observation_hash":
        path = Path(plan["runtime_evidence"]["path"])
        runtime = json.loads(path.read_text())
        runtime["dhcp_baseline_observation_sha256"] = "1" * 64
        plan["runtime_evidence"] = _write_admission_receipt(tmp_path, "controlled-runtime.json", runtime)
    elif fault == "phase":
        reservation["phase"] = "static-baseline-preflight"
        plan["address_evidence"] = _write_admission_receipt(tmp_path, "address-proof.json", reservation)
        runtime_path = Path(plan["runtime_evidence"]["path"])
        runtime = json.loads(runtime_path.read_text())
        runtime["address_proof_sha256"] = plan["address_evidence"]["sha256"]
        plan["runtime_evidence"] = _write_admission_receipt(tmp_path, "controlled-runtime.json", runtime)
    elif fault == "url":
        plan["url"] = "https://192.168.77.30"
        runtime_path = Path(plan["runtime_evidence"]["path"])
        runtime = json.loads(runtime_path.read_text())
        runtime["url"] = plan["url"]
        plan["runtime_evidence"] = _write_admission_receipt(tmp_path, "controlled-runtime.json", runtime)
    elif fault == "lease":
        reservation["dhcp_reservation"] = "192.168.77.11"
        plan["address_evidence"] = _write_admission_receipt(tmp_path, "address-proof.json", reservation)
        runtime_path = Path(plan["runtime_evidence"]["path"])
        runtime = json.loads(runtime_path.read_text())
        runtime["address_proof_sha256"] = plan["address_evidence"]["sha256"]
        plan["runtime_evidence"] = _write_admission_receipt(tmp_path, "controlled-runtime.json", runtime)
    _admit_ordinary_plan(plan, fixture, monkeypatch)

    with pytest.raises(handoff.Refusal, match=reason):
        handoff.admit_execution(plan)
