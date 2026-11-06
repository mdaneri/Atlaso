"""Protect the distinct, one-attempt recovery of a terminal initial NTP timeout."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_fixture_init as init  # noqa: E402 - Reviewed interop entrypoint.

PEER = "192.168.77.1"
MAC = "00:50:56:aa:bb:cc"
CA = b"public-test-ca"
TOKEN = "synthetic-concealed-token"
ERROR = ("ntpd clock-source transition failed: ntpd is active as the only selected clock source, "
         "but did not synchronize within 60 seconds: synchronization not reported. Previous config is restored;")
NTPSEC_TIMEOUT = (
    "ntpd clock-source transition failed: NTPsec did not verify leap_none, sync_ntp and a reachable selected upstream "
    "within {seconds} seconds. Bounded synchronization evidence: [{{\"status\": \"sanitized\"}}]. "
    "Previous config is restored;"
)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is unavailable")
@pytest.mark.parametrize("switches,reason", [
    (["-ExecuteRecovery"], "ExecuteRecovery requires RecoverFixture"),
    (["-RecoverFixture", "-Bootstrap"], "separate operations"),
    (["-RecoverFixture", "-InitializeFixture"], "separate operations"),
    (["-RecoverFixture", "-ExecuteInitialization"], "ExecuteInitialization requires InitializeFixture"),
])
def test_wrapper_refuses_mixed_recovery_modes_before_source_or_credentials(switches, reason):
    """Run the actual early PowerShell gate using unusable credential/input selectors.

    Args:
        switches: Invalid recovery/initialization/bootstrap flag combination.
        reason: Fixed expected pre-credential refusal.
    """
    root = Path(__file__).resolve().parents[1]
    parameters = {
        "RepositoryRoot": str(root), "ReviewedSourceCommit": "a" * 40, "Plan": "unused",
        "AddressEvidence": "unused", "RuntimeEvidence": "unused", "EnvironmentId": "unused",
        "PythonPath": "unused", **{switch.removeprefix("-"): True for switch in switches},
    }
    # Catch the real gate, but assert its message independently of PowerShell's
    # terminal-width wrapping and ANSI error renderer on Linux CI.
    command = (
        "$ErrorActionPreference='Stop'; try { "
        "$parameters=ConvertFrom-Json -AsHashtable $env:ATLASO_TEST_CERTIFICATE_PARAMETERS; "
        "& $env:ATLASO_TEST_CERTIFICATE_WRAPPER @parameters; exit 0 "
        "} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
    )
    result = subprocess.run([
        "pwsh", "-NoProfile", "-Command", command,
    ], capture_output=True, text=True, timeout=15, env={
        **os.environ,
        "ATLASO_TEST_CERTIFICATE_WRAPPER": str(root / "scripts/windows/vmware/inspect-certificate-peer.ps1"),
        "ATLASO_TEST_CERTIFICATE_PARAMETERS": json.dumps(parameters),
    })
    assert result.returncode != 0 and reason in result.stderr


def publish_failure(root: Path, original: dict, tls: dict, **changes) -> dict:
    """Create an immutable synthetic original failure and its independent reference.

    Args:
        root: Pytest-owned original-result directory.
        original: Original saved management interface fields.
        tls: Original served public TLS identity.
        **changes: One original failure boundary to vary.
    """
    root.mkdir()
    value = {"schema": 1, "kind": "certificate-fixture-initialization", "task_id": "task",
             "source_commit": "b" * 40, "job_id": "job_0123456789ab", "success": False,
             "stage": "apply_wait", "recovery": "preserve_and_reconcile",
             "original_interface": original, "original_tls": tls, **changes}
    path = root / "fixture-initialization-result.json"
    path.write_text(json.dumps(value))
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


@pytest.mark.parametrize("changes", [
    {"success": True}, {"recovery": "preserve_unknown_apply_do_not_resubmit"},
    {"stage": "desired_ntp"}, {"task_id": "another-task"}, {"job_id": "unbound-job"},
])
def test_recovery_refuses_unproven_original_failure_before_network(tmp_path, monkeypatch, changes):
    """Never promote an unknown, mismatched or successful task into recovery authority.

    Args:
        tmp_path: Pytest-owned original evidence directory.
        monkeypatch: Replace only source ancestry, not receipt hashing.
        changes: Original-failure condition that must refuse.
    """
    reference = publish_failure(tmp_path / "original", {}, {}, **changes)
    monkeypatch.setattr(init, "require_reviewed_ancestor", lambda *args: None)
    with pytest.raises(init.Refusal, match="terminal_initialization_failure"):
        init.admit_recovery_failure({"task_id": "task", "fixture_initialization_failure": reference})


@pytest.mark.parametrize("change", ["extra_unit", "invalid", "public_changed", "ntp_unchanged", "active"])
def test_recovery_selection_refuses_other_replays_or_changed_consent(change):
    """Keep the new operation at exactly one pending NTP and one skipped service unit.

    Args:
        change: Invalid server-owned review boundary to exercise.
    """
    review = {"active_task": None, "requested_units": sorted(init.RECOVERY_ROOTS), "units": [
        {"id": "ntpd", "selected": True, "valid": True, "changed": True},
        {"id": "public_services", "selected": True, "valid": True, "changed": False},
    ]}
    if change == "extra_unit":
        review["units"].append({"id": "network", "selected": True, "valid": True, "changed": False})
    elif change == "invalid":
        review["units"][0]["valid"] = False
    elif change == "public_changed":
        review["units"][1]["changed"] = True
    elif change == "ntp_unchanged":
        review["units"][0]["changed"] = False
    else:
        review["active_task"] = {"id": "another-job"}
    with pytest.raises(init.Refusal, match="recovery_scope_changed"):
        init.recovery_selection(review)


@pytest.mark.parametrize("change", ["wrong_task", "unknown_task", "other_failure", "no_rollback", "tls", "pending"])
def test_recovery_requires_current_terminal_ntp_failure_and_unchanged_baseline(change):
    """Refuse a different failure or baseline before any recovery claim or Apply.

    Args:
        change: Live failure or original-state binding to corrupt.
    """
    original = {"ipv4_method": "dhcp"}
    tls = {"sha256": "a" * 64}
    failure = {"job_id": "job_0123456789ab", "original_interface": original, "original_tls": dict(tls)}
    public = {"dns": {"enabled": False, "upstream_servers": [PEER]},
              "settings": {"external_dns_servers": [PEER]},
              "ntp": {"enabled": False, "nts_server_enabled": False, "time_source": "ntp_client", "peer_only": True}}
    review = {"active_task": None, "initial_apply_required": True, "pending_count": 1,
              "units": [{"id": "ntpd", "changed": True}]}
    children = [{"component_key": unit, "status": "succeeded"} for unit in sorted(init.ROOTS - init.RECOVERY_ROOTS)]
    children.extend([{"component_key": "ntpd", "status": "failed", "error": ERROR},
                     {"component_key": "public_services", "status": "skipped"}])
    task = {"id": failure["job_id"], "type": "appliance-apply", "status": "failed", "_children": children}
    if change == "wrong_task":
        task["id"] = "job_abcdefabcdef"
    elif change == "unknown_task":
        task["status"] = "running"
    elif change == "other_failure":
        children[0]["status"] = "failed"
    elif change == "no_rollback":
        children[-2]["error"] = "ntpd service start failed; original controller not restored"
    elif change == "tls":
        tls["sha256"] = "b" * 64
    else:
        review["units"].append({"id": "network", "changed": True})
        review["pending_count"] = 2
    client = SimpleNamespace(json=lambda _path: (200, {"task": task}))
    with pytest.raises(init.Refusal, match="fixture_recovery_"):
        init.inspect_recovery(client, failure, review, public, original, tls, PEER)


def inspect_with_ntp_error(error: str) -> dict:
    """Run inspect_recovery against an otherwise-valid terminal initializer failure.

    Args:
        error: Exact NTP component error text under test.
    """
    original = {"ipv4_method": "dhcp"}
    tls = {"sha256": "a" * 64}
    failure = {"job_id": "job_0123456789ab", "original_interface": original, "original_tls": dict(tls)}
    public = {"dns": {"enabled": False, "upstream_servers": [PEER]},
              "settings": {"external_dns_servers": [PEER]},
              "ntp": {"enabled": False, "nts_server_enabled": False, "time_source": "ntp_client", "peer_only": True}}
    requested = sorted(init.RECOVERY_ROOTS)
    review = {"active_task": None, "initial_apply_required": True, "pending_count": 1,
              "requested_units": requested, "units": [
                  {"id": "ntpd", "selected": True, "valid": True, "changed": True},
                  {"id": "public_services", "selected": True, "valid": True, "changed": False},
              ]}
    children = [{"component_key": unit, "status": "succeeded"}
                for unit in sorted(init.ROOTS - init.RECOVERY_ROOTS)]
    children.extend([{"component_key": "ntpd", "status": "failed", "error": error},
                     {"component_key": "public_services", "status": "skipped"}])
    task = {"id": failure["job_id"], "type": "appliance-apply", "status": "failed", "_children": children}
    selected = {"active_task": None, "requested_units": requested, "units": [
        {"id": "ntpd", "selected": True, "valid": True, "changed": True},
        {"id": "public_services", "selected": True, "valid": True, "changed": False},
    ]}

    def respond(path: str) -> tuple[int, dict]:
        return (200, {"task": task}) if path.startswith("/tasks/") else (200, selected)

    return init.inspect_recovery(SimpleNamespace(json=respond), failure, review, public, original, tls, PEER)


@pytest.mark.parametrize("seconds", ["0", "60", "1.5", "6e+01", "1e-3"])
def test_recovery_accepts_historical_and_bounded_ntpsec_timeout_shapes(seconds: str) -> None:
    """Keep the historical literal and admit only bounded NTPsec evidence timeout messages."""
    historical = inspect_with_ntp_error(ERROR)
    current = inspect_with_ntp_error(NTPSEC_TIMEOUT.format(seconds=seconds))

    assert historical["reason"] == "terminal_initial_ntp_synchronization_timeout"
    assert current["reason"] == "terminal_initial_ntp_synchronization_timeout"
    assert current["selected_units"] == sorted(init.RECOVERY_ROOTS)


@pytest.mark.parametrize(
    "error",
    [
        "ntpd clock-source transition failed: generic timeout after 60 seconds. Previous config is restored;",
        NTPSEC_TIMEOUT.format(seconds="NaN"),
        NTPSEC_TIMEOUT.format(seconds="inf"),
        NTPSEC_TIMEOUT.format(seconds="-0.1"),
        NTPSEC_TIMEOUT.format(seconds="+1"),
        NTPSEC_TIMEOUT.format(seconds=".5"),
        NTPSEC_TIMEOUT.format(seconds="5."),
        NTPSEC_TIMEOUT.format(seconds="60.001"),
        NTPSEC_TIMEOUT.format(seconds="1e999"),
        NTPSEC_TIMEOUT.format(seconds="60s"),
        NTPSEC_TIMEOUT.format(seconds="٦٠"),
        NTPSEC_TIMEOUT.format(seconds="60").replace("Bounded synchronization evidence:", "Synchronization evidence:"),
        NTPSEC_TIMEOUT.format(seconds="60").replace('[{"status": "sanitized"}]. ', ""),
        NTPSEC_TIMEOUT.format(seconds="60").replace("Previous config is restored;", "Previous config restoration failed;"),
        NTPSEC_TIMEOUT.format(seconds="60").replace("NTPsec did not verify", "NTPsec maybe did not verify"),
    ],
    ids=["generic-timeout", "nan", "infinity", "negative", "positive-sign", "leading-decimal", "trailing-decimal",
         "over-budget", "overflow", "malformed", "non-ascii-budget",
         "missing-bounded-marker", "missing-evidence", "missing-rollback", "near-match-prefix"],
)
def test_recovery_refuses_generic_malformed_or_unsafe_ntp_timeout_shapes(error: str) -> None:
    """Do not widen recovery admission to generic errors or unsafe timeout values."""
    with pytest.raises(init.Refusal, match="fixture_recovery_failure_not_admitted"):
        inspect_with_ntp_error(error)


@pytest.mark.parametrize("scenario", ["success", "lost_submit", "unknown_task", "failed_task", "late_monitor", "drift"])
def test_recovery_never_saves_forms_and_claims_only_one_apply_across_namespaces(tmp_path, monkeypatch, scenario):
    """Recover the two selected units once, or preserve the exact known/unknown outcome.

    Args:
        tmp_path: Pytest-owned original and recovery output namespaces.
        monkeypatch: Replace only native transports and clock observations.
        scenario: Terminal success, uncertain outcome, failure or inspected-state drift.
    """
    raw = {"role": "management", "mode": "access", "ipv4_method": "dhcp", "ip_cidr": "", "gateway": "",
           "ipv6_enabled": False, "ipv6_cidr": "", "ipv6_gateway": "", "mtu": 1500, "admin_up": True,
           "check_duplicate_ip_addresses": True, "access_management_ui_enabled": False}
    original = init.saved_fields(raw)
    tls = {"sha256": "a" * 64, "ip_sans": ["192.168.77.10"]}
    reference = publish_failure(tmp_path / "original", original, tls)
    original_bytes = Path(reference["path"]).read_bytes()
    output = tmp_path / "recovery"
    output.mkdir()
    plan = {"task_id": "task", "source_commit": "a" * 40, "fixture_initialization_failure": reference,
            "fixture_initialization": {"peer_time_address": PEER}, "current_address": "192.168.77.10",
            "baseline_address": "192.168.77.30", "static_candidate_address": "192.168.77.40",
            "appliance_user": "admin", "appliance_ssh_host_key": "public-pin", "ca_path": "public-ca",
            "ca_sha256": hashlib.sha256(CA).hexdigest(),
            "peer_transport": {"host": "192.0.2.1", "user": "alpine", "ssh_public_key": "public-key",
                               "ssh_host_key": "public-pin", "private_subnet": "192.168.77.0/24"}}
    calls = []
    state = {"executing": False, "applied": False, "drift": False}
    monkeypatch.setattr(init, "require_reviewed_ancestor", lambda *args: None)
    monkeypatch.setattr(init, "admit_initialization", lambda *args: ({"appliance_mac": MAC}, PEER))
    monkeypatch.setattr(init, "inspect_trusted_host", lambda *args: {})

    @contextmanager
    def monitor(*args):
        """Retain a late sticky topology error after the simulated Apply succeeds.

        Args:
            *args: Original admitted host topology.
        """
        yield SimpleNamespace(check=lambda: None)
        if state["executing"] and scenario == "late_monitor":
            raise RuntimeError("synthetic-private-monitor-error")

    class Session:
        def __init__(self, *args, **kwargs):
            """Accept the pinned transport selectors without network I/O.

            Args:
                *args: Original public transport identity.
                **kwargs: Explicit authentication mode.
            """
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            """Close the synthetic pinned transport.

            Args:
                *args: Context manager exit information.
            """
            pass

        def command(self, command):
            """Read only the original lease, MAC and public CA.

            Args:
                command: Fixed read-only native command.
            """
            if command == "cat /var/lib/misc/dnsmasq.leases":
                return f"{int(time.time()) + 3600} {MAC} 192.168.77.10 host *\n".encode()
            if command == "cat /sys/class/net/eth0/address":
                return MAC.encode()
            assert command == "cat /etc/atlaso/ca/root.crt"
            return CA

    class Client:
        def __init__(self, *args, **kwargs):
            """Accept only synthetic pinned HTTP selectors.

            Args:
                *args: Public endpoint and CA selectors.
                **kwargs: Original peer transport and private IP.
            """
            pass

        def login(self, *args):
            """Keep the synthetic credential in memory only.

            Args:
                *args: Test account and concealed password.
            """
            pass

        def interface(self, name):
            """Return the original interface without changing desired state.

            Args:
                name: Requested management interface.
            """
            assert name == "eth0"
            return dict(raw), TOKEN

        def tls_identity(self):
            return dict(tls)

        def request(self, path):
            """Expose only the normal Apply CSRF control in memory.

            Args:
                path: Fixed existing Physical Interfaces page.
            """
            assert path == "/ui/management/physical-interfaces"
            return 200, f'<input name="csrf" value="{TOKEN}">'

        def json(self, path, form=None, *, autosave=False):
            """Model the real task/review contract and prohibit every form save.

            Args:
                path: Fixed status, review or Apply endpoint.
                form: Existing Apply consent controls only.
                autosave: Any desired-form autosave must be refused.
            """
            assert autosave is False
            if form is not None:
                assert path == "/ui/management/appliance-apply"
                assert set(form["requested_units"]) == init.RECOVERY_ROOTS
                assert set(form["selected_units"]) == init.RECOVERY_ROOTS
                assert form["csrf"] == TOKEN and form["reviewed_plan"] == TOKEN
                calls.append("submit")
                if scenario == "lost_submit":
                    raise OSError("synthetic-private-response")
                return 202, {"job_id": "job_abcdefabcdef", "status_url": "/tasks/job_abcdefabcdef/status"}
            if path == "/tasks/job_0123456789ab/status":
                children = [{"component_key": unit, "status": "succeeded"}
                            for unit in sorted(init.ROOTS - init.RECOVERY_ROOTS)]
                children.extend([{"component_key": "ntpd", "status": "failed", "error": ERROR},
                                 {"component_key": "public_services", "status": "skipped"}])
                return 200, {"task": {"id": "job_0123456789ab", "type": "appliance-apply",
                                      "status": "failed", "_children": children}}
            if state["applied"]:
                return 200, {"active_task": None, "units": [], "pending_count": 0, "initial_apply_required": False}
            selected = "?" in path
            rows = [{"id": unit, "changed": unit == "ntpd", "valid": True, "selected": selected}
                    for unit in sorted(init.RECOVERY_ROOTS if selected else init.ROOTS)]
            return 200, {"active_task": None, "units": rows, "initial_apply_required": True, "pending_count": 1,
                         "requested_units": sorted(init.RECOVERY_ROOTS), "plan_token": TOKEN}

    def public_forms(*args):
        """Return current prerequisite facts without any serializable secret controls.

        Args:
            *args: Synthetic client and original private peer address.
        """
        public = {"dns": {"enabled": False, "upstream_servers": [PEER]},
                  "settings": {"external_dns_servers": [PEER]},
                  "ntp": {"enabled": False, "nts_server_enabled": False, "time_source": "ntp_client",
                          "peer_only": not state["drift"]}}
        return {"dns": ("must-not-save", [("csrf", TOKEN)])}, public

    def wait(*args):
        """Complete or preserve an uncertain existing task without resubmission.

        Args:
            *args: Existing task identity and in-memory authentication context.
        """
        if scenario == "unknown_task":
            raise OSError("synthetic-private-response")
        state["applied"] = scenario != "failed_task"
        return {"status": "failed" if scenario == "failed_task" else "succeeded"}, None

    monkeypatch.setattr(init, "watched_topology", monitor)
    monkeypatch.setattr(init, "PinnedPeerTransport", Session)
    monkeypatch.setattr(init, "PinnedApplianceSession", Session)
    monkeypatch.setattr(init, "verify_peer_isolation", lambda *args: {})
    monkeypatch.setattr(init, "verify_peer_tunnel_scope", lambda *args: {})
    monkeypatch.setattr(init, "verify_peer_time", lambda *args: {"configuration_sha256": "c" * 64})
    monkeypatch.setattr(init, "guest_identity", lambda *args: {"route_snapshot": {"state": "proven-absent"}})
    monkeypatch.setattr(init, "tls_name", lambda *args: "core.example.test")
    monkeypatch.setattr(init, "Client", Client)
    monkeypatch.setattr(init, "prepare_forms", public_forms)
    monkeypatch.setattr(init, "wait_task", wait)
    monkeypatch.setattr(init, "dns_baseline", lambda *args: {"external_dns_servers": [PEER], "upstream_servers": [PEER]})
    monkeypatch.setattr(init, "wait_clock", lambda *args: {"mode": "ntp_client", "healthy": True})
    monkeypatch.setattr(init, "sudo_read", lambda *args: ("*" + PEER + " 192.0.2.1 3 u 1 64 377 0.1 0.1 0.1\n").encode())
    secret = "synthetic-admin-secret"
    inspected = init.initialize(plan, output, secret, execute=False, recovery=True)
    assert inspected["success"] is True and calls == []
    claim = Path(reference["path"]).parent / "fixture-ntp-recovery-claim.json"
    assert not claim.exists()
    path = output / "fixture-recovery-inspection.json"
    plan["fixture_recovery_inspection"] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    state.update(executing=True, drift=scenario == "drift")
    if scenario == "success":
        assert init.initialize(plan, output, secret, execute=True, recovery=True)["stage"] == "recovered_clean_baseline"
    else:
        error = {"lost_submit": OSError, "unknown_task": OSError, "failed_task": init.Refusal,
                 "late_monitor": RuntimeError, "drift": init.Refusal}[scenario]
        with pytest.raises(error):
            init.initialize(plan, output, secret, execute=True, recovery=True)
    result = json.loads((output / "fixture-recovery-result.json").read_text())
    assert result["success"] is (scenario == "success")
    assert Path(reference["path"]).read_bytes() == original_bytes
    assert calls == ([] if scenario == "drift" else ["submit"])
    assert claim.exists() is (scenario != "drift")
    if scenario in {"lost_submit", "unknown_task"}:
        assert result["recovery"] == "preserve_unknown_apply_do_not_resubmit"
    if scenario != "drift":
        other = tmp_path / "another-output"
        other.mkdir()
        with pytest.raises(init.Refusal, match="already_claimed_requires_reconciliation"):
            init.initialize(plan, other, secret, execute=True, recovery=True)
        assert calls == ["submit"]
    for record in tmp_path.rglob("*.json"):
        assert all(value not in record.read_text() for value in (TOKEN, secret, "synthetic-private-response"))
