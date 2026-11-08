"""Regression tests for bounded NTPsec Apply synchronization evidence."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
from functools import lru_cache
from pathlib import Path

import pytest

HELPER_PATH = Path(__file__).resolve().parents[2] / "scripts" / "appliance" / "atlaso-helper"


@lru_cache(maxsize=1)
def load_helper_module():
    """Load the appliance helper as an isolated Python module."""
    loader = importlib.machinery.SourceFileLoader("atlaso_ntpd_candidate_test", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("atlaso_ntpd_candidate_test", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def probe(stdout: str, *, returncode: int = 0, stderr: str = "") -> dict[str, object]:
    """Build one ntpq process result without introducing host clock state.

    Args:
        stdout: Synthetic standard output from the local ntpq query.
        returncode: Process exit status attached to the query result.
        stderr: Synthetic error output used to exercise query-failure handling.
    """
    return {"returncode": returncode, "stdout": stdout, "stderr": stderr}


HEALTHY_VARIABLES = "associd=0 status=0615 leap_none, sync_ntp, 1 event, clock_sync\nstratum=2\n"
HEALTHY_PEER = "*192.0.2.1 .GPS. 1 u 10 64 377 1.0 0.0 0.0\n"


@pytest.mark.parametrize(
    ("variables", "peers", "expected_query"),
    [
        (
            probe(HEALTHY_VARIABLES, stderr="localhost:123: Connection refused"),
            probe(HEALTHY_PEER),
            "socket",
        ),
        (
            probe(HEALTHY_VARIABLES, stderr="ntpq: Name or service not known"),
            probe(HEALTHY_PEER),
            "lookup",
        ),
        (probe("leap_none, sync_ntp, stratum=2"), probe(HEALTHY_PEER), "ok"),
        (
            probe("associd=0 status=0615 leap_alarm, sync_ntp\nstratum=16\n"),
            probe(" 192.0.2.1 .GPS. 1 u 10 64 377 1.0 0.0 0.0\n"),
            "ok",
        ),
        (
            probe("associd=0 status=c615 leap_none, sync_ntp\nstratum=2\n"),
            probe(HEALTHY_PEER),
            "ok",
        ),
        (
            probe(HEALTHY_VARIABLES),
            probe("*192.0.2.1 .GPS. 1 u 10 64 0 1.0 0.0 0.0\n"),
            "ok",
        ),
        (
            probe(HEALTHY_VARIABLES),
            probe("*192.0.2.1 .GPS. 16 u 10 64 377 1.0 0.0 0.0\n"),
            "ok",
        ),
        (
            probe(HEALTHY_VARIABLES),
            probe("*127.127.1.0 .LOCL. 1 u 10 64 377 1.0 0.0 0.0\n"),
            "ok",
        ),
        (
            probe(HEALTHY_VARIABLES),
            probe("*192.0.2.1 .PPS. 1 l 10 64 377 1.0 0.0 0.0\n"),
            "ok",
        ),
        (probe(HEALTHY_VARIABLES), probe(" 192.0.2.1 .GPS. 1 u 10 64 377 1.0 0.0 0.0\n"), "ok"),
    ],
    ids=[
        "zero-exit-socket-error", "name-lookup-error", "flags-without-status-word",
        "alarm-and-unspecified-system-stratum", "numeric-leap-alarm-despite-text",
        "selected-peer-has-zero-reach", "selected-peer-stratum-is-unspecified",
        "synthetic-local-clock-is-not-upstream", "refclock-peer-type-is-not-unicast", "no-selected-peer",
    ],
)
def test_synchronization_evidence_requires_successful_flags_and_a_real_selected_peer(
    variables: dict[str, object], peers: dict[str, object], expected_query: str
) -> None:
    """Do not treat zero exit, text flags, stale events, or an unselected row as health.

    Args:
        variables: Result of the system-variable query.
        peers: Result of the peer-list query.
        expected_query: Sanitized query-failure category expected for the sample pair.
    """
    evidence = load_helper_module()._ntpd_synchronization_evidence(variables, peers)

    assert evidence["healthy"] is False
    assert evidence["query"] == expected_query


def test_synchronization_evidence_accepts_a_selected_reachable_numeric_ipv6_peer() -> None:
    """Ntpq wide output can wrap a numeric IPv6 source onto two lines."""
    peers = probe(
        "     remote                         refid      st t when poll reach   delay   offset  jitter\n"
        "===========================================================================================\n"
        "*2001:db8:1234:5678:90ab:cdef:1234:5678\n"
        "                                   .GPS.       2 u   10   64  377    1.0     0.0     0.0\n"
    )
    evidence = load_helper_module()._ntpd_synchronization_evidence(probe(HEALTHY_VARIABLES), peers)

    assert evidence["healthy"] is True
    assert evidence["selected"] == {
        "address": "2001:db8:1234:5678:90ab:cdef:1234:5678",
        "stratum": "2",
        "reach": "377",
    }


@pytest.mark.parametrize("peer_type", ["8", "0"], ids=["nts-with-cookies", "nts-without-cookies"])
def test_synchronization_evidence_accepts_nts_peer_cookie_count_type(peer_type: str) -> None:
    """NTPsec displays an NTS peer's cookie count in the peer type column.

    Args:
        peer_type: NTPsec peer-type token representing the reported cookie count.
    """
    peer = probe(f"*192.0.2.1 .GPS. 2 {peer_type} 10 64 377 1.0 0.0 0.0\n")
    evidence = load_helper_module()._ntpd_synchronization_evidence(probe(HEALTHY_VARIABLES), peer)

    assert evidence["healthy"] is True
    assert evidence["selected"] == {"address": "192.0.2.1", "stratum": "2", "reach": "377"}


def test_synchronization_evidence_ignores_a_stale_no_system_peer_event() -> None:
    """Current healthy flags and the selected peer override an old event label."""
    variables = probe(HEALTHY_VARIABLES.replace("clock_sync", "no_sys_peer"))
    evidence = load_helper_module()._ntpd_synchronization_evidence(variables, probe(HEALTHY_PEER))

    assert evidence["healthy"] is True


def test_post_step_alarm_reports_native_flags_without_echoing_arbitrary_variables() -> None:
    """A post-step system can report sync_ntp while its leap alarm still forbids health."""
    variables = probe("associd=0 status=c61a leap_alarm, sync_ntp\nstratum=16, token=do-not-echo\n")
    evidence = load_helper_module()._ntpd_synchronization_evidence(variables, probe(""))

    assert evidence["healthy"] is False
    assert evidence["leap"] == "leap_alarm"
    assert evidence["source"] == "sync_ntp"
    assert evidence["stratum"] == 16
    assert evidence["selected"] is None
    assert "do-not-echo" not in str(evidence)


def test_synchronization_evidence_rejects_nonzero_query_with_healthy_stdout() -> None:
    """A failed ntpq process cannot become healthy from plausible output alone."""
    evidence = load_helper_module()._ntpd_synchronization_evidence(
        probe(HEALTHY_VARIABLES, returncode=2), probe(HEALTHY_PEER)
    )

    assert evidence["healthy"] is False
    assert evidence["query"] == "failed"
    assert evidence["variables_returncode"] == 2


def test_wait_uses_numeric_local_query_and_bounds_the_last_probe_to_remaining_time(monkeypatch) -> None:
    """The combined status/peer probe uses the remaining portion of the 60-second guard.

    Args:
        monkeypatch: Patcher for ntpq lookup, monotonic time, sleep, and query execution.
    """
    helper = load_helper_module()
    now = [0.0]
    calls: list[tuple[list[str], float]] = []
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/ntpq" if name == "ntpq" else None)
    monkeypatch.setattr(helper.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)

    def run(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        """Return a synthetic process result for the bounded query.

        Args:
            command: Bounded ntpd or ntpq invocation being stubbed.
            timeout: Maximum runtime allowed for the synthetic query.
        """
        calls.append((command, timeout))
        return subprocess.CompletedProcess(command, 0, HEALTHY_VARIABLES + HEALTHY_PEER, "")

    monkeypatch.setattr(helper, "_run", run)

    helper._ntpd_wait_synchronized(timeout_seconds=0.75)

    assert calls == [
        (["/usr/bin/ntpq", "-n", "-w", "-c", "rv", "-c", "peers", "127.0.0.1"], 0.75)
    ]


def test_wait_timeout_retains_only_distinct_sanitized_state(monkeypatch) -> None:
    """Failure evidence identifies state changes without including raw query payloads.

    Args:
        monkeypatch: Patcher for the clock, ntpq lookup, sleep, and query results.
    """
    helper = load_helper_module()
    now = [0.0]
    samples = [
        ("associd=0 status=0415 leap_alarm, sync_unspec\nstratum=16\n", "token=must-not-appear"),
        ("associd=0 status=0615 leap_alarm, sync_ntp\nstratum=16\n", "key=also-must-not-appear"),
    ]
    calls = [0]
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/ntpq" if name == "ntpq" else None)
    monkeypatch.setattr(helper.time, "monotonic", lambda: now[0])

    def sleep(seconds: float) -> None:
        """Advance the test clock without waiting in real time.

        Args:
            seconds: Interval to add to the mocked monotonic clock.
        """
        now[0] += seconds

    monkeypatch.setattr(helper.time, "sleep", sleep)

    def run(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        """Return a synthetic process result for the bounded query.

        Args:
            command: Combined local status and peer query being stubbed.
            timeout: Remaining runtime budget supplied to the query process.
        """
        del timeout
        index = min(calls[0], len(samples) - 1)
        calls[0] += 1
        variables, secret = samples[index]
        return subprocess.CompletedProcess(command, 0, variables + HEALTHY_PEER, secret)

    monkeypatch.setattr(helper, "_run", run)

    with pytest.raises(RuntimeError) as error:
        helper._ntpd_wait_synchronized(timeout_seconds=4)

    message = str(error.value)
    assert message.count('"healthy": false') == 2
    assert '"query": "failed"' in message
    assert "must-not-appear" not in message
    assert "leap_alarm" not in message
    assert "status" in message


def test_wait_timeout_keeps_only_last_four_distinct_states(monkeypatch) -> None:
    """A changing status inventory stays bounded and retains its latest sample.

    Args:
        monkeypatch: Patcher for the clock, ntpq lookup, sleep, and query results.
    """
    helper = load_helper_module()
    now = [0.0]
    samples = [
        (f"associd=0 status={status} leap_alarm, sync_ntp\nstratum=16\n", f"secret-{status}")
        for status in ("0115", "0215", "0315", "0415", "0515")
    ]
    calls = [0]
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/ntpq" if name == "ntpq" else None)
    monkeypatch.setattr(helper.time, "monotonic", lambda: now[0])

    def sleep(seconds: float) -> None:
        """Advance the test clock without waiting in real time.

        Args:
            seconds: Interval to add to the mocked monotonic clock.
        """
        now[0] += seconds

    monkeypatch.setattr(helper.time, "sleep", sleep)

    def run(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        """Return a synthetic process result for the bounded query.

        Args:
            command: Combined local status and peer query being stubbed.
            timeout: Remaining runtime budget supplied to the query process.
        """
        del timeout
        variables, secret = samples[min(calls[0], len(samples) - 1)]
        calls[0] += 1
        return subprocess.CompletedProcess(command, 0, variables + HEALTHY_PEER, secret)

    monkeypatch.setattr(helper, "_run", run)

    with pytest.raises(RuntimeError) as error:
        helper._ntpd_wait_synchronized(timeout_seconds=10)

    message = str(error.value)
    assert message.count('"healthy": false') == 4
    assert '"status": "0215"' in message
    assert '"status": "0515"' in message
    assert '"status": "0115"' not in message
    assert "secret-" not in message


def configure_transition_mocks(monkeypatch, helper, *, start=None, wait=None) -> list[str]:
    """Replace system operations while retaining Apply transition ordering.

    Args:
        monkeypatch: Patcher for the helper's system-operation functions.
        helper: Loaded appliance helper module whose operations are replaced.
        start: Optional replacement for persistent ntpd service startup.
        wait: Optional replacement for synchronization waiting.
    """
    operations: list[str] = []
    monkeypatch.setattr(helper, "_ntpd_stop_service", lambda unit: operations.append(f"stop:{unit}"))
    monkeypatch.setattr(helper, "_ntpd_set_vmware_timesync", lambda enabled: operations.append(f"vmware:{enabled}"))
    monkeypatch.setattr(helper, "_install_ntpd_config", lambda _path: operations.append("install-config"))
    monkeypatch.setattr(helper, "_ntpd_client_packet_guard", lambda mode: operations.append(f"guard:{mode}"))
    monkeypatch.setattr(helper, "_ntpd_nts_server_enabled", lambda _path: False)
    monkeypatch.setattr(helper, "_ntpd_start_service", start or (lambda _unit, **_kwargs: operations.append("start")))
    monkeypatch.setattr(helper, "_ntpd_wait_synchronized", wait or (lambda timeout: operations.append(f"wait:{timeout}")))
    monkeypatch.setattr(helper, "_ntpd_checkpoint_verified", lambda: operations.append("checkpoint"))
    monkeypatch.setattr(helper, "_ntpd_retire_nts_material", lambda: operations.append("retire"))
    return operations


def test_transition_subtracts_initialization_time_from_the_existing_sync_budget(monkeypatch, tmp_path) -> None:
    """A slower one-shot initializer consumes the same 60-second synchronization deadline.

    Args:
        monkeypatch: Patcher used to advance monotonic time during service startup.
        tmp_path: Temporary directory for the candidate NTP configuration path.
    """
    helper = load_helper_module()
    now = [0.0]

    def start(_unit: str, **_kwargs: object) -> None:
        """Record the mocked service start and its elapsed startup time.

        Args:
            _unit: Systemd unit requested by the transition.
            **_kwargs: Optional bounded startup arguments passed to the helper.
        """
        operations.append("start")
        now[0] = 19.5

    operations = configure_transition_mocks(monkeypatch, helper, start=start)
    monkeypatch.setattr(helper.time, "monotonic", lambda: now[0])

    helper._ntpd_transition("ntp_client", tmp_path / "candidate.conf")

    assert "wait:40.5" in operations
    assert operations.index("start") < operations.index("wait:40.5") < operations.index("checkpoint")


def test_transition_does_not_checkpoint_when_candidate_sync_fails(monkeypatch, tmp_path) -> None:
    """Failed candidate synchronization cannot advance the verified clock checkpoint.

    Args:
        monkeypatch: Patcher used to make candidate synchronization fail.
        tmp_path: Temporary directory for the candidate NTP configuration path.
    """
    helper = load_helper_module()

    def fail(_timeout: float) -> None:
        """Fail the candidate synchronization wait.

        Args:
            _timeout: Remaining synchronization budget passed by the transition.
        """
        raise RuntimeError("NTPsec candidate remains unsynchronized")

    operations = configure_transition_mocks(monkeypatch, helper, wait=fail)

    with pytest.raises(RuntimeError, match="remains unsynchronized"):
        helper._ntpd_transition("ntp_client", tmp_path / "candidate.conf")

    assert "start" in operations
    assert "checkpoint" not in operations


def test_transition_does_not_checkpoint_when_systemd_start_fails(monkeypatch, tmp_path) -> None:
    """A failed bounded systemctl start stops before synchronization or checkpoint.

    Args:
        monkeypatch: Patcher used to inspect and fail the systemctl start operation.
        tmp_path: Temporary directory for the candidate NTP configuration path.
    """
    helper = load_helper_module()
    start_service = helper._ntpd_start_service
    operations = configure_transition_mocks(
        monkeypatch,
        helper,
        start=lambda unit, **kwargs: start_service(unit, **kwargs),
    )
    checked: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(helper, "_ntpd_read_transaction", lambda: None)

    def run_checked(command: list[str], _description: str, **kwargs: object) -> None:
        """Return a bounded synthetic systemd process result.

        Args:
            command: Bounded systemctl command being stubbed.
            _description: Fixed operation description supplied by the helper.
            **kwargs: Optional bounded process arguments supplied by the helper.
        """
        checked.append((command, kwargs))
        if command[:2] == ["systemctl", "start"]:
            raise RuntimeError("systemctl start failed")

    monkeypatch.setattr(helper, "_ntpd_run_checked", run_checked)

    with pytest.raises(RuntimeError, match="systemctl start failed"):
        helper._ntpd_transition("ntp_client", tmp_path / "candidate.conf", restart=False)

    assert checked == [
        (["systemctl", "enable", "ntpd.service"], {}),
        (["systemctl", "start", "ntpd.service"], {"timeout": 35}),
    ]
    assert "wait:60" not in operations
    assert "checkpoint" not in operations


def test_ntpd_service_owns_one_shot_initialization_before_persistent_daemon(monkeypatch, tmp_path) -> None:
    """Guarded initialization runs before persistent ntpd in its own cgroup.

    Args:
        monkeypatch: Patcher for service paths and bounded system-operation calls.
        tmp_path: Temporary root for generated service unit files.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "FIREWALL_SERVICE_PATH", tmp_path / "missing-firewall.service")
    monkeypatch.setattr(helper, "NTP_GUARD_SERVICE_PATH", tmp_path / "atlaso-time-sync-guard.service")
    monkeypatch.setattr(helper, "NTP_NTPD_DROPIN_PATH", tmp_path / "ntpd.service.d" / "atlaso-time-sync.conf")
    monkeypatch.setattr(helper, "NTP_VMTOOLS_DROPIN_PATH", tmp_path / "vmtoolsd.service.d" / "atlaso-time-sync.conf")
    monkeypatch.setattr(helper, "_ntpd_run_checked", lambda *_args, **_kwargs: None)

    helper._ntpd_install_guards()

    dropin = helper.NTP_NTPD_DROPIN_PATH.read_text(encoding="utf-8")
    guard = "ExecStartPre=/opt/atlaso/bin/atlaso-helper ntpd guard pre-ntpd --real"
    initialize = "ExecStartPre=/opt/atlaso/bin/atlaso-helper ntpd guard initialize-ntpd --real"
    assert dropin.index(guard) < dropin.index(initialize)
    assert "ExecStartPre=/usr/sbin/ntpd -gq" not in dropin
    assert "TimeoutStartSec=30" in dropin
    assert "KillMode=control-group" in dropin
    assert "Restart=no" in dropin


def configure_initializer(
    monkeypatch,
    helper,
    tmp_path,
    *,
    mode="ntp_client",
    transaction=None,
    control_pid=None,
    owner_alive=True,
    q_returncode=0,
    q_error=None,
):
    """Mock every process and filesystem dependency used by the clock initializer.

    Args:
        monkeypatch: Patcher for helper constants, process calls, and owner checks.
        helper: Loaded appliance helper module whose dependencies are replaced.
        tmp_path: Temporary directory for the managed candidate NTP config.
        mode: Applied time mode returned by the helper state reader.
        transaction: Optional prepared Apply ownership record.
        control_pid: Optional systemd ControlPID value returned by the mocked query.
        owner_alive: Boolean or predicate result for the Apply transaction owner check.
        q_returncode: Exit status returned by the one-shot ntpd query.
        q_error: Optional exception raised by the one-shot ntpd query.
    """
    config = tmp_path / "ntp.conf"
    config.write_text("managed NTP fixture", encoding="utf-8")
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", config)
    monkeypatch.setattr(helper, "_ntpd_config_managed", lambda _path: True)
    monkeypatch.setattr(helper, "_ntpd_applied_time_mode", lambda _path: mode)
    monkeypatch.setattr(helper, "_ntpd_read_transaction", lambda: transaction)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", owner_alive)
    control_calls: list[list[str]] = []
    q_calls: list[list[str]] = []

    def run_checked(command: list[str], _description: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        """Return a bounded synthetic systemd process result.

        Args:
            command: Bounded process command used to query systemd ownership.
            _description: Fixed operation description supplied by the helper.
            **_kwargs: Optional bounded process arguments supplied by the helper.
        """
        control_calls.append(command)
        stdout = str(helper.os.getpid()) if control_pid is None else control_pid
        return subprocess.CompletedProcess(command, 0, stdout, "")

    def run(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        """Return a synthetic process result for the bounded query.

        Args:
            command: One-shot ntpd query command being stubbed.
            timeout: Maximum runtime allowed for the query.
        """
        del timeout
        q_calls.append(command)
        if q_error is not None:
            raise q_error
        return subprocess.CompletedProcess(command, q_returncode, "", "")

    monkeypatch.setattr(helper, "_ntpd_run_checked", run_checked)
    monkeypatch.setattr(helper, "_run", run)
    return control_calls, q_calls


def test_initialize_clock_refuses_a_different_systemd_control_pid(monkeypatch, tmp_path) -> None:
    """Only the helper process systemd launched as ControlPID may run ntpd -q.

    Args:
        monkeypatch: Patcher used by the clock-initializer dependency fixture.
        tmp_path: Temporary directory for the managed candidate NTP config.
    """
    helper = load_helper_module()
    _control_calls, q_calls = configure_initializer(
        monkeypatch, helper, tmp_path, control_pid="999999"
    )

    assert helper._ntpd_initialize_clock() == 1
    assert q_calls == []


@pytest.mark.parametrize(
    ("mode", "transaction", "owner_alive"),
    [
        ("vmware_tools", None, True),
        ("ntp_client", {"phase": "prepared", "owner": "candidate"}, lambda _owner: False),
    ],
    ids=["non-ntp-applied-mode", "prepared-apply-owner-is-dead"],
)
def test_initialize_clock_refuses_wrong_mode_or_dead_apply_owner(
    monkeypatch, tmp_path, mode: str, transaction: dict[str, object] | None, owner_alive
) -> None:
    """Mode or transaction ownership failures stop before the one-shot command.

    Args:
        monkeypatch: Patcher used by the clock-initializer dependency fixture.
        tmp_path: Temporary directory for the managed candidate NTP config.
        mode: Applied time mode presented to the initializer.
        transaction: Optional candidate Apply transaction record.
        owner_alive: Result controlling whether the transaction owner is alive.
    """
    helper = load_helper_module()
    _control_calls, q_calls = configure_initializer(
        monkeypatch, helper, tmp_path, mode=mode, transaction=transaction, owner_alive=owner_alive
    )

    assert helper._ntpd_initialize_clock() == 1
    assert q_calls == []


def test_initialize_clock_zero_exit_does_not_checkpoint_or_verify_health(monkeypatch, tmp_path) -> None:
    """One-shot success only permits systemd to proceed to persistent ntpd.

    Args:
        monkeypatch: Patcher used by the clock-initializer dependency fixture.
        tmp_path: Temporary directory for the managed candidate NTP config.
    """
    helper = load_helper_module()
    _control_calls, q_calls = configure_initializer(monkeypatch, helper, tmp_path)
    checkpoints: list[str] = []
    health_checks: list[str] = []
    monkeypatch.setattr(helper, "_ntpd_checkpoint_verified", lambda: checkpoints.append("checkpoint"))
    monkeypatch.setattr(helper, "_ntpd_wait_synchronized", lambda *_args: health_checks.append("health"))

    assert helper._ntpd_initialize_clock() == 0
    assert q_calls == [["/usr/sbin/ntpd", "-gq", "-u", "ntp:ntp", "-c", "/etc/ntp.conf"]]
    assert checkpoints == []
    assert health_checks == []


def test_initialize_clock_apply_failure_prevents_candidate_daemon_start(monkeypatch, tmp_path) -> None:
    """An Apply-owned acquisition failure returns nonzero so ExecStart cannot run.

    Args:
        monkeypatch: Patcher used by the clock-initializer dependency fixture.
        tmp_path: Temporary directory for the managed candidate NTP config.
    """
    helper = load_helper_module()
    transaction = {"phase": "prepared", "owner": "candidate"}
    _control_calls, q_calls = configure_initializer(
        monkeypatch,
        helper,
        tmp_path,
        transaction=transaction,
        owner_alive=lambda _owner: True,
        q_returncode=1,
    )
    persistent_starts: list[str] = []
    result = helper._ntpd_initialize_clock()
    if result == 0:
        persistent_starts.append("ntpd")

    assert result == 1
    assert q_calls
    assert persistent_starts == []


@pytest.mark.parametrize(
    ("q_returncode", "q_error", "diagnostic"),
    [
        (1, None, "exit code 1"),
        (0, subprocess.TimeoutExpired("ntpd", 20), "TimeoutExpired"),
    ],
    ids=["nonzero-exit", "timed-out"],
)
def test_initialize_clock_boot_failure_allows_persistent_recovery_without_health(
    monkeypatch, tmp_path, capsys, q_returncode: int, q_error: Exception | None, diagnostic: str
) -> None:
    """Without a prepared Apply, acquisition failure still starts polling ntpd.

    Args:
        monkeypatch: Patcher for query, checkpoint, and health-wait operations.
        tmp_path: Temporary directory for the managed candidate NTP config.
        capsys: Capture fixture used to inspect the sanitized failure diagnostic.
        q_returncode: Exit status returned by the one-shot ntpd query.
        q_error: Optional exception raised by the one-shot ntpd query.
        diagnostic: Fixed diagnostic text expected for the query failure.
    """
    helper = load_helper_module()
    _control_calls, q_calls = configure_initializer(
        monkeypatch, helper, tmp_path, q_returncode=q_returncode, q_error=q_error
    )
    checkpoints: list[str] = []
    health_checks: list[str] = []
    monkeypatch.setattr(helper, "_ntpd_checkpoint_verified", lambda: checkpoints.append("checkpoint"))
    monkeypatch.setattr(helper, "_ntpd_wait_synchronized", lambda *_args: health_checks.append("health"))

    assert helper._ntpd_initialize_clock() == 0
    assert q_calls
    assert diagnostic in capsys.readouterr().err
    assert checkpoints == []
    assert health_checks == []


def test_initialize_clock_refuses_candidate_if_owner_dies_during_successful_query(
    monkeypatch, tmp_path
) -> None:
    """An Apply that ends during -q cannot hand its config to persistent ntpd.

    Args:
        monkeypatch: Patcher for transaction ownership and process operations.
        tmp_path: Temporary directory for the managed candidate NTP config.
    """
    helper = load_helper_module()
    alive = iter((True, False))
    transaction = {"phase": "prepared", "owner": "candidate"}
    _control_calls, q_calls = configure_initializer(
        monkeypatch,
        helper,
        tmp_path,
        transaction=transaction,
        owner_alive=lambda _owner: next(alive),
    )
    persistent_starts: list[str] = []
    result = helper._ntpd_initialize_clock()
    if result == 0:
        persistent_starts.append("ntpd")

    assert result == 1
    assert q_calls
    assert persistent_starts == []
