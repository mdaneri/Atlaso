"""Focused tests for the bounded dedicated-host collector and pin guard."""

from __future__ import annotations

from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.interop import dedicated_host_proof as proof
from scripts.interop.dedicated_host_contract import Refusal

VMX = r"E:\lab\appliance.vmx"
VMRUN = Path(r"C:\Program Files\VMware\vmrun.exe")
POWERSHELL = Path(r"C:\Program Files\PowerShell\7\pwsh.exe")
MAC = "00:50:56:aa:bb:01"


def _expected() -> dict[str, list[dict[str, Any]]]:
    return {VMX: [{"index": 0, "connection_type": "pvn", "network_id": "segment-id", "mac": MAC}]}


def _install_collector_mocks(
    monkeypatch: pytest.MonkeyPatch, running_inventories: list[list[str]] | None = None,
) -> list[tuple[str, str]]:
    """Stub bounded host reads and record runtime adapter queries.

    Args:
        monkeypatch: Pytest fixture replacing collector boundaries.
        running_inventories: Optional provider inventory rows for consecutive reads.
    """
    runtime_calls: list[tuple[str, str]] = []
    list_calls: list[None] = []
    inventories = running_inventories or [[VMX], [VMX]]

    def bounded(arguments: list[str]) -> str:
        """Return a synthetic inventory for each bracket edge.

        Args:
            arguments: Provider executable and fixed command arguments.
        """
        if arguments[-1] == "list":
            index = len(list_calls)
            list_calls.append(None)
            paths = inventories[min(index, len(inventories) - 1)]
            return f"Total running VMs: {len(paths)}\n" + "\n".join(paths)
        raise AssertionError("unexpected provider command")

    def runtime(_vmrun: Path, vmx: str, key: str) -> str:
        """Return the fixture's runtime adapter values.

        Args:
            _vmrun: Pinned VMware command path supplied by the collector.
            vmx: VMX path whose adapter value is read.
            key: Runtime configuration key requested by the collector.
        """
        runtime_calls.append((vmx, key))
        index = int(key.removeprefix("ethernet").split(".")[0])
        field = key.split(".", 1)[1]
        if index != 0:
            return "FALSE" if field == "present" else ""
        return {
            "present": "TRUE", "connectionType": "pvn", "pvnID": "segment-id",
            "address": MAC, "startConnected": "TRUE",
        }.get(field, "")

    monkeypatch.setattr(proof, "bounded_command", bounded)
    monkeypatch.setattr(proof, "runtime_value", runtime)
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: 'ethernet0.present = "TRUE"\n')
    return runtime_calls


def _install_child_mock(monkeypatch: pytest.MonkeyPatch, *, stdout: bytes = b"", stderr: bytes = b"",
                        returncode: int = 0, wait_error: Exception | None = None) -> None:
    """Replace the contained-child boundary with a bounded synthetic process.

    Args:
        monkeypatch: Pytest fixture replacing the child runner.
        stdout: Bytes made available on the child's standard output.
        stderr: Bytes made available on the child's standard error.
        returncode: Terminal status returned by the synthetic process.
        wait_error: Optional failure raised while waiting for process completion.
    """
    class FakeProcess:
        def __init__(self) -> None:
            """Initialize in-memory pipes and a fixed process outcome."""
            self.stdout = BytesIO(stdout)
            self.stderr = BytesIO(stderr)
            self.returncode = returncode
            self.killed = False

        def wait(self, timeout: float) -> int:
            """Return or raise the configured result after a bounded wait.

            Args:
                timeout: Maximum wait selected by the collector.
            """
            assert timeout == 20
            if wait_error is not None:
                raise wait_error
            return self.returncode

        def kill(self) -> None:
            """Record termination requested after an output bound is exceeded."""
            self.killed = True

    @contextmanager
    def contained(_arguments: list[str], _cwd: Path, _env: dict[str, str]):
        """Yield a fake child under the collector's containment interface.

        Args:
            _arguments: Executable and arguments passed to the child runner.
            _cwd: Working directory selected for the child.
            _env: Sanitized child environment.
        """
        yield FakeProcess()

    monkeypatch.setattr(proof, "contained_child", contained)


def test_collects_complete_runtime_snapshot_without_host_process_census(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept all slots using only bracketed enrolled provider observations.

    Args:
        monkeypatch: Pytest fixture replacing host provider reads.
    """
    runtime_calls = _install_collector_mocks(monkeypatch)

    result = proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)

    assert result["contract"] == "fixture-stable-observation-v1"
    assert result["claim"] == "enrolled-fixture-observations-only"
    assert "exclusive_membership" not in result
    assert result["running_vm_paths"] == [VMX]
    assert len(result["adapters"]) == 10
    assert result["adapters"][0]["network_id"] == "segment-id"
    assert len(runtime_calls) == 10 + 4


def test_unreadable_os_process_identity_is_not_a_collector_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collect fixture evidence without querying host process command lines.

    Args:
        monkeypatch: Pytest fixture replacing provider and runtime boundaries.
    """
    runtime_calls = _install_collector_mocks(monkeypatch)
    assert not hasattr(proof, "process_inventory")
    assert proof.collect_snapshot(_expected(), VMRUN, Path("unavailable-powershell.exe"))["adapters"]
    assert runtime_calls


def test_unrelated_vm_inventory_changes_do_not_refuse_fixture_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ignore unrelated provider VM entries while bracketing enrolled VMXs.

    Args:
        monkeypatch: Pytest fixture replacing host provider reads.
    """
    runtime_calls = _install_collector_mocks(
        monkeypatch, [[VMX, r"E:\lab\other-a.vmx"], [r"E:\lab\other-b.vmx", VMX]],
    )

    result = proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)

    assert result["running_vm_paths"] == [VMX]
    assert len(runtime_calls) == 14


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [("connectionType", "", "adapter_configuration_invalid"),
     ("pvnID", "", "adapter_configuration_invalid"),
     ("address", "", "adapter_mac_invalid"),
     ("startConnected", "", "expected_adapter_not_start_connected")],
)
def test_blank_live_network_or_mac_refuses_snapshot(
    monkeypatch: pytest.MonkeyPatch, field: str, value: str, reason: str,
) -> None:
    """Reject blank live values for an enrolled provider adapter.

    Args:
        monkeypatch: Pytest fixture replacing runtime configuration reads.
        field: Runtime configuration field forced to an empty value.
        value: Replacement runtime value.
        reason: Expected fixed refusal category.
    """
    _install_collector_mocks(monkeypatch)
    original_runtime = proof.runtime_value

    def runtime(vmrun: Path, vmx: str, key: str) -> str:
        """Replace one selected runtime value and delegate all other reads.

        Args:
            vmrun: Provider executable passed to the original runtime reader.
            vmx: VMX path passed to the original runtime reader.
            key: Runtime configuration key currently being read.
        """
        if key == f"ethernet0.{field}":
            return value
        return original_runtime(vmrun, vmx, key)

    monkeypatch.setattr(proof, "runtime_value", runtime)
    with pytest.raises(Refusal, match=reason):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)


def test_runtime_absence_for_enrolled_slot_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse a runtime-absent adapter present in independent enrollment.

    Args:
        monkeypatch: Pytest fixture replacing runtime provider reads.
    """
    runtime_calls = _install_collector_mocks(monkeypatch)
    original_runtime = proof.runtime_value

    def runtime(vmrun: Path, vmx: str, key: str) -> str:
        """Report the enrolled NIC absent and delegate other runtime values.

        Args:
            vmrun: Provider executable passed to the original runtime reader.
            vmx: VMX path passed to the original runtime reader.
            key: Runtime configuration key currently being read.
        """
        runtime_calls.append((vmx, key))
        return "FALSE" if key == "ethernet0.present" else original_runtime(vmrun, vmx, key)

    monkeypatch.setattr(proof, "runtime_value", runtime)
    with pytest.raises(Refusal, match="runtime_expected_adapter_unavailable"):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)
    assert (VMX, "ethernet0.present") in runtime_calls


def test_absent_runtime_slot_conflicts_with_saved_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse a runtime-absent adapter whose saved VMX still describes it.

    Args:
        monkeypatch: Pytest fixture replacing the pinned VMX text read.
    """
    _install_collector_mocks(monkeypatch)
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: 'ethernet0.present = "TRUE"\nethernet7.address = "00:50:56:aa:bb:77"\n')
    with pytest.raises(Refusal, match="runtime_expected_adapter_unavailable"):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)


def test_empty_runtime_absence_is_accepted_only_when_vmx_has_no_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept an empty runtime absence only when persistent config has no slot.

    Args:
        monkeypatch: Pytest fixture replacing provider and VMX reads.
    """
    _install_collector_mocks(monkeypatch)
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: "")
    result = proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)
    assert len(result["adapters"]) == 10
    assert result["adapters"][1]["present"] is False


def test_explicitly_disabled_slots_require_matching_saved_and_runtime_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept explicitly disabled slots only when both observations say FALSE.

    Args:
        monkeypatch: Pytest fixture replacing provider and pinned VMX reads.
    """
    _install_collector_mocks(monkeypatch)
    saved = ('ethernet0.present = "TRUE"\n'
             'ethernet2.present = "FALSE"\n'
             'ethernet3.present = "FALSE"\n')
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: saved)

    result = proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)
    rows = {row["index"]: row for row in result["adapters"]}

    assert rows[2]["present"] is False
    assert rows[3]["present"] is False


@pytest.mark.parametrize(
    "saved",
    [
        'ethernet0.present = "TRUE"\nethernet2.present = "TRUE"\n',
        'ethernet0.present = "TRUE"\nethernet2.present = "FALSE"\nethernet2.present = "FALSE"\n',
        'ethernet0.present = "TRUE"\nethernet2.address = "00:50:56:aa:bb:02"\n',
    ],
    ids=["saved-true", "duplicate-present", "missing-present"],
)
def test_disabled_runtime_slot_rejects_ambiguous_saved_configuration(
    monkeypatch: pytest.MonkeyPatch, saved: str,
) -> None:
    """Refuse disabled runtime slots without exactly one saved FALSE declaration.

    Args:
        monkeypatch: Pytest fixture replacing provider and pinned VMX reads.
        saved: VMX content containing a conflicting or incomplete slot declaration.
    """
    _install_collector_mocks(monkeypatch)
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: saved)

    with pytest.raises(Refusal):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)


def test_disabled_saved_slot_rejects_blank_runtime_presence(monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse a saved disabled adapter when runtime presence cannot confirm FALSE.

    Args:
        monkeypatch: Pytest fixture replacing runtime configuration reads.
    """
    _install_collector_mocks(monkeypatch)
    saved = 'ethernet0.present = "TRUE"\nethernet2.present = "FALSE"\n'
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: saved)
    original_runtime = proof.runtime_value

    def runtime(vmrun: Path, vmx: str, key: str) -> str:
        """Return empty for the disabled slot and delegate other runtime reads.

        Args:
            vmrun: Provider executable passed to the original runtime reader.
            vmx: VMX path passed to the original runtime reader.
            key: Runtime configuration key currently being read.
        """
        if key == "ethernet2.present":
            return ""
        return original_runtime(vmrun, vmx, key)

    monkeypatch.setattr(proof, "runtime_value", runtime)
    with pytest.raises(Refusal):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)


def test_enrolled_vm_disappearing_between_provider_reads_refuses_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse an enrolled VMX that disappears during runtime collection.

    Args:
        monkeypatch: Pytest fixture replacing provider inventory reads.
    """
    _install_collector_mocks(monkeypatch, [[VMX], [r"E:\lab\unrelated.vmx"]])

    with pytest.raises(Refusal, match="enrolled_vm_not_running"):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)


def test_runtime_configuration_change_away_from_enrollment_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse a runtime adapter value that no longer matches enrollment.

    Args:
        monkeypatch: Pytest fixture replacing provider and runtime reads.
    """
    _install_collector_mocks(monkeypatch)
    proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)
    original_runtime = proof.runtime_value

    def changed_runtime(vmrun: Path, vmx: str, key: str) -> str:
        """Change the enrolled network identifier and preserve other values.

        Args:
            vmrun: Pinned provider executable passed to the original reader.
            vmx: Enrolled VMX path passed to the original reader.
            key: Runtime configuration key requested by the collector.
        """
        if key == "ethernet0.pvnID":
            return "different-segment"
        return original_runtime(vmrun, vmx, key)

    monkeypatch.setattr(proof, "runtime_value", changed_runtime)
    with pytest.raises(Refusal, match="expected_adapter_mismatch"):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)


def test_contained_process_failure_hides_provider_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanitize process-launch diagnostics from the bounded-command refusal.

    Args:
        monkeypatch: Pytest fixture replacing the contained child process.
    """
    _install_child_mock(monkeypatch, stdout=b"secret stdout", stderr=b"secret stderr",
                        wait_error=OSError("secret process diagnostic"))
    with pytest.raises(Refusal) as caught:
        proof.bounded_command(["provider"])
    assert str(caught.value) == "host_provider_unavailable"
    assert "secret" not in str(caught.value)


def test_nonzero_bounded_command_hides_provider_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not include either provider output stream in a nonzero refusal.

    Args:
        monkeypatch: Pytest fixture replacing the contained child process.
    """
    _install_child_mock(monkeypatch, stdout=b"private stdout", stderr=b"private stderr", returncode=1)
    with pytest.raises(Refusal) as caught:
        proof.bounded_command(["provider"])
    assert str(caught.value) == "host_provider_read_refused"
    assert "private" not in str(caught.value)


def test_bounded_command_returns_only_successful_public_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return successful public stdout while discarding child stderr.

    Args:
        monkeypatch: Pytest fixture replacing the contained child process.
    """
    _install_child_mock(monkeypatch, stdout=b"public output\n", stderr=b"private diagnostic")
    assert proof.bounded_command(["provider"]) == "public output"


def test_bounded_command_timeout_hides_captured_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanitize all timeout diagnostics from the contained process.

    Args:
        monkeypatch: Pytest fixture replacing the contained child process.
    """
    _install_child_mock(monkeypatch, stdout=b"secret stdout", stderr=b"secret stderr",
                        wait_error=proof.subprocess.TimeoutExpired(["provider", "secret-argument"], 20,
                                                                  output=b"secret stdout", stderr=b"secret stderr"))
    with pytest.raises(Refusal) as caught:
        proof.bounded_command(["provider"])
    assert str(caught.value) == "host_provider_unavailable"
    assert "secret" not in str(caught.value)


def test_guard_failure_releases_every_entered_file_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Release all opened file pins when the second proof observation fails.

    Args:
        monkeypatch: Pytest fixture replacing the platform and file-pin boundaries.
    """
    released: list[str] = []

    class FakeWindowsFiles:
        @contextmanager
        def ancestors(self, path: Path):
            """Track release of a synthetic path-ancestor pin.

            Args:
                path: Executable or VMX path whose ancestors would be pinned.
            """
            try:
                yield
            finally:
                released.append(f"ancestors:{path}")

        @contextmanager
        def opened(self, path: Path):
            """Track release of a synthetic file pin.

            Args:
                path: Executable or VMX path pinned by the proof guard.
            """
            try:
                yield
            finally:
                released.append(f"opened:{path}")

    monkeypatch.setattr(proof, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(proof, "WindowsFiles", FakeWindowsFiles)
    reads = 0

    def collect(*_args: object) -> dict[str, Any]:
        """Succeed admission once, then refuse the bracket check.

        Args:
            *_args: Expected snapshot collector arguments.
        """
        nonlocal reads
        reads += 1
        if reads == 1:
            return {"contract": "baseline"}
        raise Refusal("host_snapshot_changed")

    monkeypatch.setattr(proof, "collect_snapshot", collect)
    guard = proof.DedicatedHostProof(_expected(), VMRUN, POWERSHELL)

    with pytest.raises(Refusal, match="host_snapshot_changed"):
        guard.__enter__()

    assert len(released) == 4
    assert guard.baseline is not None
    assert all(str(POWERSHELL) not in entry for entry in released)
