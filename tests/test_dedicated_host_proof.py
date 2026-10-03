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
EXECUTABLE = r"C:\Program Files\VMware\vmware-vmx.exe"
MAC = "00:50:56:aa:bb:01"


def _expected() -> dict[str, list[dict[str, Any]]]:
    return {VMX: [{"index": 0, "connection_type": "pvn", "network_id": "segment-id", "mac": MAC}]}


def _process(pid: int = 101) -> dict[str, Any]:
    return {"pid": pid, "creation_time": "2026-10-03T10:00:00Z", "vmx_path": VMX,
            "executable": EXECUTABLE}


def _install_collector_mocks(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    runtime_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(proof, "process_inventory", lambda _powershell: [_process()])

    def bounded(arguments: list[str]) -> str:
        if arguments[-1] == "list":
            return "Total running VMs: 1\n" + VMX
        raise AssertionError("unexpected provider command")

    def runtime(_vmrun: Path, vmx: str, key: str) -> str:
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
    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = BytesIO(stdout)
            self.stderr = BytesIO(stderr)
            self.returncode = returncode
            self.killed = False

        def wait(self, timeout: float) -> int:
            assert timeout == 20
            if wait_error is not None:
                raise wait_error
            return self.returncode

        def kill(self) -> None:
            self.killed = True

    @contextmanager
    def contained(_arguments: list[str], _cwd: Path, _env: dict[str, str]):
        yield FakeProcess()

    monkeypatch.setattr(proof, "contained_child", contained)


def test_collects_complete_runtime_snapshot_and_brackets_process_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime_calls = _install_collector_mocks(monkeypatch)
    process_calls: list[Path] = []
    monkeypatch.setattr(proof, "process_inventory", lambda path: (process_calls.append(path) or [_process()]))

    result = proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)

    assert result["claim"] == "validated-observation-only"
    assert result["exclusive_membership"] is False
    assert len(result["adapters"]) == 10
    assert result["adapters"][0]["network_id"] == "segment-id"
    assert len(process_calls) == 2
    assert process_calls == [POWERSHELL, POWERSHELL]
    assert len(runtime_calls) == 10 + 4


def test_missing_command_line_identity_stops_before_runtime_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime_calls: list[str] = []
    monkeypatch.setattr(proof, "process_inventory", lambda _path: (_ for _ in ()).throw(
        Refusal("host_process_identity_unavailable")))
    monkeypatch.setattr(proof, "bounded_command", lambda _args: "Total running VMs: 1\n" + VMX)
    monkeypatch.setattr(proof, "runtime_value", lambda *_args: runtime_calls.append("read") or "TRUE")

    with pytest.raises(Refusal, match="host_process_identity_unavailable"):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)
    assert runtime_calls == []


def test_unexpected_vm_inventory_stops_before_runtime_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_collector_mocks(monkeypatch)
    runtime_calls: list[str] = []
    monkeypatch.setattr(proof, "process_inventory", lambda _path: [_process()])
    monkeypatch.setattr(proof, "bounded_command", lambda _args: "Total running VMs: 2\n" + VMX + "\nE:\\lab\\other.vmx")
    monkeypatch.setattr(proof, "runtime_value", lambda *_args: runtime_calls.append("read") or "TRUE")

    with pytest.raises(Refusal, match="unexpected_running_vm"):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)
    assert runtime_calls == []


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
    _install_collector_mocks(monkeypatch)
    original_runtime = proof.runtime_value

    def runtime(vmrun: Path, vmx: str, key: str) -> str:
        if key == f"ethernet0.{field}":
            return value
        return original_runtime(vmrun, vmx, key)

    monkeypatch.setattr(proof, "runtime_value", runtime)
    with pytest.raises(Refusal, match=reason):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)


def test_runtime_absence_for_enrolled_slot_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime_calls = _install_collector_mocks(monkeypatch)
    original_runtime = proof.runtime_value

    def runtime(vmrun: Path, vmx: str, key: str) -> str:
        runtime_calls.append((vmx, key))
        return "FALSE" if key == "ethernet0.present" else original_runtime(vmrun, vmx, key)

    monkeypatch.setattr(proof, "runtime_value", runtime)
    with pytest.raises(Refusal, match="runtime_expected_adapter_unavailable"):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)
    assert (VMX, "ethernet0.present") in runtime_calls


def test_absent_runtime_slot_conflicts_with_saved_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_collector_mocks(monkeypatch)
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: 'ethernet0.present = "TRUE"\nethernet7.address = "00:50:56:aa:bb:77"\n')
    with pytest.raises(Refusal, match="runtime_expected_adapter_unavailable"):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)


def test_empty_runtime_absence_is_accepted_only_when_vmx_has_no_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_collector_mocks(monkeypatch)
    monkeypatch.setattr(Path, "read_text", lambda _self, **_kwargs: "")
    result = proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)
    assert len(result["adapters"]) == 10
    assert result["adapters"][1]["present"] is False


def test_pid_restart_during_runtime_reads_refuses_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_collector_mocks(monkeypatch)
    inventories = iter([[_process(101)], [_process(202)]])
    monkeypatch.setattr(proof, "process_inventory", lambda _path: next(inventories))

    with pytest.raises(Refusal, match="host_process_inventory_changed"):
        proof.collect_snapshot(_expected(), VMRUN, POWERSHELL)


def test_contained_process_failure_hides_provider_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_child_mock(monkeypatch, stdout=b"secret stdout", stderr=b"secret stderr",
                        wait_error=OSError("secret process diagnostic"))
    with pytest.raises(Refusal) as caught:
        proof.bounded_command(["provider"])
    assert str(caught.value) == "host_provider_unavailable"
    assert "secret" not in str(caught.value)


def test_nonzero_bounded_command_hides_provider_output(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_child_mock(monkeypatch, stdout=b"private stdout", stderr=b"private stderr", returncode=1)
    with pytest.raises(Refusal) as caught:
        proof.bounded_command(["provider"])
    assert str(caught.value) == "host_provider_read_refused"
    assert "private" not in str(caught.value)


def test_bounded_command_returns_only_successful_public_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_child_mock(monkeypatch, stdout=b"public output\n", stderr=b"private diagnostic")
    assert proof.bounded_command(["provider"]) == "public output"


def test_bounded_command_timeout_hides_captured_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_child_mock(monkeypatch, stdout=b"secret stdout", stderr=b"secret stderr",
                        wait_error=proof.subprocess.TimeoutExpired(["provider", "secret-argument"], 20,
                                                                  output=b"secret stdout", stderr=b"secret stderr"))
    with pytest.raises(Refusal) as caught:
        proof.bounded_command(["provider"])
    assert str(caught.value) == "host_provider_unavailable"
    assert "secret" not in str(caught.value)


def test_guard_failure_releases_every_entered_file_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    released: list[str] = []

    class FakeWindowsFiles:
        @contextmanager
        def ancestors(self, path: Path):
            try:
                yield
            finally:
                released.append(f"ancestors:{path}")

        @contextmanager
        def opened(self, path: Path):
            try:
                yield
            finally:
                released.append(f"opened:{path}")

    monkeypatch.setattr(proof, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(proof, "WindowsFiles", FakeWindowsFiles)
    reads = 0

    def collect(*_args: object) -> dict[str, Any]:
        nonlocal reads
        reads += 1
        if reads == 1:
            return {"contract": "baseline"}
        raise Refusal("host_snapshot_changed")

    monkeypatch.setattr(proof, "collect_snapshot", collect)
    guard = proof.DedicatedHostProof(_expected(), VMRUN, POWERSHELL)

    with pytest.raises(Refusal, match="host_snapshot_changed"):
        guard.__enter__()

    assert len(released) == 6
    assert guard.baseline is not None
