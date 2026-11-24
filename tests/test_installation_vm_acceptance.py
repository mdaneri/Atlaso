"""Focused unit checks for release VM acceptance evidence and controls."""

import io
import json
import os
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.installation import vm_acceptance


def test_receipt_uses_the_ordered_prerelease_vm_check_contract():
    assert vm_acceptance.CHECKS == [
        "disconnected_uefi_install",
        "selected_64g_target",
        "media_free_boot",
        "atlaso_services_active",
        "installed_application_version",
        "installed_application_commit",
        "unselected_4g_disk_unchanged",
    ]


def test_credential_key_events_cover_shifted_and_unshifted_ascii():
    assert vm_acceptance.key_events("Atlaso 42!") == [
        ["shift", "a"], ["t"], ["l"], ["a"], ["s"], ["o"], ["spc"],
        ["4"], ["2"], ["shift", "1"],
    ]


def test_credential_key_events_refuse_unrepresentable_text():
    with pytest.raises(vm_acceptance.AcceptanceError):
        vm_acceptance.key_events("password-é")


def test_native_review_requires_exact_selected_disk_line_and_rejects_4g_suffix():
    assert vm_acceptance.REVIEW_DISK.findall("/dev/sda: QEMU Hard Disk 64 GiB") == ["64"]
    observed = "Confirn\nErase selected disks?\nfdeu/sda: QEMNU HARDDISK 64 GiB\nSerial/WWN: unavailable"
    assert vm_acceptance.REVIEW_DISK.findall(observed) == ["64"]
    assert vm_acceptance.REVIEW_DISK.findall(observed + "\n/dev/sdb: QEMU Hard Disk 4 GiB") == ["64", "4"]
    assert not vm_acceptance.REVIEW_DISK.search("/dev/sda: QEMU Hard Disk 164 GiB")


def test_native_disk_rows_include_model_before_the_capacity():
    text = "SO select a disk\nQENU HARDDISK — 64 GiB @ /deu/sda\nQENU HARDDISK — 4 GiB @ /deu/sdb"

    assert vm_acceptance.is_disk_selection_screen(text)
    assert [match.group(1) for match in vm_acceptance.DISK_ROW.finditer(text)] == ["64", "4"]


def test_concealed_credential_prompt_matches_the_expected_account_and_step():
    assert vm_acceptance.is_credential_prompt("Set admin passuord", "admin", False)
    assert vm_acceptance.is_credential_prompt("Confirn root password", "root", True)
    assert not vm_acceptance.is_credential_prompt("Set admin password", "root", False)
    assert not vm_acceptance.is_credential_prompt("Confirm admin password", "admin", False)


@pytest.mark.parametrize("compact_form", [True, False])
def test_acceptance_enters_passwords_in_the_recognized_installer_layout(tmp_path, monkeypatch, compact_form):
    """Keep acceptance compatible with existing signed media and the new form.

    Args:
        tmp_path: Directory for transient screenshot files.
        monkeypatch: Supplies synthetic OCR and observes concealed input steps.
        compact_form: Whether the installed media presents the new account form.
    """
    form = "Account passwords\nAdmin password\nConfirm admin password\nRoot password\nConfirm root password\nContinue"
    screens = iter([form] if compact_form else [
        "Set admin password", "Confirm admin password", "Set root password", "Confirm root password",
    ])
    events = []
    qmp = SimpleNamespace(send_key=lambda key: events.append(key))

    def wait_screen(_qmp, _output, predicate, _label, _seconds):
        """Make the harness verify the next simulated prompt.

        Args:
            _qmp: Fake QMP control connection.
            _output: Test screenshot path.
            predicate: Required OCR screen predicate.
            _label: Public checkpoint label.
            _seconds: Checkpoint time bound.
        """
        text = next(screens)
        assert predicate(text)
        return text

    monkeypatch.setattr(vm_acceptance, "wait_screen", wait_screen)
    monkeypatch.setattr(vm_acceptance, "type_text", lambda _qmp, value: events.append(value))

    vm_acceptance.enter_installer_passwords(qmp, tmp_path, {"admin": "fixture-one", "root": "fixture-two"})

    assert events == ["fixture-one", "fixture-one", "fixture-two", "fixture-two"] + (["ret"] if compact_form else [])


def test_media_free_probe_verifies_the_native_console_and_installed_metadata():
    assert vm_acceptance.installed_console_ready("Atlaso Appliance 1.0.0\n<F4> Console")
    assert vm_acceptance.installed_console_ready("Manage this appliance at:")
    assert not vm_acceptance.installed_console_ready("Atlaso Appliance Powered by Photon OS")
    login = "Welcome to Photon 5.0 (x86_64) (tty2)\natlaso login:"
    assert vm_acceptance.installed_login_prompt(login)
    assert not vm_acceptance.installed_login_prompt(login.replace("tty2", "tty1"))
    command = vm_acceptance.installed_identity_command("__build_git_commit__", "C")
    assert "a.__build_git_commit__==os.getenv" in command
    assert "True" not in command


@pytest.mark.parametrize("guest,reason,accepted", [(True, "guest-reset", True), (True, "guest-panic", False), (False, "host-signal", False)])
def test_installer_wait_accepts_only_the_guests_own_reset(tmp_path, monkeypatch, guest, reason, accepted):
    """Check that the installer must request its own reboot.

    Args:
        tmp_path: Directory for transient fixture files.
        monkeypatch: Fixture used to feed synthetic QMP replies.
        guest: Whether QEMU attributes the shutdown to the guest.
        reason: Reported QMP shutdown reason.
        accepted: Whether the shutdown completes the install checkpoint.
    """
    vm = object.__new__(vm_acceptance.Qmp)
    vm.stream = io.BytesIO()
    vm.guest_requested_reboot = False
    responses = iter([
        {"event": "SHUTDOWN", "data": {"guest": guest, "reason": reason}},
        {"event": "STOP"},
        {"return": {"status": "shutdown"}},
    ])
    monkeypatch.setattr(vm, "_read", lambda: next(responses))
    deadline = vm_acceptance.time.monotonic() + 1
    if accepted:
        vm_acceptance.wait_for_installer_reboot(vm, tmp_path, deadline)
    else:
        with pytest.raises(vm_acceptance.AcceptanceError, match="without a guest-requested reboot"):
            vm_acceptance.wait_for_installer_reboot(vm, tmp_path, deadline)


@pytest.mark.parametrize("timed_out", [True, False])
def test_unreadable_ocr_frame_waits_for_verified_checkpoint(tmp_path, monkeypatch, capsys, timed_out):
    """Accept only a readable matching frame after a transient OCR error.

    Args:
        tmp_path: Directory for transient screenshot files.
        monkeypatch: Fixture used to stub the console observer and clocks.
        capsys: Fixture that captures public checkpoint logs.
        timed_out: Simulate an OCR timeout or a nonzero OCR process exit.
    """
    frame = b"P6\n1 1\n255\n" + bytes(3)
    vm = object.__new__(vm_acceptance.Qmp)
    options = []

    def capture(command, arguments):
        """Write a one-pixel frame to the requested screenshot path.

        Args:
            command: QMP command name.
            arguments: QMP options containing the transient screenshot path.
        """
        assert command == "screendump"
        Path(arguments["filename"]).write_bytes(frame)

    def recognize(command, **kwargs):
        """Fail the first OCR read and recognize the following guest frame.

        Args:
            command: Arguments passed to the OCR subprocess.
            **kwargs: Subprocess execution options including the thread limit.
        """
        options.append(kwargs)
        if len(options) == 1:
            if timed_out:
                raise subprocess.TimeoutExpired(command, kwargs["timeout"], stderr=b"private frame output")
            return subprocess.CompletedProcess(command, 1, "Select a disk", "private frame output")
        return subprocess.CompletedProcess(command, 0, "Select a disk", "")

    monkeypatch.setattr(vm, "execute", capture)
    vm.process = SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(vm_acceptance.subprocess, "run", recognize)
    monkeypatch.setattr(vm_acceptance.time, "sleep", lambda _: None)

    assert vm_acceptance.wait_screen(vm, tmp_path, vm_acceptance.is_disk_selection_screen, "disk selection", 1)
    assert [call["env"]["OMP_THREAD_LIMIT"] for call in options] == ["1", "1"]
    assert not list(tmp_path.iterdir())
    assert "private frame output" not in capsys.readouterr().out


def test_ppm_preprocessing_crops_and_upscales_the_gray_installer_panel():
    width, height = 1280, 800
    pixels = bytearray((0, 0, 170) * width * height)
    for y in range(272, 504):
        for x in range(360, 912):
            offset = (y * width + x) * 3
            pixels[offset:offset + 3] = bytes((170, 170, 170))
    text_offset = (300 * width + 400) * 3
    pixels[text_offset:text_offset + 3] = bytes((0, 0, 0))
    raw = f"P6\n{width} {height}\n255\n".encode() + pixels

    prepared, cropped = vm_acceptance.preprocess_ppm(raw)

    assert cropped is True
    dimensions = re.match(rb"P6\n(\d+) (\d+)\n255\n", prepared)
    assert dimensions is not None
    assert tuple(map(int, dimensions.groups())) == (1728, 768)
    pixels_offset = dimensions.end()
    scaled_text_offset = pixels_offset + ((300 - 260) * 3 * 1728 + (400 - 348) * 3) * 3
    assert prepared[scaled_text_offset:scaled_text_offset + 3] == bytes((0, 0, 0))


def test_ppm_preprocessing_keeps_non_dialog_frame_for_sparse_grub_ocr():
    width, height = 80, 25
    pixels = bytes((0, 0, 0) * width * height)
    raw = f"P6\n{width} {height}\n255\n".encode() + pixels

    prepared, cropped = vm_acceptance.preprocess_ppm(raw)

    assert cropped is False
    dimensions = re.match(rb"P6\n(\d+) (\d+)\n255\n", prepared)
    assert dimensions is not None
    assert tuple(map(int, dimensions.groups())) == (160, 50)


def test_fixture_intent_binds_a_new_output_directory_to_release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Bind the VM directory's recorded identity to the release under test.

    Args:
        tmp_path: Directory that contains an isolated fixture root.
        monkeypatch: Fixture used to provide the task and repository environment.
    """
    output = tmp_path / "new-vm"
    output.mkdir()
    receipt = tmp_path / "receipt.json"
    monkeypatch.setenv("GITHUB_REPOSITORY", "mdaneri/Atlaso")

    intent = vm_acceptance.fixture_intent(output, receipt, "1.0.0", "a" * 40, "b" * 64)

    assert intent["repository"] == "mdaneri/Atlaso"
    assert intent["commit"] == "a" * 40
    assert intent["iso_sha256"] == "b" * 64
    assert intent["output_identity"] == {
        "device": output.stat().st_dev,
        "inode": output.stat().st_ino,
    }
    assert intent["receipt"] == str(receipt)


def test_final_receipt_is_new_and_contains_only_public_acceptance_fields(tmp_path: Path):
    """Verify exclusive receipt creation and the public evidence schema.

    Args:
        tmp_path: Directory that contains the fixture receipt.
    """
    receipt = tmp_path / "receipt.json"
    value = {
        "schema": 1,
        "version": "1.0.0",
        "commit": "a" * 40,
        "iso_sha256": "b" * 64,
        "checks": vm_acceptance.CHECKS,
    }

    vm_acceptance.write_new_json(receipt, value)

    assert json.loads(receipt.read_text()) == value
    assert receipt.stat().st_mode & 0o777 == 0o600 if os.name != "nt" else True
    with pytest.raises(FileExistsError):
        vm_acceptance.write_new_json(receipt, value)


def test_service_checks_require_current_unambiguous_replies(monkeypatch, tmp_path):
    """Ignore stale replies and require one state for the current poll.

    Args:
        monkeypatch: Fixture that replaces console input and OCR.
        tmp_path: Directory representing the VM fixture.
    """
    evidence = vm_acceptance.FailureEvidence()
    commands = []
    frames = iter([
        ("APP 2 active", "APP 1 activating"),
        ("APP 1 active", "APP 2 inactive\nAPP 2 active"),
        ("APP 3 ACTIVE",),
        ("APP 3 active", "WORKER 1 active"),
    ])
    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda _qmp, command: commands.append(command))
    monkeypatch.setattr(vm_acceptance.time, "sleep", lambda _seconds: None)

    def wait_screen(_qmp, _output, predicate, _label, _seconds):
        """Match the current frame and reject every stale frame.

        Args:
            _qmp: Unused control connection.
            _output: Unused fixture directory.
            predicate: Matcher for the current request.
            _label: Unused checkpoint label.
            _seconds: Unused checkpoint budget.
        """
        *stale, current = next(frames)
        assert all(not predicate(frame) for frame in stale)
        assert predicate(current)
        return current

    monkeypatch.setattr(vm_acceptance, "wait_screen", wait_screen)
    vm_acceptance.check_installed_services(object(), tmp_path, evidence)

    assert evidence.service_states == {
        "atlaso.service": ["activating", "ambiguous", "active"],
        "atlaso-worker.service": ["active"],
    }
    assert "WORKER 1 %s" in commands[-1]


def test_service_timeout_keeps_gate_closed_and_collects_evidence(monkeypatch, tmp_path):
    """Collect diagnostics after the deadline without admitting a success receipt.

    Args:
        monkeypatch: Fixture that controls the clock and mimics unrecognized console replies.
        tmp_path: Directory representing the VM fixture.
    """
    evidence = vm_acceptance.FailureEvidence()
    clock = iter([0, 0, 15, 150, 150])
    collected = []
    monkeypatch.setattr(vm_acceptance, "time", SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _: None))
    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda *_: None)

    def wait_screen(*_):
        """Simulate a console reply that OCR cannot recognize.

        Args:
            *_: Unused console wait arguments.
        """
        raise vm_acceptance.ScreenTimeout("unrecognized")

    monkeypatch.setattr(vm_acceptance, "wait_screen", wait_screen)
    monkeypatch.setattr(vm_acceptance, "collect_service_failure", lambda _vm, _out, unit, _: collected.append(unit))
    with pytest.raises(vm_acceptance.AcceptanceError, match="atlaso.service did not become active"):
        vm_acceptance.check_installed_services(object(), tmp_path, evidence)

    assert evidence.service_states == {"atlaso.service": ["unrecognized"]}
    assert collected == ["atlaso.service"]


@pytest.mark.parametrize(("version", "probes_required"), [("0.9.522", False), ("0.9.523", True), ("1.0.0", True)])
def test_acceptance_exercises_network_diagnostics_from_the_first_shipping_version(
    monkeypatch, tmp_path, version, probes_required,
):
    """Apply the network probe requirement only to versions that ship it.

    Args:
        monkeypatch: Fixture that supplies synthetic console replies.
        tmp_path: Directory representing the VM fixture.
        version: Installed version to verify.
        probes_required: Whether this version must exercise the network probes.
    """
    observed = []
    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda *_: None)
    monkeypatch.setattr(vm_acceptance, "check_installed_services", lambda *_: observed.append("services"))

    def wait_screen(_qmp, _output, predicate, label, _seconds):
        """Supply the correct recognized frame for the current checkpoint.

        Args:
            _qmp: Unused control connection.
            _output: Unused fixture directory.
            predicate: Matcher for the current request.
            label: Checkpoint used to choose a synthetic reply.
            _seconds: Unused checkpoint budget.
        """
        observed.append(label)
        response = "PROBES-OK" if label == "installed network diagnostics" else "True"
        assert predicate(response)
        return response

    monkeypatch.setattr(vm_acceptance, "wait_screen", wait_screen)
    vm_acceptance.check_installed_application(object(), tmp_path, version, "a" * 40, vm_acceptance.FailureEvidence())

    expected = ["installed Atlaso version", "installed Atlaso source commit", "services"]
    if probes_required:
        expected.append("installed network diagnostics")
    assert observed == expected


def test_failed_acceptance_only_seals_allowlisted_evidence(monkeypatch, tmp_path, capsys):
    """Write sanitized failure evidence and withhold the success receipt.

    Args:
        monkeypatch: Fixture that supplies synthetic service and journal diagnostics.
        tmp_path: Directory that contains the acceptance and diagnostic destinations.
        capsys: Fixture used to check public stdout and stderr.
    """
    receipt = tmp_path / "vm-acceptance.json"
    iso = tmp_path / "exact.iso"
    password = "sensitive-fixture-value"
    monkeypatch.setattr(vm_acceptance.sys, "argv", [
        "vm_acceptance", "--iso", str(iso), "--output", str(tmp_path / "fixture"),
        "--receipt", str(receipt), "--version", "0.9.522", "--commit", "a" * 40, "--sha256", "b" * 64,
    ])
    monkeypatch.setattr(vm_acceptance, "require_inputs", lambda _: (
        iso, tmp_path, receipt, tmp_path / "intent.json", {"admin": password, "root": password},
    ))
    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda *_: None)
    frames = iter([
        f"atlaso.service failed\natlaso-bootstrap-https.service inactive\nsecret.service failed\n"
        f"Result=exit-code\nExecMainStatus=203\n{password}\nUNITS DONE",
        f"{password}\nPermission denied\nNo space left on device: {password}\nJOURNAL 0",
    ])

    def wait_screen(_qmp, _output, predicate, _label, _seconds):
        """Supply a synthetic diagnostic frame with recognizable and untrusted text.

        Args:
            _qmp: Unused control connection.
            _output: Unused fixture directory.
            predicate: Matcher for the diagnostic completion marker.
            _label: Unused checkpoint label.
            _seconds: Unused checkpoint budget.
        """
        frame = next(frames)
        assert predicate(frame)
        return frame

    def failed_install(_iso, output, _args, _passwords, evidence):
        """Simulate a failed service check after the disk-only boot.

        Args:
            _iso: Unused installer image.
            output: Directory representing the VM fixture.
            _args: Unused installer arguments.
            _passwords: Unused concealed credentials.
            evidence: Record populated by the diagnostic functions.
        """
        assert not vm_acceptance.observe_boot_console(f"{password}\nA start job is running", evidence)
        evidence.checkpoint = "atlaso.service active"
        evidence.record_state("atlaso.service", "failed")
        vm_acceptance.collect_service_failure(object(), output, "atlaso.service", evidence)
        raise vm_acceptance.AcceptanceError("service activation failed")

    monkeypatch.setattr(vm_acceptance, "wait_screen", wait_screen)
    monkeypatch.setattr(vm_acceptance, "install", failed_install)
    assert vm_acceptance.main() == 1
    assert not receipt.exists()
    raw = vm_acceptance.failure_path(receipt).read_text()
    record = json.loads(raw)
    assert record["kind"] == "atlaso-vm-acceptance-failure"
    assert record["commit"] == "a" * 40
    assert record["iso_sha256"] == "b" * 64
    assert record["checkpoint"] == "atlaso.service active"
    assert record["boot_screen"] == "linux_startup"
    assert record["units"] == {"atlaso.service": "failed", "atlaso-bootstrap-https.service": "inactive"}
    assert record["unit_result"] == "exit-code"
    assert record["exec_main_status"] == 203
    assert record["journal_signals"] == ["permission_denied"]
    assert "checks" not in record
    assert password not in raw
    captured = capsys.readouterr()
    assert "atlaso.service state: failed" in captured.out
    assert password not in captured.out + captured.err
