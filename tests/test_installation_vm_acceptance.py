"""Focused unit checks for release VM acceptance evidence and controls."""

import base64
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


def test_combined_storage_layout_requires_all_assignments_and_mounts():
    screen = """Storage layout
Root installation target
Mount: /
Volume: /dev/sda (64 GiB) - Auto
SFTP backup storage
Mount: /mnt/atlaso-vcf-backups
Volume: shared
VCFDT depot storage
Mount: /mnt/atlaso-vcf-offline-depot
Volume: shared"""

    assert vm_acceptance.is_combined_storage_layout_screen(screen)
    incomplete = screen.replace("Mount: /mnt/atlaso-vcf-offline-depot", "")
    assert not vm_acceptance.is_combined_storage_layout_screen(incomplete)
    assert not vm_acceptance.is_storage_layout_or_legacy_choice(incomplete)
    assert vm_acceptance.is_combined_storage_layout_screen(screen.replace("Auto", "Custom"))
    bordered = screen.replace("Storage layout", "x Storage layout x").replace(
        "Root installation target", "x Root installation target x",
    ).replace("Mount:", "x Mount:").replace("Volume:", "x Volume:").replace(
        "SFTP backup storage", "x SFTP backup storage x",
    ).replace("VCFDT depot storage", "x VCFDT depot storage x")
    assert vm_acceptance.is_combined_storage_layout_screen(bordered)
    missing_root_mount = screen.replace("Mount: /\nVolume:", "Mount: /mnt/elsewhere\nVolume:")
    assert not vm_acceptance.is_combined_storage_layout_screen(missing_root_mount)


def test_storage_ocr_recovers_highlight_without_accepting_wrong_assignments(tmp_path, monkeypatch):
    """Replay recognized text from the signed installer with the root row highlighted.

    Args:
        tmp_path: Directory for the transient frame and its OCR input.
        monkeypatch: Supplies the captured text for each pass through OCR.
    """
    recovered = """storage layout
Root installation target
Mount: +
Volume: /dev/sda (64 GiB) - Auto
SFTP backup storage
Mount: /mnt-/at laso-ucf-backups
Volume: Shared storage on /devu-/sda
VCFDT depot storage
Mount: /mnt-at laso-ucf—-offline-depot
Volume: Shared storage on /devu-/sda
"""
    frame = b"P6\n1 1\n255\n" + bytes(3)
    vm = object.__new__(vm_acceptance.Qmp)
    monkeypatch.setattr(vm, "execute", lambda _, args: Path(args["filename"]).write_bytes(frame))
    responses = iter((recovered.replace("Volume: /dev/sda (64 GiB) - Auto\n", ""), recovered))
    monkeypatch.setattr(
        vm_acceptance.subprocess, "run",
        lambda cmd, **_: subprocess.CompletedProcess(cmd, 0, next(responses), ""),
    )

    observed = vm_acceptance.screen_text(vm, tmp_path)
    assert observed == recovered
    assert vm_acceptance.initial_installer_screen(observed)
    assert vm_acceptance.storage_layout_root_disk(observed) == "/dev/sda"
    assert not vm_acceptance.initial_installer_screen(recovered.replace("ucf-backups", "ucf-depot"))
    assert not vm_acceptance.initial_installer_screen(recovered.replace("Mount: +", "Mount: /other"))
    assert not list(tmp_path.iterdir())


def test_storage_preprocessing_restores_reversed_glyphs():
    """Keep selected text dark while clearing its reverse-video background."""
    rows = [bytearray(120) for _ in range(16)]
    for y in range(3, 13):
        rows[y][20:90] = bytes([1]) * 70
    rows[8][32] = 0
    rows[8][100] = 1

    vm_acceptance.restore_highlighted_text(rows)

    assert rows[8][31:34] == bytes([0, 1, 0])
    assert rows[8][100] == 1


def test_storage_acceptance_advances_through_combined_layout_once(monkeypatch):
    """Verify the combined page keeps Custom editing nondestructive.

    Args:
        monkeypatch: Replaces screen polling with bounded public fixture frames.
    """
    screen = """Storage layout
Root installation target
Mount: /
Volume: /dev/sda (64 GiB) - Auto
SFTP backup storage
Mount: /mnt/atlaso-vcf-backups
Volume: shared
VCFDT depot storage
Mount: /mnt/atlaso-vcf-offline-depot
Volume: shared"""
    qmp_events = []
    qmp = SimpleNamespace(send_key=lambda key: qmp_events.append(key))
    observed = []
    screens = iter((
        "Current partitions:\n<Go Back> <Delete All> <Create New> <Next>",
        screen,
        screen,
        screen,
    ))

    def wait_screen(_qmp, _output, predicate, label, _seconds):
        """Supply a bounded simulated installer screen.

        Args:
            _qmp: Fake QMP connection.
            _output: Fixture screenshot location.
            predicate: Screen predicate the current frame must satisfy.
            label: Public acceptance checkpoint.
            _seconds: Maximum polling interval.
        """
        observed.append(label)
        current = next(screens)
        assert predicate(current)
        return current

    monkeypatch.setattr(vm_acceptance, "wait_screen", wait_screen)

    vm_acceptance.configure_storage_assignments(qmp, Path("fixture"), "/dev/sda", screen)

    assert qmp_events == ["l", "left", "left", "ret", "tab", "tab", "ret"]
    assert observed == [
        "Custom partition editor", "Auto storage layout after Custom",
        "combined SFTP backup storage assignment", "combined VCFDT depot storage assignment",
    ]


def test_storage_acceptance_keeps_published_sequential_screen_support(monkeypatch):
    """Keep compatibility with published sequential service prompts.

    Args:
        monkeypatch: Replaces screen polling with bounded public fixture frames.
    """
    screens = iter(("SFTP backup storage", "VCFDT depot storage"))
    qmp_events = []
    qmp = SimpleNamespace(send_key=lambda key: qmp_events.append(key))
    observed = []

    def wait_screen(_qmp, _output, predicate, label, _seconds):
        """Supply the next published sequential screen.

        Args:
            _qmp: Fake QMP connection.
            _output: Fixture screenshot location.
            predicate: Screen predicate the current frame must satisfy.
            label: Public acceptance checkpoint.
            _seconds: Maximum polling interval.
        """
        screen = next(screens)
        observed.append(label)
        assert predicate(screen)
        return screen

    monkeypatch.setattr(vm_acceptance, "wait_screen", wait_screen)

    vm_acceptance.configure_storage_assignments(qmp, Path("fixture"), "/dev/sda")

    assert qmp_events == ["ret", "ret"]
    assert observed == ["installer storage layout", "legacy VCFDT depot storage"]


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
    """Require fresh serial observations and a delayed active state for both units.

    Args:
        monkeypatch: Fixture used to capture guest console commands.
        tmp_path: Temporary VM output directory.
    """
    evidence = vm_acceptance.FailureEvidence()
    commands = []
    requested = iter((("APP", "atlaso.service"), ("WORKER", "atlaso-worker.service")))
    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda _qmp, command: commands.append(command))

    def read_service_records(token, _deadline):
        """Supply fresh, unit-bound serial observations.

        Args:
            token: Challenge generated for this unit.
            _deadline: Bounded read deadline.
        """
        key, unit_id = next(requested)
        prefix = f"ATLASO-SERVICE:{token}:"
        return [
            prefix + "READY",
            prefix + f"{key}:{unit_id}:activating:success:-",
            prefix + f"{key}:{unit_id}:active:success:0",
            prefix + "DONE",
        ]

    qmp = SimpleNamespace(read_service_records=read_service_records)
    vm_acceptance.check_installed_services(qmp, tmp_path, evidence)

    assert evidence.service_states == {
        "atlaso.service": ["activating", "active"],
        "atlaso-worker.service": ["activating", "active"],
    }
    assert len(commands) == 3
    assert any("systemctl show" in command and "service_probe" in command for command in commands)
    assert any("service_probe APP atlaso.service" in command for command in commands)
    assert any("service_probe WORKER atlaso-worker.service" in command for command in commands)


def test_service_timeout_keeps_gate_closed_and_collects_evidence(monkeypatch, tmp_path):
    """Report a responsive but failed unit with its bounded systemd status.

    Args:
        monkeypatch: Fixture that supplies a confirmed unit failure.
        tmp_path: Directory representing the VM fixture.
    """
    evidence = vm_acceptance.FailureEvidence()
    collected = []
    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda *_: None)

    def read_service_records(token, _deadline):
        """Supply a fixed failed-unit result.

        Args:
            token: Challenge generated for the service.
            _deadline: Bounded read deadline.
        """
        prefix = f"ATLASO-SERVICE:{token}:"
        return [prefix + "READY", prefix + "APP:atlaso.service:failed:exit-code:203", prefix + "DONE"]

    monkeypatch.setattr(vm_acceptance, "collect_service_failure", lambda _vm, _out, unit, _: collected.append(unit))
    with pytest.raises(vm_acceptance.AcceptanceError, match="atlaso.service remained failed"):
        vm_acceptance.check_installed_services(
            SimpleNamespace(read_service_records=read_service_records),
            tmp_path,
            evidence,
        )

    assert evidence.service_states == {"atlaso.service": ["failed"]}
    assert evidence.unit_result == "exit-code"
    assert evidence.exec_main_status == 203
    assert collected == ["atlaso.service"]


def test_missing_service_records_are_distinct_from_a_confirmed_nonactive_unit(monkeypatch, tmp_path):
    """Report a missing reply separately from a responsive service failure.

    Args:
        monkeypatch: Fixture that simulates a missing terminal service record.
        tmp_path: Directory representing the VM fixture.
    """
    evidence = vm_acceptance.FailureEvidence()
    collected = []
    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda *_: None)
    monkeypatch.setattr(vm_acceptance, "collect_service_failure", lambda _vm, _out, unit, _: collected.append(unit))

    def read_service_records(_token, _deadline):
        """Simulate a serial read that expires before a complete transaction.

        Args:
            _token: Per-unit challenge.
            _deadline: Bounded read deadline.
        """
        raise vm_acceptance.ScreenTimeout("incomplete service state records")

    qmp = SimpleNamespace(read_service_records=read_service_records)
    with pytest.raises(vm_acceptance.AcceptanceError, match="atlaso.service state could not be read"):
        vm_acceptance.check_installed_services(qmp, tmp_path, evidence)

    assert evidence.service_states == {"atlaso.service": ["unrecognized"]}
    assert evidence.unit_result is None
    assert evidence.exec_main_status is None
    assert collected == ["atlaso.service"]


def test_temporary_systemd_query_timeout_does_not_hide_later_active_state(monkeypatch, tmp_path):
    """Accept a later verified active reply after one unavailable systemd query.

    Args:
        monkeypatch: Fixture that supplies an unavailable query followed by active.
        tmp_path: Directory representing the VM fixture.
    """
    evidence = vm_acceptance.FailureEvidence()
    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda *_: None)
    requested = iter((("APP", "atlaso.service"), ("WORKER", "atlaso-worker.service")))

    def read_service_records(token, _deadline):
        """Supply one bounded unavailable result and a successful later snapshot.

        Args:
            token: Per-unit challenge.
            _deadline: Bounded read deadline.
        """
        key, service = next(requested)
        prefix = f"ATLASO-SERVICE:{token}:"
        observations = [prefix + f"{key}:-:unrecognized:-:-"] if key == "APP" else []
        observations.append(prefix + f"{key}:{service}:active:success:0")
        return [prefix + "READY", *observations, prefix + "DONE"]

    qmp = SimpleNamespace(read_service_records=read_service_records)
    vm_acceptance.check_installed_services(qmp, tmp_path, evidence)
    assert evidence.service_states == {
        "atlaso.service": ["unrecognized", "active"],
        "atlaso-worker.service": ["active"],
    }


@pytest.mark.parametrize("fields", [
    ["READY", "APP:atlaso.service:active:-:0", "DONE"],
    ["READY", "APP:atlaso.service:active:success:-", "DONE"],
    ["READY", "APP:atlaso.service:active:success:256", "DONE"],
    ["READY", "WORKER:atlaso-worker.service:active:success:0", "DONE"],
    ["READY", "APP:atlaso-worker.service:active:success:0", "DONE"],
    ["READY", "APP:atlaso.service:active:success:0"],
    ["READY", "APP:atlaso.service:active:success:0", "APP:atlaso.service:failed:exit-code:1", "DONE"],
])
def test_incomplete_or_out_of_order_service_evidence_is_rejected(fields):
    """Reject contradictory states and incomplete or mismatched systemd snapshots.

    Args:
        fields: Ordered record suffixes for an invalid guest reply.
    """
    records = ["ATLASO-SERVICE:token:" + field for field in fields]
    with pytest.raises(vm_acceptance.AcceptanceError):
        vm_acceptance.service_observations(records, "token", "APP", "atlaso.service")


@pytest.mark.parametrize(("version", "probes_required"), [("0.9.522", False), ("0.9.523", True), ("1.0.0", True)])
def test_acceptance_exercises_network_diagnostics_from_the_first_shipping_version(
    monkeypatch, tmp_path, version, probes_required, capsys,
):
    """Apply the network probe requirement only to versions that ship it.

    Args:
        monkeypatch: Fixture that supplies synthetic console replies.
        tmp_path: Directory representing the VM fixture.
        version: Installed version to verify.
        probes_required: Whether this version must exercise the network probes.
        capsys: Fixture used to verify that only the discarded byte count is logged.
    """
    observed = []
    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda *_: None)
    monkeypatch.setattr(vm_acceptance, "check_installed_services", lambda *_: observed.append("services"))

    monkeypatch.setattr(vm_acceptance, "check_installed_network_diagnostics",
                        lambda *_: observed.append("installed network diagnostics"))

    def discard_serial_boot_output():
        """Record that the one-time serial backlog drain occurs at this point."""
        observed.append("discard serial boot output")
        return 37

    qmp = SimpleNamespace(discard_serial_boot_output=discard_serial_boot_output)

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
        assert predicate("True")
        return "True"

    monkeypatch.setattr(vm_acceptance, "wait_screen", wait_screen)
    vm_acceptance.check_installed_application(qmp, tmp_path, version, "a" * 40, vm_acceptance.FailureEvidence())

    expected = [
        "installed Atlaso version",
        "installed Atlaso source commit",
        "discard serial boot output",
        "services",
    ]
    if probes_required:
        expected.append("installed network diagnostics")
    assert observed == expected
    output = capsys.readouterr().out
    assert "Discarded 37 serial boot bytes" in output
    assert "ATLASO-PROBE" not in output


@pytest.mark.parametrize("installing", [True, False])
def test_probe_serial_port_only_exists_on_media_free_boot(monkeypatch, tmp_path, installing):
    """Keep the dedicated in-memory result port on the installed guest.

    Args:
        monkeypatch: Replace QEMU launch and control.
        tmp_path: Fixture paths for the QEMU command.
        installing: Whether this boot has installation media attached.
    """
    commands = []
    monkeypatch.setattr(vm_acceptance.subprocess, "Popen", lambda cmd, **kw: commands.append(cmd))
    monkeypatch.setattr(vm_acceptance, "Qmp", lambda *args, **kw: SimpleNamespace(execute=lambda *_: None))
    vm_acceptance.start_qemu(tmp_path / "installation.iso" if installing else None, tmp_path,
                             tmp_path / "disk", tmp_path / "vars", tmp_path / "code", "control",
                             abstract_sockets=False, accelerator="tcg")
    args = commands[0]
    assert ("ringbuf,id=atlaso-probes,size=4096" in args) == (not installing)
    assert ("isa-serial,chardev=atlaso-probes,index=1" in args) == (not installing)


def test_serial_reader_reassembles_fragmented_guest_records(monkeypatch):
    """Read LF and CRLF records split at arbitrary QMP boundaries.

    Args:
        monkeypatch: Supply fragments from the simulated QEMU ring buffer.
    """
    vm = object.__new__(vm_acceptance.Qmp)
    chunks = iter([b"ATLASO-PRO", b"BE:abc:DONE\r", b"\nATLASO-PROBE:abc:EXIT:0\n"])

    def execute(command, arguments):
        """Read one fragment from the fixed device.

        Args:
            command: QMP operation.
            arguments: Character device and encoding.
        """
        assert command == "ringbuf-read"
        assert arguments["device"] == "atlaso-probes" and arguments["format"] == "base64"
        return base64.b64encode(next(chunks)).decode("ascii")

    monkeypatch.setattr(vm, "execute", execute)
    assert vm.read_network_records("abc", vm_acceptance.time.monotonic() + 5, "EXIT") == [
        "ATLASO-PROBE:abc:DONE", "ATLASO-PROBE:abc:EXIT:0",
    ]


@pytest.mark.parametrize("payload", [
    b"",
    b"\x00partial ATLASO-PROBE:old:REA\xff",
    bytes(range(256)) * 16,
])
def test_serial_boot_drain_reads_one_bounded_ring_buffer(monkeypatch, capsys, payload):
    """Discard arbitrary startup bytes in one full-capacity QMP read.

    Args:
        monkeypatch: Supply one encoded ring-buffer response.
        capsys: Fixture that verifies no guest bytes are logged.
        payload: Empty, partial, binary, or full-capacity startup data.
    """
    vm = object.__new__(vm_acceptance.Qmp)
    calls = []

    def execute(command, arguments):
        """Capture the request and return the queued buffer contents.

        Args:
            command: QMP operation.
            arguments: Character device, read size, and encoding.
        """
        calls.append((command, arguments))
        return base64.b64encode(payload).decode("ascii")

    monkeypatch.setattr(vm, "execute", execute)

    assert vm.discard_serial_boot_output() == len(payload)
    assert calls == [(
        "ringbuf-read",
        {"device": "atlaso-probes", "size": vm_acceptance.NETWORK_RINGBUF_BYTES, "format": "base64"},
    )]
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == ""


@pytest.mark.parametrize("response", [
    None,
    b"not a string",
    "@@@",
    base64.b64encode(b"x" * (vm_acceptance.NETWORK_RINGBUF_BYTES + 1)).decode("ascii"),
])
def test_serial_boot_drain_rejects_invalid_qmp_buffers(monkeypatch, response):
    """Reject invalid or oversized QMP data without exposing its contents.

    Args:
        monkeypatch: Supply an invalid QMP ring-buffer response.
        response: Wrong type, malformed base64, or payload larger than the ring.
    """
    vm = object.__new__(vm_acceptance.Qmp)
    monkeypatch.setattr(vm, "execute", lambda *_: response)

    with pytest.raises(vm_acceptance.AcceptanceError) as error:
        vm.discard_serial_boot_output()

    assert "not a string" not in str(error.value)
    assert "@@@" not in str(error.value)


def test_serial_boot_drain_discards_partial_preamble_before_fresh_challenge(monkeypatch):
    """Ignore arbitrary boot bytes and accept a subsequent fresh challenge record.

    Args:
        monkeypatch: Supply startup bytes followed by one fresh token-bound record.
    """
    vm = object.__new__(vm_acceptance.Qmp)
    preamble = b"\x00\xffATLASO-PROBE:stale:REA"
    fresh_record = b"ATLASO-PROBE:fresh:READY\n"
    chunks = iter((preamble, fresh_record))
    reads = []

    def execute(command, arguments):
        """Return the next ring-buffer chunk and retain request sizes.

        Args:
            command: QMP operation.
            arguments: Character device, read size, and encoding.
        """
        assert command == "ringbuf-read"
        reads.append(arguments["size"])
        return base64.b64encode(next(chunks)).decode("ascii")

    monkeypatch.setattr(vm, "execute", execute)

    assert vm.discard_serial_boot_output() == len(preamble)
    assert vm.read_network_records("fresh", vm_acceptance.time.monotonic() + 5, "READY") == [
        "ATLASO-PROBE:fresh:READY",
    ]
    assert reads == [vm_acceptance.NETWORK_RINGBUF_BYTES, vm_acceptance.NETWORK_RINGBUF_READ_BYTES]


@pytest.mark.parametrize("post_challenge", [
    b"ATLASO-PROBE:stale:READY\n",
    b"ATLASO-PROBE:fresh:READY\nATLASO-PROBE:stale:DONE\n",
    b"ATLASO-PROBE:fresh:REA\xff\n",
])
def test_serial_boot_drain_does_not_weaken_post_challenge_token_checks(monkeypatch, post_challenge):
    """Reject stale or extra serial records that arrive after the drain boundary.

    Args:
        monkeypatch: Supply startup bytes and invalid post-challenge data.
        post_challenge: Stale-token reply or extra record after a valid READY.
    """
    vm = object.__new__(vm_acceptance.Qmp)
    chunks = iter((b"old partial preamble", post_challenge))
    monkeypatch.setattr(
        vm,
        "execute",
        lambda *_: base64.b64encode(next(chunks)).decode("ascii"),
    )

    vm.discard_serial_boot_output()
    with pytest.raises(vm_acceptance.AcceptanceError):
        vm.read_network_records("fresh", vm_acceptance.time.monotonic() + 5, "READY")


def test_service_serial_reader_reassembles_fragmented_status_records(monkeypatch):
    """Read startup state records independently of console text recognition.

    Args:
        monkeypatch: Supply fragmented service replies from the simulated QEMU ring buffer.
    """
    vm = object.__new__(vm_acceptance.Qmp)
    chunks = iter([
        b"ATLASO-SERVICE:abc:READY\nATLASO-SERVICE:abc:APP:atlaso.service:activating:success:-\n",
        b"ATLASO-SERVICE:abc:APP:atlaso.service:act", b"ive:success:0\r", b"\nATLASO-SERVICE:abc:DONE\n",
    ])

    def execute(command, arguments):
        """Return the next fixed ring-buffer fragment.

        Args:
            command: QMP operation.
            arguments: Character device and encoding.
        """
        assert command == "ringbuf-read"
        assert arguments["device"] == "atlaso-probes" and arguments["format"] == "base64"
        return base64.b64encode(next(chunks)).decode("ascii")

    monkeypatch.setattr(vm, "execute", execute)
    assert vm.read_service_records("abc", vm_acceptance.time.monotonic() + 5) == [
        "ATLASO-SERVICE:abc:READY",
        "ATLASO-SERVICE:abc:APP:atlaso.service:activating:success:-",
        "ATLASO-SERVICE:abc:APP:atlaso.service:active:success:0",
        "ATLASO-SERVICE:abc:DONE",
    ]


@pytest.mark.parametrize("payload", [
    b"ATLASO-SERVICE:stale:READY\n",
    b"ATLASO-SERVICE:abc:APP:atlaso.service:untrusted:success:0\n",
    b"ATLASO-SERVICE:abc:APP:atlaso.service:failed:unexpected:1\n",
    b"ATLASO-SERVICE:abc:DONE\nATLASO-SERVICE:abc:APP:atlaso.service:active:success:0\n",
])
def test_service_serial_reader_rejects_stale_or_invalid_records(monkeypatch, payload):
    """Fail closed on stale, malformed, or late startup evidence.

    Args:
        monkeypatch: Supply a simulated QEMU ring-buffer reply.
        payload: Bytes that must not be accepted as service evidence.
    """
    vm = object.__new__(vm_acceptance.Qmp)
    monkeypatch.setattr(vm, "execute", lambda *_: base64.b64encode(payload).decode("ascii"))

    with pytest.raises(vm_acceptance.AcceptanceError):
        vm.read_service_records("abc", vm_acceptance.time.monotonic() + 5)


@pytest.mark.parametrize("payload", [
    b"ATLASO-PROBE:stale:READY\n", b"unexpected guest output\n",
    b"ATLASO-PROBE:abc:READY\nextra", b"ATLASO-PROBE:abc:EXIT:1\n",
])
def test_serial_reader_rejects_invalid_handshake(monkeypatch, payload):
    """Fail closed without emitting raw guest bytes.

    Args:
        monkeypatch: Supply a simulated QEMU reply.
        payload: Guest bytes returned by the ring buffer.
    """
    vm = object.__new__(vm_acceptance.Qmp)
    monkeypatch.setattr(vm, "execute", lambda *_: base64.b64encode(payload).decode("ascii"))
    with pytest.raises(vm_acceptance.AcceptanceError) as error:
        vm.read_network_records("abc", vm_acceptance.time.monotonic() + 5, "READY")
    assert "unexpected guest output" not in str(error.value)


@pytest.mark.parametrize(("reports", "error"), [
    (["1:PASS", "2:PASS", "3:PASS", "4:PASS", "5:PASS", "DONE", "EXIT:0"], None),
    (["1:PASS", "2:PASS", "3:PASS", "4:FAIL", "5:PASS", "DONE", "EXIT:1"], "IPv6 loopback traceroute"),
    (["1:PASS", "2:PASS", "2:PASS", "4:PASS", "5:PASS", "DONE", "EXIT:0"], "invalid"),
    (["EXIT:0"], "exited before completing"),
    (["EXIT:124"], "deadline"),
    (["EXIT:127"], "127"),
])
def test_installed_network_probes_require_five_results_and_clean_exit(monkeypatch, tmp_path, reports, error):
    """Accept only the complete probe sequence from a runnable guest command.

    Args:
        monkeypatch: Intercept guest keyboard input and serial reads.
        tmp_path: Guest fixture directory.
        reports: Fixed guest records returned after the handshake.
        error: Expected failure message or None for success.
    """
    commands = []

    def read_records(token, deadline, terminal):
        """Supply records tagged for the active attempt.

        Args:
            token: Per-attempt identity.
            deadline: Absolute time limit for the current phase.
            terminal: Expected last record.
        """
        if terminal == "READY":
            assert len(commands) == 1 and "/dev/ttyS1" in commands[0]
            return [f"ATLASO-PROBE:{token}:READY"]
        assert 175 < deadline - vm_acceptance.time.monotonic() <= 180
        return [f"ATLASO-PROBE:{token}:{value}" for value in reports]

    monkeypatch.setattr(vm_acceptance, "run_console_command", lambda _, command: commands.append(command))
    qmp = SimpleNamespace(read_network_records=read_records)
    evidence = vm_acceptance.FailureEvidence()
    if error is None:
        vm_acceptance.check_installed_network_diagnostics(qmp, tmp_path, evidence)
    else:
        with pytest.raises(vm_acceptance.AcceptanceError, match=error):
            vm_acceptance.check_installed_network_diagnostics(qmp, tmp_path, evidence)
    assert any("runuser -u atlaso" in cmd for cmd in commands)
    for command in commands:
        vm_acceptance.key_events(command)


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
