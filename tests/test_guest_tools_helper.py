"""Verify fixed-provider maintenance, observation failures and sole clock authority."""

import hashlib
import json
import stat
import subprocess
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from tests.test_appliance_helper import load_helper_module


@pytest.fixture
def helper():
    """Load the privileged helper without executing its command-line entry point."""
    return load_helper_module()


@pytest.mark.parametrize("detected,dmi,expected", [
    ("vmware", "VMware, Inc.", "vmware"), ("kvm", "QEMU", "qemu"),
    ("microsoft", "Microsoft Virtual Machine", "hyperv"), ("none", "Physical", "baremetal"),
    ("vmware", "QEMU", "unknown"),
])
def test_provider_uses_hardware_including_iso_installations(helper, monkeypatch, tmp_path, detected, dmi, expected):
    """Installation media identity must not override actual virtual hardware.

    Args:
        helper: Isolated helper module.
        monkeypatch: Native probe replacements.
        tmp_path: Isolated firmware attributes.
        detected: Systemd's virtualization identifier.
        dmi: Firmware vendor evidence.
        expected: Compatible provider or ambiguity.
    """
    vendor = tmp_path / "vendor"
    vendor.write_text(dmi)
    monkeypatch.setenv("ATLASO_STORAGE_PROFILE", "installation")
    monkeypatch.setattr(helper, "ATLASO_DMI_SYS_VENDOR_PATH", vendor)
    monkeypatch.setattr(helper, "ATLASO_DMI_PRODUCT_NAME_PATH", vendor)
    monkeypatch.setattr(helper.shutil, "which", lambda name: name)
    monkeypatch.setattr(helper, "_run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, detected, ""))
    assert helper._guest_tools_detect_provider()[0] == expected


def test_rpm_failure_is_unknown_instead_of_missing(helper, monkeypatch):
    """A corrupt RPM database and an absent package carry different evidence.

    Args:
        helper: Isolated privileged helper.
        monkeypatch: Read-only RPM query replacement.
    """
    monkeypatch.setattr(helper.shutil, "which", lambda name: name)
    monkeypatch.setattr(helper, "_run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, "", "rpm database unavailable"))
    assert helper._guest_tools_package_state("open-vm-tools")["installed"] is None
    monkeypatch.setattr(helper, "_run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, "package open-vm-tools is not installed", ""))
    assert helper._guest_tools_package_state("open-vm-tools")["installed"] is False


@pytest.mark.parametrize("installed,active,conflict,clock,state", [
    (False, False, False, "pending", "missing"), (True, False, False, "verified", "stopped"),
    (True, True, False, "verified", "healthy"), (True, True, True, "verified", "unsupported"),
    (None, False, False, "verified", "unknown"), (True, True, False, "unknown", "unknown"),
])
def test_status_does_not_confuse_missing_stopped_conflicting_or_unknown(
    helper, monkeypatch, installed, active, conflict, clock, state,
):
    """All operator states derive from effective evidence rather than a zero exit code.

    Args:
        helper: Privileged helper module.
        monkeypatch: Independent package/service/capability observations.
        installed: Target package query result.
        active: Required service runtime state.
        conflict: Foreign provider package presence.
        clock: Applied time-authority verification state.
        state: Expected operator-facing classification.
    """
    monkeypatch.setattr(helper, "_guest_tools_detect_provider", lambda: ("vmware", ""))
    monkeypatch.setattr(helper, "_guest_tools_platform_evidence", lambda provider: (True, ""))
    monkeypatch.setattr(helper, "_guest_tools_package_state", lambda name: {
        "name": name, "installed": installed if name == "open-vm-tools" else conflict,
        "version": "0:1.0-1", "architecture": "x86_64",
    })
    monkeypatch.setattr(helper, "_guest_tools_service_state", lambda unit: {
        "unit": unit, "load_state": "loaded" if unit == "vmtoolsd.service" else "not-found",
        "active": active if unit == "vmtoolsd.service" else False,
        "enabled": active if unit == "vmtoolsd.service" else False,
    })
    monkeypatch.setattr(helper, "_guest_tools_clock_safety", lambda provider: {
        "status": clock, "authority": "ntp_client", "protected": clock == "verified", "reason": "Apply time source",
    })
    monkeypatch.setattr(helper, "_guest_tools_payload", lambda provider: {"available": True, "digest": "payload", "packages": []})
    result = helper._guest_tools_status()
    assert result["state"] == state
    assert result["available"] is (state in {"missing", "stopped", "healthy"})
    assert len(result["review_digest"]) == 64


def test_changed_review_refuses_mutation_and_healthy_repeat_is_noop(helper, monkeypatch, tmp_path):
    """A stale review changes nothing; repeated healthy install does no host work.

    Args:
        helper: Isolated helper module.
        monkeypatch: Stable status fixture and mutation tripwire.
        tmp_path: Isolated durable guest-tools evidence location.
    """
    status = {"provider": "vmware", "review_digest": "a" * 64, "state": "healthy", "available": True, "version": "0:1-1"}
    monkeypatch.setattr(helper, "ATLASO_GUEST_TOOLS_STATUS_PATH", tmp_path / "guest-tools-status.json")
    monkeypatch.setattr(helper, "_guest_tools_status", lambda: dict(status))
    monkeypatch.setattr(helper, "_guest_tools_clock_guard", lambda **kwargs: pytest.fail("A no-op must not change clock services"))
    stale = helper._guest_tools_apply({"guest_tools": {"provider": "vmware", "review_digest": "b" * 64}})
    assert stale["status"] == "failed"
    repeat = helper._guest_tools_apply({"guest_tools": {"provider": "vmware", "review_digest": "a" * 64}})
    assert repeat["status"] == "succeeded"
    assert repeat["applied"]["guest_tools"]["no_change"] is True
    evidence = json.loads((tmp_path / "guest-tools-status.json").read_text(encoding="utf-8"))
    assert evidence["result"]["applied"]["guest_tools"]["no_change"] is True


@pytest.mark.parametrize("defect", [
    None, "foreign_repo", "remove", "downgrade", "invalid_json", "unknown", "unverified", "duplicate", "foreign_path",
    "duplicate_identity", "missing_target", "missing_tdnf", "nonzero_epoch",
])
def test_guest_tools_check_uses_only_verified_local_solver_packages(helper, monkeypatch, tmp_path, defect):
    """The offline solver may select only exact verified RPMs from the active profile.

    Args:
        helper: Isolated privileged helper.
        monkeypatch: Stable source state and local solver response.
        tmp_path: Isolated local RPM profile.
        defect: Foreign, missing, or ambiguous solver result to reject.
    """
    root = tmp_path / "payload"
    profile = root / "vmware"
    profile.mkdir(parents=True)
    target_path = profile / "open-vm-tools.rpm"
    dependency_path = profile / "libvmtools.rpm"
    conflict_path = profile / "hostname.rpm"
    for path in (target_path, dependency_path, conflict_path):
        path.write_bytes(b"verified fixture RPM")
    foreign_path = tmp_path / "foreign.rpm"
    foreign_path.write_bytes(b"unverified package")
    duplicate_path = profile / "duplicate.rpm"
    duplicate_path.write_bytes(b"duplicate package")
    monkeypatch.setattr(helper, "ATLASO_GUEST_TOOLS_PAYLOAD_DIR", root)
    monkeypatch.setattr(helper, "ATLASO_FIRST_BOOT_GUEST_TOOLS_DIR", tmp_path / "other-payload")
    monkeypatch.setattr(helper.shutil, "which", lambda name: name)
    packages = [
        {"name": "open-vm-tools", "version": "0:13.1.0-2.ph5", "architecture": "x86_64", "path": str(target_path)},
        {"name": "libvmtools", "version": "0:13.1.0-2.ph5", "architecture": "x86_64", "path": str(dependency_path)},
        {"name": "hostname", "version": "0:3.25-3.ph5", "architecture": "x86_64", "path": str(conflict_path)},
    ]
    rows = [
        {"Name": "open-vm-tools", "Arch": "x86_64", "Evr": "13.1.0-2.ph5", "InstallSize": 1,
         "Repo": "atlaso-guest-tools"},
        {"Name": "libvmtools", "Arch": "x86_64", "Evr": "13.1.0-2.ph5", "InstallSize": 1,
         "Repo": "atlaso-guest-tools"},
    ]
    response = {"Install": rows}
    if defect == "foreign_repo":
        rows[1]["Repo"] = "photon"
    elif defect == "remove":
        response["Remove"] = [{"Name": "net-tools"}]
    elif defect == "downgrade":
        response = {"Downgrade": [dict(rows[0])]}
    elif defect == "unknown":
        response["Erase"] = []
    elif defect == "unverified":
        rows[1]["Name"] = "not-in-payload"
    elif defect == "duplicate":
        rows.append(dict(rows[0]))
    elif defect == "foreign_path":
        packages[1]["path"] = str(foreign_path)
    elif defect == "duplicate_identity":
        packages.append({**packages[1], "path": str(duplicate_path)})
    elif defect == "missing_target":
        packages = packages[1:]
    elif defect == "nonzero_epoch":
        packages[0]["version"] = "2:13.1.0-2.ph5"
        rows[0]["Evr"] = "2:13.1.0-2.ph5"
    commands = []

    def command_payload(command, **kwargs):
        """Provide a synthetic solver decision and RPM transaction result.

        Args:
            command: Bounded offline package command.
            **kwargs: Captured command limits.
        """
        commands.append(command)
        if command[0] == "tdnf":
            return {"command": command, "success": True, "returncode": 0,
                    "stdout": "not-json" if defect == "invalid_json" else json.dumps(response), "stderr": ""}
        return {"command": command, "success": True, "returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(helper, "_command_payload", command_payload)
    if defect == "missing_tdnf":
        monkeypatch.setattr(helper.shutil, "which", lambda name: None if name == "tdnf" else name)
    state = {"provider": "vmware", "review_digest": "a" * 64, "state": "missing", "available": True,
             "reason": "Verified VMware closure is available.", "plan": {"package_change": True},
             "payload": {"available": True, "digest": "verified", "path": str(root), "packages": packages}}
    monkeypatch.setattr(helper, "_guest_tools_status", lambda: dict(state))
    result = helper._guest_tools_check({"guest_tools": {"provider": "vmware", "review_digest": "a" * 64}})

    if defect not in {None, "nonzero_epoch"}:
        assert result["state"] == "failed"
        if defect in {"foreign_path", "duplicate_identity", "missing_target", "missing_tdnf"}:
            assert commands == []
        else:
            assert commands[0][0] == "tdnf"
            assert len(commands) == 1
        return

    assert result["state"] == "available"
    assert result["_transaction_packages"] == [str(target_path), str(dependency_path)]
    assert str(conflict_path) not in result["_transaction_packages"]
    assert commands[0] == [
        "tdnf", "--disablerepo=*", f"--repofromdir=atlaso-guest-tools,{profile}",
        "--repoid=atlaso-guest-tools", "--assumeno", "--json", "install",
        "open-vm-tools-2:13.1.0-2.ph5.x86_64" if defect == "nonzero_epoch"
        else "open-vm-tools-13.1.0-2.ph5.x86_64",
    ]
    assert commands[1] == ["rpm", "-Uvh", "--replacepkgs", "--test", str(target_path), str(dependency_path)]
    assert not {"--nodeps", "--replacefiles", "--nogpgcheck", "--skipconflicts"} & set(commands[0])


def test_guest_tools_apply_uses_only_solver_selected_rpms(helper, monkeypatch, tmp_path):
    """Check and apply carry only the local solver's verified package set into RPM.

    Args:
        helper: Isolated privileged helper.
        monkeypatch: Native command and status replacements.
        tmp_path: Isolated provider payload.
    """
    root = tmp_path / "payload"
    profile = root / "vmware"
    profile.mkdir(parents=True)
    target_path = profile / "open-vm-tools.rpm"
    dependency_path = profile / "libvmtools.rpm"
    conflict_path = profile / "hostname.rpm"
    for path in (target_path, dependency_path, conflict_path):
        path.write_bytes(b"verified fixture RPM")
    packages = [
        {"name": "open-vm-tools", "version": "0:13.1.0-2.ph5", "architecture": "x86_64", "path": str(target_path)},
        {"name": "libvmtools", "version": "0:13.1.0-2.ph5", "architecture": "x86_64", "path": str(dependency_path)},
        {"name": "hostname", "version": "0:3.25-3.ph5", "architecture": "x86_64", "path": str(conflict_path)},
    ]
    payload_info = {"available": True, "digest": "verified", "path": str(root), "packages": packages}
    installing = {"provider": "vmware", "review_digest": "a" * 64, "state": "missing", "available": True,
                  "version": "", "reason": "Verified offline closure is available.",
                  "plan": {"package_change": True}, "payload": payload_info}
    healthy = {**installing, "state": "healthy", "version": "0:13.1.0-2.ph5", "payload": payload_info}
    statuses = iter((installing, installing, healthy))
    monkeypatch.setattr(helper, "ATLASO_GUEST_TOOLS_PAYLOAD_DIR", root)
    monkeypatch.setattr(helper, "ATLASO_FIRST_BOOT_GUEST_TOOLS_DIR", tmp_path / "other-payload")
    monkeypatch.setattr(helper, "_guest_tools_status", lambda: next(statuses))
    monkeypatch.setattr(helper, "_guest_tools_payload", lambda provider: payload_info)
    monkeypatch.setattr(helper, "_guest_tools_clock_guard", lambda **kwargs: {"success": True})
    update_info_path = tmp_path / "update-info.json"
    update_info = {
        "status": "succeeded",
        "job_id": "job_prior_photon",
        "applied": {"photon_os": {"updated": True}},
        "attempted": {"photon_os": {"updated": True}},
        "commands": [],
        "reboot_recommended": False,
        "restart_required": False,
        "selected_streams": ["photon_os"],
        "finished_at": "2026-10-31T18:00:00+00:00",
        "finalizer_status_path": "",
    }
    update_info_path.write_text(json.dumps(update_info, indent=2) + "\n", encoding="utf-8")
    original_update_info = update_info_path.read_bytes()
    guest_tools_status_path = tmp_path / "guest-tools-status.json"
    monkeypatch.setattr(helper, "APPLIANCE_UPDATE_INFO_PATH", update_info_path)
    monkeypatch.setattr(helper, "ATLASO_GUEST_TOOLS_STATUS_PATH", guest_tools_status_path)
    monkeypatch.setattr(helper.shutil, "which", lambda name: name)
    rows = [
        {"Name": "open-vm-tools", "Arch": "x86_64", "Evr": "13.1.0-2.ph5", "InstallSize": 1,
         "Repo": "atlaso-guest-tools"},
        {"Name": "libvmtools", "Arch": "x86_64", "Evr": "13.1.0-2.ph5", "InstallSize": 1,
         "Repo": "atlaso-guest-tools"},
    ]
    calls = []

    def command_payload(command, **kwargs):
        """Record every test and install command and return the local solver plan.

        Args:
            command: Bounded native command.
            **kwargs: Captured command limits.
        """
        calls.append(command)
        stdout = json.dumps({"Install": rows}) if command[0] == "tdnf" else ""
        return {"command": command, "success": True, "returncode": 0, "stdout": stdout, "stderr": ""}

    monkeypatch.setattr(helper, "_command_payload", command_payload)

    result = helper._guest_tools_apply({"guest_tools": {"provider": "vmware", "review_digest": "a" * 64}})

    selected = [str(target_path), str(dependency_path)]
    assert result["status"] == "succeeded"
    assert calls[0][0] == "tdnf" and calls[0][1] == "--disablerepo=*"
    assert calls[0][-1] == "open-vm-tools-13.1.0-2.ph5.x86_64"
    assert calls[1] == ["rpm", "-Uvh", "--replacepkgs", "--test", *selected]
    assert calls[2] == ["rpm", "-Uvh", "--replacepkgs", "--test", *selected]
    assert calls[3] == ["rpm", "-Uvh", "--replacepkgs", *selected]
    assert str(conflict_path) not in calls[1] + calls[2] + calls[3]
    assert update_info_path.read_bytes() == original_update_info
    from atlaso.app.services.appliance_update import appliance_update_evidence_state

    updater_state = appliance_update_evidence_state(
        qualifying_install_job_id="job_prior_photon",
        qualifying_install_stream="photon_os",
        qualifying_install_started_at=datetime(2026, 10, 31, 17, 59, tzinfo=timezone.utc),
        update_info_path=str(update_info_path),
        finalizer_path=str(tmp_path / "missing-finalizer.json"),
    )
    assert updater_state["state"] == "available"
    guest_tools_evidence = json.loads(guest_tools_status_path.read_text(encoding="utf-8"))
    assert guest_tools_evidence["schema"] == 1
    assert guest_tools_evidence["result"]["status"] == "succeeded"
    assert guest_tools_evidence["result"]["guest_tools"]["provider"] == "vmware"


@pytest.mark.parametrize("failure", ["stale_review", "clock_guard", "final_verification"])
def test_guest_tools_apply_cli_propagates_verification_failure(helper, monkeypatch, capsys, failure):
    """Failed admission or final observation must fail even without a failed command.

    Args:
        helper: Isolated privileged helper.
        monkeypatch: Safe observations and host operation replacements.
        capsys: Captured helper JSON output.
        failure: Admission or verification stage to reject.
    """
    state = {"provider": "vmware", "review_digest": "a" * 64, "state": "stopped", "available": True}
    payload = {"guest_tools": {"provider": "vmware", "review_digest": ("b" if failure == "stale_review" else "a") * 64}}
    monkeypatch.setattr(helper, "_guest_tools_status", lambda: dict(state))
    monkeypatch.setattr(helper, "_guest_tools_check", lambda payload: {"state": "available"})
    monkeypatch.setattr(helper, "_guest_tools_clock_guard", lambda **kwargs: {"success": failure != "clock_guard"})
    monkeypatch.setattr(helper.shutil, "which", lambda name: name)
    monkeypatch.setattr(helper, "_command_payload", lambda command, **kwargs: {"command": command, "success": True})
    monkeypatch.setattr(helper, "_write_guest_tools_evidence", lambda result: None)
    monkeypatch.setattr(helper, "_validate_appliance_update_config_path", lambda path: path)
    monkeypatch.setattr(helper, "_load_appliance_update_config", lambda path: payload)
    monkeypatch.setattr(helper, "_load_appliance_update_credentials", lambda args: {})
    monkeypatch.setattr(helper, "_appliance_update_config_errors", lambda *args, **kwargs: [])
    monkeypatch.setattr(helper, "_apply_appliance_update", lambda payload, *args: helper._guest_tools_apply(payload))
    assert helper._handle_appliance_update_locked("apply", ["synthetic-config"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "failed"
    assert all(command["success"] for command in result.get("commands", []))
    assert bool(result.get("commands")) is (failure == "final_verification")


@pytest.mark.parametrize("provider", ["qemu", "hyperv"])
def test_foreign_selected_clock_authority_blocks_non_vmware(helper, monkeypatch, provider):
    """Installing another provider must not normalize away a selected VMware clock.

    Args:
        helper: Isolated helper module.
        monkeypatch: Last applied clock contract.
        provider: Non-VMware provider being considered.
    """
    monkeypatch.setattr(helper, "_ntpd_applied_time_mode", lambda path: "vmware_tools")
    assert helper._guest_tools_clock_safety(provider)["status"] == "blocked"


def test_clock_protection_is_persistent_and_bounded_to_time_capability(helper):
    """QEMU RPC blocking and Hyper-V class isolation leave the other agents intact.

    Args:
        helper: Isolated helper module.
    """
    assert "--block-rpcs=guest-set-time" in helper._guest_tools_qemu_guard_text()
    rule = helper._guest_tools_hyperv_udev_text()
    assert helper.ATLASO_HYPERV_TIMESYNC_CLASS_ID in rule
    assert 'ATTR{driver_override}="none"' in rule
    assert "hv_kvp" not in rule and "hv_vss" not in rule
    assert "Before=ntpd.service" in helper._guest_tools_hyperv_guard_text()


def test_hyperv_requires_real_userspace_kernel_channels_not_legacy_file_copy(helper, monkeypatch):
    """Host capability absence is unsupported even when userspace daemons could run.

    Args:
        helper: Privileged helper module.
        monkeypatch: Synthetic kernel channel observations.
    """
    monkeypatch.setattr(helper, "ATLASO_HYPERV_CAPABILITY_PATHS", (SimpleNamespace(is_char_device=lambda: False),))
    supported, reason = helper._guest_tools_platform_evidence("hyperv")
    assert supported is False and "KVP/VSS" in reason
    monkeypatch.setattr(helper, "ATLASO_HYPERV_CAPABILITY_PATHS", (SimpleNamespace(is_char_device=lambda: True),))
    monkeypatch.setattr(helper, "_guest_tools_hyperv_device", lambda: (None, "absent"))
    assert helper._guest_tools_platform_evidence("hyperv") == (True, "")
    assert helper._guest_tools_hyperv_inhibit()["success"] is True


@pytest.mark.parametrize("devices", [0, 1, 2])
def test_hyperv_timesync_discovery_distinguishes_absence_from_ambiguity(helper, monkeypatch, tmp_path, devices):
    """An empty valid inventory is safe; duplicate timesync devices remain a refusal.

    Args:
        helper: Isolated privileged helper.
        monkeypatch: Synthetic VMBus inventory and kernel capability paths.
        tmp_path: Receipt-bound kernel inventory fixture.
        devices: Number of matching timesync devices to expose.
    """
    for index in range(devices):
        device = tmp_path / str(index)
        device.mkdir()
        (device / "class_id").write_text("{" + helper.ATLASO_HYPERV_TIMESYNC_CLASS_ID + "}")
        (device / "driver_override").write_text("none")
    unrelated = tmp_path / "kvp"
    unrelated.mkdir()
    (unrelated / "class_id").write_text("unrelated-class")
    monkeypatch.setattr(helper, "ATLASO_HYPERV_DEVICES_PATH", tmp_path)
    monkeypatch.setattr(helper, "ATLASO_HYPERV_CAPABILITY_PATHS", (SimpleNamespace(is_char_device=lambda: True),))
    device, reason = helper._guest_tools_hyperv_device()
    if devices == 0:
        assert (device, reason) == (None, "absent")
        assert helper._guest_tools_platform_evidence("hyperv") == (True, "")
        assert helper._guest_tools_hyperv_inhibit()["success"] is True
    elif devices == 1:
        assert device == tmp_path / "0" and reason == ""
    else:
        assert device is None and "ambiguous" in reason
        assert helper._guest_tools_platform_evidence("hyperv")[0] is False
        assert helper._guest_tools_hyperv_inhibit()["success"] is False


def test_hyperv_clock_inhibition_does_not_block_owned_prepared_ntp_apply(helper, monkeypatch, tmp_path):
    """Guest protection must preserve the NTP owner's authorized candidate-start path.

    Args:
        helper: Privileged helper module.
        monkeypatch: Safe kernel and clock-controller operation replacements.
        tmp_path: Synthetic managed candidate and installed guard.
    """
    config = tmp_path / "ntp.conf"
    config.write_text(f"{helper.NTP_TIME_MODE_PREFIX} ntp_client\n")
    guard = tmp_path / "guest-guard.service"
    guard.write_text("synthetic installed guard")
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", config)
    monkeypatch.setattr(helper, "ATLASO_GUEST_TOOLS_CLOCK_GUARD_UNIT_PATH", guard)
    calls = []
    monkeypatch.setattr(helper, "_guest_tools_hyperv_inhibit", lambda: calls.append("inhibit") or {"success": True})
    monkeypatch.setattr(helper, "_guest_tools_hyperv_guard_files_valid", lambda: True)
    monkeypatch.setattr(helper, "_guest_tools_clock_guard", lambda **kwargs: pytest.fail("Maintenance admission cannot gate an owned NTP candidate"))
    monkeypatch.setattr(helper, "_ntpd_recover_interrupted_apply", lambda **kwargs: None)
    monkeypatch.setattr(helper, "_ntpd_read_transaction", lambda: {"phase": "prepared", "owner": {}})
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda owner: True)
    monkeypatch.setattr(helper, "_ntpd_stop_service", lambda unit: None)
    monkeypatch.setattr(helper, "_ntpd_client_packet_guard", lambda mode: None)
    monkeypatch.setattr(helper, "_ntpd_set_vmware_timesync", lambda enabled: None)
    assert helper._ntpd_guard("pre-ntpd") == 0
    assert calls == ["inhibit"]


def test_guest_tools_stream_is_isolated_and_has_recovery_identity(helper):
    """The shared maintenance pipeline may not mix provider installation with OS work.

    Args:
        helper: Isolated helper module.
    """
    payload = {"selected_streams": ["guest_tools", "photon_os"], "sources": {}, "guest_tools": {"provider": "vmware"}}
    errors = helper._appliance_update_config_errors(payload, require_synchronized=False)
    assert any("selected alone" in error for error in errors)
    identity = helper._appliance_update_action_unit_name("job_0123456789ab", "guest_tools")
    assert identity.startswith("atlaso-helper-action-")


def test_all_package_actions_share_serialization_before_dispatch(helper, monkeypatch):
    """Existing OS transactions and guest-tools work use the same admission order.

    Args:
        helper: Isolated helper module.
        monkeypatch: Admission and operation trace replacements.
    """
    events = []

    def deployment(action, operation):
        """Record deployment admission around the package lock.

        Args:
            action: Maintenance operation.
            operation: Admitted package-lock callback.
        """
        events.append("deployment")
        return operation()

    def package(operation):
        """Record exclusive package admission before dispatch.

        Args:
            operation: Bounded maintenance operation.
        """
        events.append("package")
        return operation()

    monkeypatch.setattr(helper, "_with_appliance_update_deployment_guard", deployment)
    monkeypatch.setattr(helper, "_with_package_transaction_guard", package)
    monkeypatch.setattr(helper, "_handle_appliance_update_locked", lambda action, args: events.append(action) or 0)
    for action in ("check", "apply", "sync-sources"):
        events.clear()
        assert helper._handle_appliance_update(action, []) == 0
        assert events == ["deployment", "package", action]


def test_partial_package_failure_is_never_verified_success(helper, monkeypatch):
    """An interrupted local RPM transaction retains failure and its attempted evidence.

    Args:
        helper: Privileged helper module.
        monkeypatch: Exact reviewed plan and package-manager failure replacements.
    """
    state = {"provider": "vmware", "review_digest": "a" * 64, "state": "missing", "available": True,
             "reason": "Compatible offline tools are ready.",
             "plan": {"package_change": True}, "packages": [{"name": "open-vm-tools", "installed": False}],
             "payload": {"available": True, "digest": "payload", "packages": [{"path": "/verified/open-vm-tools.rpm"}]}}
    monkeypatch.setattr(helper, "_guest_tools_status", lambda: dict(state))
    monkeypatch.setattr(helper, "_guest_tools_clock_guard", lambda **kwargs: {"success": True})
    monkeypatch.setattr(helper, "_guest_tools_payload", lambda provider: state["payload"])
    monkeypatch.setattr(helper, "_guest_tools_check", lambda payload: {
        "state": "available", "_transaction_packages": ["/verified/open-vm-tools.rpm"],
    })
    monkeypatch.setattr(helper.shutil, "which", lambda name: name)
    monkeypatch.setattr(helper, "_command_payload", lambda command, **kwargs: {
        "command": command, "success": "--test" in command, "returncode": 0 if "--test" in command else 1,
    })
    result = helper._guest_tools_apply({"guest_tools": {"provider": "vmware", "review_digest": "a" * 64}})
    assert result["status"] == "failed"
    assert result["attempted"]["guest_tools"]["state"] == "partial_failure"
    assert "applied" not in result


@pytest.mark.parametrize("defect", [None, "tamper", "extra", "signature", "architecture", "hardlink", "ancestor", "identity"])
def test_offline_payload_rejects_untrusted_or_incompatible_closures(helper, monkeypatch, tmp_path, defect):
    """Exercise exact coverage and RPM trust without granting access to a real package manager.

    Args:
        helper: Isolated helper module.
        monkeypatch: Root metadata and RPM-header/signature observation replacements.
        tmp_path: Receipt-bound synthetic package tree.
        defect: Independent trust or compatibility failure to inject.
    """
    root = tmp_path / "payload"
    root.mkdir()
    compatibility = {"schema": 1, "distribution": "photon", "release": "5.0", "architecture": "x86_64"}
    (root / "compatibility.json").write_text(json.dumps(compatibility))
    if defect == "identity":
        (root / "compatibility.json").write_text(json.dumps({**compatibility, "release": "6.0"}))
    names = {"vmware": "open-vm-tools", "hyperv": "hyper-v", "qemu": "atlaso-qemu-guest-agent"}
    manifest = []
    for provider, name in names.items():
        directory = root / provider
        directory.mkdir()
        package = directory / f"{name}.rpm"
        package.write_bytes(b"synthetic package fixture")
        manifest.append(f"{hashlib.sha256(package.read_bytes()).hexdigest()}  {provider}/{package.name}")
    (root / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
    if defect == "tamper":
        (root / "hyperv/hyper-v.rpm").write_bytes(b"changed unselected profile")
    if defect == "extra":
        (root / "unexpected.rpm").write_bytes(b"unexpected")

    class RootOwnedPath(type(tmp_path)):
        """Provide explicit synthetic POSIX metadata on the Windows test host."""

        def lstat(self, *args, **kwargs):
            """Keep real content while supplying the admitted root ownership contract.

            Args:
                *args: Native path stat arguments.
                **kwargs: Native path stat options.
            """
            metadata = super().lstat(*args, **kwargs)
            mode = stat.S_IFDIR | (0o700 if self == root or self.parent == root else 0o755) if self.is_dir() else stat.S_IFREG | 0o600
            if defect == "ancestor" and self == root.parent:
                mode = stat.S_IFDIR | 0o777
            return SimpleNamespace(st_mode=mode, st_uid=0, st_gid=0, st_size=metadata.st_size,
                                   st_nlink=2 if defect == "hardlink" and self.suffix == ".rpm" else 1)

    def rpm_observation(command, **kwargs):
        """Return bounded signed-RPM header evidence for the synthetic closure.

        Args:
            command: Allowlisted read-only RPM command.
            **kwargs: Command deadlines.
        """
        if "--checksig" in command:
            return subprocess.CompletedProcess(command, 1 if defect == "signature" else 0, "digests signatures OK", "")
        name = RootOwnedPath(command[-1]).stem
        architecture = "aarch64" if defect == "architecture" else "x86_64"
        return subprocess.CompletedProcess(command, 0, f"{name}\t0:1.0-1.ph5\t{architecture}\n", "")

    monkeypatch.setattr(helper, "Path", RootOwnedPath)
    monkeypatch.setattr(helper, "_guest_tools_runtime_compatibility", lambda: compatibility)
    monkeypatch.setattr(helper, "ATLASO_GUEST_TOOLS_PAYLOAD_DIR", RootOwnedPath(root))
    monkeypatch.setattr(helper, "ATLASO_FIRST_BOOT_GUEST_TOOLS_DIR", RootOwnedPath(tmp_path / "absent"))
    monkeypatch.setattr(helper.shutil, "which", lambda name: name)
    monkeypatch.setattr(helper, "_run", rpm_observation)
    result = helper._guest_tools_payload("vmware")
    assert result["available"] is (defect is None)
