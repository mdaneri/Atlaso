"""Quiesced NTS custody, interruption and lifecycle-hook exclusion."""

import pytest

from tests.test_appliance_helper import load_helper_module


def _prepare_apply(monkeypatch, tmp_path, *, prior_nts=True, candidate_mode="ntp_client"):
    """Prepare real isolated files and replace privileged host operations.

    Args:
        monkeypatch: Replace service, validation and guard operations.
        tmp_path: Isolated configuration and synthetic cookie fixture.
        prior_nts: Whether the prior managed controller is an NTS server.
        candidate_mode: Clock mode staged for the attempted transition.
    """
    helper = load_helper_module()
    config = tmp_path / "ntp.conf"
    prior_mode = "ntp_server" if prior_nts else "ntp_client"
    config.write_text(
        f"# Atlaso NTP enabled: {str(prior_nts).lower()}\n"
        f"# Atlaso time mode: {prior_mode}\n" + ("nts enable\n" if prior_nts else ""),
        encoding="utf-8",
    )
    candidate = tmp_path / "candidate.conf"
    candidate.write_text(
        ("# Atlaso NTP enabled: true\n# Atlaso time mode: ntp_server\nnts enable\n"
         if candidate_mode == "ntp_server" else
         "# Atlaso NTP enabled: false\n" +
         ("" if candidate_mode == "disabled" else f"# Atlaso time mode: {candidate_mode}\n")),
        encoding="utf-8",
    )
    cookies = tmp_path / "cookies"
    cookies.mkdir()
    (cookies / "old").write_bytes(b"synthetic prior cookie")
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", config)
    monkeypatch.setattr(helper, "NTP_NTS_COOKIE_PATH", cookies)
    monkeypatch.setattr(helper, "NTP_CERT_DIR", tmp_path / "certs")
    monkeypatch.setattr(helper.shutil.rmtree, "avoids_symlink_attacks", True, raising=False)
    monkeypatch.setattr(helper, "_validate_ntpd_config_path", lambda _value: candidate)
    monkeypatch.setattr(helper, "_ntpd_config_errors", lambda *_args: [])
    monkeypatch.setattr(helper, "_ntpd_runtime_identity_errors", lambda: [])
    monkeypatch.setattr(helper, "_ntpd_install_guards", lambda: None)
    monkeypatch.setattr(helper, "_ntpd_fail_closed_stop", lambda: [])
    return helper, config, candidate, cookies, prior_mode


@pytest.mark.parametrize(
    ("prior_nts", "candidate_mode"),
    [(True, "ntp_client"), (False, "ntp_server"), (True, "disabled")],
)
def test_apply_captures_final_cookie_rotation_only_after_stop(
    monkeypatch, tmp_path, prior_nts, candidate_mode
):
    """Rollback preserves the key added at the prior controller's final stop.

    Args:
        monkeypatch: Replace service operations while retaining real custody code.
        tmp_path: Isolated synthetic configuration and material fixture.
        prior_nts: Whether the prior controller requires NTS custody.
        candidate_mode: Client, first NTS server or legacy disabled candidate.
    """
    helper, config, candidate, cookies, prior_mode = _prepare_apply(
        monkeypatch, tmp_path, prior_nts=prior_nts, candidate_mode=candidate_mode
    )
    prior_bytes = config.read_bytes()
    running = [True]
    order = []
    real_capture = helper._ntpd_snapshot_nts_server_material
    begin_transaction = helper._ntpd_begin_transaction
    handoff_hook_checked = False

    def begin_with_handoff_check(snapshot, **kwargs):
        """Run an external Tools hook at the prepared restore-custody handoff.

        Args:
            snapshot: Prior config and captured material supplied to the journal writer.
            **kwargs: Pending markers supplied to the journal writer.
        """
        nonlocal handoff_hook_checked
        begin_transaction(snapshot, **kwargs)
        if kwargs.get("nts_restore_pending") and not handoff_hook_checked:
            before_hook = real_capture()
            assert helper._ntpd_guard("post-vmtoolsd") == 0
            assert real_capture() == before_hook
            handoff_hook_checked = True
            order.append("handoff-hook-deferred")

    def stop(unit, **_kwargs):
        """Simulate final daemon rotation before reporting verified inactivity.

        Args:
            unit: Clock-controller service that must be stopped.
            **_kwargs: Service-stop options retained by the caller.
        """
        assert unit == "ntpd.service"
        journal = helper._ntpd_read_transaction()
        assert journal["nts_capture_pending"] is True
        assert journal.get("nts_restore_pending") is not True
        assert config.read_bytes() == prior_bytes
        (cookies / "final").write_bytes(b"synthetic final prior cookie")
        running[0] = False
        order.append("stop")

    def capture():
        """Capture only while the simulated controller is inactive."""
        assert running[0] is False
        order.append("capture")
        return real_capture()

    def transition(mode, config_path=None, **_kwargs):
        """Fail the candidate and verify restored prior authority.

        Args:
            mode: Candidate or prior managed clock mode.
            config_path: Staged candidate path, or absent during rollback.
            **_kwargs: Controller restart options retained by the caller.
        """
        if mode == candidate_mode:
            journal = helper._ntpd_read_transaction()
            assert journal["nts_restore_pending"] is True
            assert journal.get("nts_capture_pending") is not True
            (cookies / "final").write_bytes(b"synthetic candidate rotation")
            (cookies / "candidate-only").write_bytes(b"synthetic candidate cookie")
            raise RuntimeError("candidate could not synchronize")
        assert mode == prior_mode and config_path is None
        assert config.read_bytes() == prior_bytes
        assert (cookies / "final").read_bytes() == b"synthetic final prior cookie"
        assert not (cookies / "candidate-only").exists()
        order.append("prior-restart")
        running[0] = True

    monkeypatch.setattr(helper, "_ntpd_stop_service", stop)
    monkeypatch.setattr(helper, "_ntpd_snapshot_nts_server_material", capture)
    monkeypatch.setattr(helper, "_ntpd_begin_transaction", begin_with_handoff_check)
    monkeypatch.setattr(helper, "_ntpd_transition", transition)
    # Linux proves this through /proc; the platform-neutral fixture marks the
    # synthetic owner live so the lifecycle hook exercises the handoff branch.
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: True)
    assert helper._handle_ntpd("apply", [str(candidate)]) == 1
    assert order[:3] == ["stop", "capture", "handoff-hook-deferred"]
    assert order[-1] == "prior-restart"
    assert handoff_hook_checked
    assert helper._ntpd_read_transaction() is None and running[0] is True


@pytest.mark.parametrize("failure", ["stop", "capture"])
def test_capture_preparation_failure_restores_prior_without_candidate_mutation(
    monkeypatch, tmp_path, failure
):
    """Pre-candidate failure retains existing material and recovers prior intent.

    Args:
        monkeypatch: Inject a stop or custody capture failure.
        tmp_path: Isolated prior managed NTS state.
        failure: Preparation operation that must fail before candidate writes.
    """
    helper, config, candidate, cookies, prior_mode = _prepare_apply(monkeypatch, tmp_path)
    prior_bytes = config.read_bytes()
    events = []

    def stop(_unit, **_kwargs):
        """Fail stopping or allow the capture stage to proceed.

        Args:
            _unit: NTPsec service selected for quiescence.
            **_kwargs: Unused service-stop options.
        """
        events.append("stop")
        if failure == "stop":
            raise RuntimeError("stop verification failed")

    def capture():
        """Refuse material capture before any candidate mutation."""
        events.append("capture")
        raise RuntimeError("capture failed")

    def prior_transition(mode, config_path=None, **_kwargs):
        """Verify that only the unchanged prior controller is restored.

        Args:
            mode: Prior clock mode being reactivated.
            config_path: No staged candidate may be passed during rollback.
            **_kwargs: Prior-controller restart options.
        """
        assert mode == prior_mode and config_path is None
        assert config.read_bytes() == prior_bytes
        assert (cookies / "old").read_bytes() == b"synthetic prior cookie"
        assert helper._ntpd_read_transaction().get("nts_capture_pending") is not True
        events.append("prior-restart")

    monkeypatch.setattr(helper, "_ntpd_stop_service", stop)
    monkeypatch.setattr(helper, "_ntpd_snapshot_nts_server_material", capture)
    monkeypatch.setattr(helper, "_ntpd_transition", prior_transition)
    monkeypatch.setattr(
        helper, "_ntpd_write_managed_file",
        lambda *_args: pytest.fail("candidate config must not be written"),
    )
    assert helper._handle_ntpd("apply", [str(candidate)]) == 1
    assert events == (["stop", "prior-restart"] if failure == "stop" else
                      ["stop", "capture", "prior-restart"])
    assert helper._ntpd_read_transaction() is None


def test_interrupted_capture_recovers_config_only_without_material_loss(monkeypatch, tmp_path):
    """A killed pre-candidate capture has not earned a private-material barrier.

    Args:
        monkeypatch: Simulate helper interruption and a dead transaction owner.
        tmp_path: Isolated config, journal and synthetic cookie paths.
    """
    helper, config, candidate, cookies, _mode = _prepare_apply(monkeypatch, tmp_path)
    prior_bytes = config.read_bytes()
    monkeypatch.setattr(helper, "_ntpd_stop_service", lambda *_args: None)

    def interrupted_capture():
        """Interrupt without candidate config or NTS material mutation."""
        raise KeyboardInterrupt

    monkeypatch.setattr(helper, "_ntpd_snapshot_nts_server_material", interrupted_capture)
    with pytest.raises(KeyboardInterrupt):
        helper._handle_ntpd("apply", [str(candidate)])
    journal = helper._ntpd_read_transaction()
    assert journal["nts_capture_pending"] is True
    assert journal.get("nts_restore_pending") is not True
    assert config.read_bytes() == prior_bytes
    assert b"synthetic prior cookie" not in helper._ntpd_transaction_path().read_bytes()
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: False)
    helper._ntpd_recover_interrupted_apply()
    assert config.read_bytes() == prior_bytes
    assert (cookies / "old").read_bytes() == b"synthetic prior cookie"
    assert helper._ntpd_read_transaction() is None


@pytest.mark.parametrize("phase", ["pre-ntpd", "pre-vmtoolsd", "post-vmtoolsd", "boot"])
def test_live_capture_hooks_cannot_restart_or_mutate_controllers(monkeypatch, tmp_path, phase):
    """Service hooks preserve the interval between verified stop and capture.

    Args:
        monkeypatch: Report a live capture owner and refuse native operations.
        tmp_path: Isolated managed configuration and journal fixture.
        phase: Service or boot hook that must defer during capture.
    """
    helper, _config, _candidate, _cookies, _mode = _prepare_apply(monkeypatch, tmp_path)
    helper._ntpd_begin_transaction(helper._ntpd_snapshot_applied_config(), nts_capture_pending=True)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: True)
    for operation in ("_ntpd_stop_service", "_ntpd_start_service", "_ntpd_run_checked",
                      "_ntpd_client_packet_guard", "_ntpd_set_vmware_timesync"):
        monkeypatch.setattr(helper, operation, lambda *_args, **_kwargs: pytest.fail("hook mutated capture interval"))
    assert helper._ntpd_guard(phase) == (1 if phase == "pre-ntpd" else 0)


@pytest.mark.parametrize("mode", ["ntp_client", "ntp_server", "vmware_tools"])
@pytest.mark.parametrize("phase", ["pre-ntpd", "pre-vmtoolsd", "post-vmtoolsd", "boot"])
def test_restore_pending_hooks_defer_until_candidate_start_is_authorized(
    monkeypatch, tmp_path, mode, phase
):
    """No lifecycle hook may select either controller during the candidate handoff.

    Args:
        monkeypatch: Replace host mutations and preserve the live Apply owner.
        tmp_path: Isolated managed configuration, journal and synthetic cookie fixture.
        mode: Candidate clock source recorded in the installed config.
        phase: Service lifecycle boundary executing before start authorization.
    """
    helper, config, candidate, _cookies, _prior_mode = _prepare_apply(
        monkeypatch, tmp_path, candidate_mode=mode
    )
    config.write_bytes(candidate.read_bytes())
    helper._ntpd_begin_transaction(helper._ntpd_snapshot_applied_config(), nts_restore_pending=True)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: True)
    for operation in (
        "_ntpd_stop_service",
        "_ntpd_start_service",
        "_ntpd_run_checked",
        "_ntpd_client_packet_guard",
        "_ntpd_set_vmware_timesync",
    ):
        monkeypatch.setattr(
            helper,
            operation,
            lambda *_args, **_kwargs: pytest.fail("lifecycle hook mutated pending NTS custody"),
        )

    assert helper._ntpd_guard(phase) == (1 if phase == "pre-ntpd" else 0)


@pytest.mark.parametrize("phase", ["boot", "pre-vmtoolsd", "post-vmtoolsd"])
def test_authorized_restore_pending_still_defers_external_lifecycle_hooks(
    monkeypatch, tmp_path, phase
):
    """External lifecycle hooks remain deferred even after Apply authorizes ntpd.

    Args:
        monkeypatch: Replace host mutations and preserve the live Apply owner.
        tmp_path: Isolated candidate config and recovery journal fixture.
        phase: External lifecycle boundary that must not alter the handoff.
    """
    helper, config, candidate, _cookies, _prior_mode = _prepare_apply(monkeypatch, tmp_path)
    config.write_bytes(candidate.read_bytes())
    helper._ntpd_begin_transaction(helper._ntpd_snapshot_applied_config(), nts_restore_pending=True)
    transaction = helper._ntpd_read_transaction()
    assert transaction is not None
    transaction["nts_start_authorized_sha256"] = helper.hashlib.sha256(config.read_bytes()).hexdigest()
    helper._ntpd_write_transaction(transaction)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: True)
    for operation in (
        "_ntpd_stop_service",
        "_ntpd_start_service",
        "_ntpd_run_checked",
        "_ntpd_client_packet_guard",
        "_ntpd_set_vmware_timesync",
    ):
        monkeypatch.setattr(
            helper,
            operation,
            lambda *_args, **_kwargs: pytest.fail("external hook mutated authorized Apply"),
        )

    assert helper._ntpd_guard(phase) == 0


@pytest.mark.parametrize("mode", ["ntp_client", "ntp_server"])
def test_authorized_candidate_ntpd_prestart_accepts_matching_config_hash(monkeypatch, tmp_path, mode):
    """The owning Apply may pass pre-start only for its exact installed config.

    Args:
        monkeypatch: Replace native service operations for the lifecycle guard.
        tmp_path: Isolated staged and applied clock config fixture.
        mode: NTP controller mode authorized by the active Apply.
    """
    helper, config, candidate, _cookies, _prior_mode = _prepare_apply(
        monkeypatch, tmp_path, candidate_mode=mode
    )
    config.write_bytes(candidate.read_bytes())
    helper._ntpd_begin_transaction(helper._ntpd_snapshot_applied_config(), nts_restore_pending=True)
    transaction = helper._ntpd_read_transaction()
    assert transaction is not None
    transaction["nts_start_authorized_sha256"] = helper.hashlib.sha256(config.read_bytes()).hexdigest()
    helper._ntpd_write_transaction(transaction)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: True)
    operations = []
    monkeypatch.setattr(helper, "_ntpd_stop_service", lambda unit, **_kwargs: operations.append(("stop", unit)))
    monkeypatch.setattr(helper, "_ntpd_client_packet_guard", lambda selected: operations.append(("guard", selected)))
    monkeypatch.setattr(helper, "_ntpd_set_vmware_timesync", lambda enabled: operations.append(("vmware", enabled)))
    monkeypatch.setattr(helper, "_ntpd_run_checked", lambda command, _action: operations.append(("run", command)))

    assert helper._ntpd_guard("pre-ntpd") == 0
    assert ("guard", mode) in operations
    assert ("vmware", False) in operations


def test_candidate_start_persists_exact_hash_before_systemctl_start(monkeypatch, tmp_path):
    """The NTP helper records authorization durably before issuing systemctl start.

    Args:
        monkeypatch: Replace systemd calls and report the selected service active.
        tmp_path: Isolated applied config and prepared transaction fixture.
    """
    helper, config, candidate, _cookies, _prior_mode = _prepare_apply(monkeypatch, tmp_path)
    config.write_bytes(candidate.read_bytes())
    helper._ntpd_begin_transaction(helper._ntpd_snapshot_applied_config(), nts_restore_pending=True)
    expected_hash = helper.hashlib.sha256(config.read_bytes()).hexdigest()
    operations = []

    def record_checked(command, _action):
        """Record the journal hash visible before each systemd operation.

        Args:
            command: Systemd command issued by the helper.
            _action: Human-readable operation description supplied by the helper.
        """
        transaction = helper._ntpd_read_transaction()
        operations.append((command, transaction.get("nts_start_authorized_sha256")))

    monkeypatch.setattr(helper, "_ntpd_run_checked", record_checked)
    monkeypatch.setattr(helper, "_ntpd_service_state", lambda _unit: {"active": True, "enabled": True})

    helper._ntpd_start_service("ntpd.service")

    assert operations == [
        (["systemctl", "enable", "ntpd.service"], expected_hash),
        (["systemctl", "start", "ntpd.service"], expected_hash),
    ]


def test_candidate_prestart_refuses_changed_config_hash(monkeypatch, tmp_path):
    """A changed applied candidate cannot reuse a prior start authorization.

    Args:
        monkeypatch: Preserve a live Apply owner and forbid controller mutations.
        tmp_path: Isolated staged/applied configs and authorization journal fixture.
    """
    helper, config, candidate, _cookies, _prior_mode = _prepare_apply(monkeypatch, tmp_path)
    config.write_bytes(candidate.read_bytes())
    helper._ntpd_begin_transaction(helper._ntpd_snapshot_applied_config(), nts_restore_pending=True)
    transaction = helper._ntpd_read_transaction()
    assert transaction is not None
    transaction["nts_start_authorized_sha256"] = "0" * 64
    helper._ntpd_write_transaction(transaction)
    config.write_bytes(config.read_bytes() + b"# changed after authorization\n")
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: True)
    monkeypatch.setattr(
        helper,
        "_ntpd_stop_service",
        lambda *_args, **_kwargs: pytest.fail("unauthorized pre-start must not alter services"),
    )

    assert helper._ntpd_guard("pre-ntpd") == 1


@pytest.mark.parametrize("invalid_hash", ["not-a-digest", "A" * 64])
def test_malformed_start_authorization_fails_closed(monkeypatch, tmp_path, invalid_hash, capsys):
    """Malformed journal authorization cannot pass the NTPsec start guard.

    Args:
        monkeypatch: Preserve a live Apply owner and forbid service mutations.
        tmp_path: Isolated applied config and recovery journal fixture.
        invalid_hash: Malformed digest representation stored in the journal.
        capsys: Pytest fixture for capturing the fail-closed diagnostic.
    """
    helper, config, candidate, _cookies, _prior_mode = _prepare_apply(monkeypatch, tmp_path)
    config.write_bytes(candidate.read_bytes())
    helper._ntpd_begin_transaction(helper._ntpd_snapshot_applied_config(), nts_restore_pending=True)
    transaction = helper._ntpd_read_transaction()
    assert transaction is not None
    transaction["nts_start_authorized_sha256"] = invalid_hash
    helper._ntpd_write_transaction(transaction)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: True)
    monkeypatch.setattr(
        helper,
        "_ntpd_stop_service",
        lambda *_args, **_kwargs: pytest.fail("malformed authorization must not mutate services"),
    )

    assert helper._ntpd_guard("pre-ntpd") == 1
    assert "NTS start authorization is invalid" in capsys.readouterr().err


def test_rollback_journal_rewrite_clears_candidate_start_authorization(monkeypatch, tmp_path):
    """Rollback custody cannot retain a hash authorizing the failed candidate.

    Args:
        monkeypatch: Replace fixed appliance paths with isolated test paths.
        tmp_path: Isolated applied config and prepared journal fixture.
    """
    helper, config, candidate, _cookies, _prior_mode = _prepare_apply(monkeypatch, tmp_path)
    config.write_bytes(candidate.read_bytes())
    snapshot = helper._ntpd_snapshot_applied_config()
    snapshot["nts_material"] = []
    helper._ntpd_begin_transaction(snapshot, nts_restore_pending=True)
    transaction = helper._ntpd_read_transaction()
    assert transaction is not None
    transaction["nts_start_authorized_sha256"] = helper.hashlib.sha256(config.read_bytes()).hexdigest()
    helper._ntpd_write_transaction(transaction)

    # The next prepared checkpoint is the one used before failed-candidate stop.
    helper._ntpd_begin_transaction(snapshot, nts_restore_pending=True)

    rewritten = helper._ntpd_read_transaction()
    assert rewritten is not None
    assert rewritten["nts_restore_pending"] is True
    assert "nts_start_authorized_sha256" not in rewritten
