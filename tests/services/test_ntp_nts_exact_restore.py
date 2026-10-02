"""Exact, fail-closed restoration for transient NTS server material."""

import os

import pytest

from tests.test_appliance_helper import load_helper_module


def _configure_roots(monkeypatch, tmp_path):
    """Configure isolated NTS material paths for the helper restore test.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper = load_helper_module()
    # The helper is deployed only on Photon/Linux. Unit tests on Windows mark
    # the real stdlib remover as the safe primitive exercised by these cases.
    monkeypatch.setattr(
        helper.shutil.rmtree, "avoids_symlink_attacks", True, raising=False
    )
    state_dir = tmp_path / "var" / "lib" / "ntp"
    cert_parent = tmp_path / "etc" / "atlaso" / "ntp"
    state_dir.mkdir(parents=True)
    cert_parent.mkdir(parents=True)
    cookie_path = state_dir / "nts-keys"
    cert_dir = cert_parent / "certs"
    monkeypatch.setattr(helper, "NTP_NTS_COOKIE_PATH", cookie_path)
    monkeypatch.setattr(helper, "NTP_CERT_DIR", cert_dir)
    return helper, cookie_path, cert_dir


def test_restore_removes_candidate_descendants_and_restores_rotated_bytes_and_modes(
    monkeypatch, tmp_path
):
    """Verify restore removes candidate descendants and restores rotated bytes and modes.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper, cookie_path, cert_dir = _configure_roots(monkeypatch, tmp_path)
    cookie_path.mkdir()
    (cookie_path / "nested").mkdir()
    prior_cookie = cookie_path / "nested" / "cookie"
    prior_cookie.write_bytes(b"prior cookie bytes")
    os.chmod(prior_cookie, 0o640)
    cert_dir.mkdir()
    prior_cert = cert_dir / "server.crt"
    prior_cert.write_bytes(b"prior certificate bytes")
    os.chmod(prior_cert, 0o644)
    snapshot = helper._ntpd_snapshot_nts_server_material()

    prior_cookie.write_bytes(b"rotated candidate cookie")
    (cookie_path / "candidate-only").mkdir()
    (cookie_path / "candidate-only" / "nested.key").write_bytes(b"candidate key")
    prior_cert.write_bytes(b"rotated candidate certificate")
    (cert_dir / "candidate-only").mkdir()
    (cert_dir / "candidate-only" / "extra.pem").write_bytes(b"candidate extra")
    shutil_rmtree_calls = []
    original_rmtree = helper.shutil.rmtree

    def recording_rmtree(path, *args, **kwargs):
        """Record the requested tree removal before delegating to the original remover.

        Args:
            path: Management endpoint path or owned filesystem root used by this operation.
            *args: Additional positional options forwarded to the filesystem remover.
            **kwargs: Additional result fields included in the JSON response.
        """
        shutil_rmtree_calls.append(path)
        return original_rmtree(path, *args, **kwargs)

    recording_rmtree.avoids_symlink_attacks = True
    monkeypatch.setattr(helper.shutil, "rmtree", recording_rmtree)
    helper._ntpd_restore_nts_server_material(snapshot)

    assert (cookie_path / "nested" / "cookie").read_bytes() == b"prior cookie bytes"
    assert (cert_dir / "server.crt").read_bytes() == b"prior certificate bytes"
    assert not (cookie_path / "candidate-only").exists()
    assert not (cert_dir / "candidate-only").exists()
    assert set(shutil_rmtree_calls) == {cookie_path, cert_dir}
    if os.name == "posix":
        assert os.stat(cookie_path / "nested" / "cookie").st_mode & 0o7777 == 0o640
        assert os.stat(cert_dir / "server.crt").st_mode & 0o7777 == 0o644


def test_restore_prior_file_root_over_candidate_directory(monkeypatch, tmp_path):
    """Verify restore prior file root over candidate directory.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper, cookie_path, cert_dir = _configure_roots(monkeypatch, tmp_path)
    cookie_path.write_bytes(b"previous cookie file")
    os.chmod(cookie_path, 0o600)
    snapshot = helper._ntpd_snapshot_nts_server_material()

    cookie_path.unlink()
    cookie_path.mkdir()
    (cookie_path / "new/nested").mkdir(parents=True)
    (cookie_path / "new/nested/candidate.key").write_bytes(b"not prior state")
    cert_dir.mkdir()
    (cert_dir / "candidate.crt").write_bytes(b"candidate cert")

    helper._ntpd_restore_nts_server_material(snapshot)

    assert cookie_path.is_file()
    assert cookie_path.read_bytes() == b"previous cookie file"
    assert not cert_dir.exists()
    if os.name == "posix":
        assert os.stat(cookie_path).st_mode & 0o7777 == 0o600


def test_restore_candidate_material_for_roots_absent_in_snapshot(monkeypatch, tmp_path):
    """Verify restore candidate material for roots absent in snapshot.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper, cookie_path, cert_dir = _configure_roots(monkeypatch, tmp_path)
    snapshot = helper._ntpd_snapshot_nts_server_material()
    assert len(snapshot) == 2
    assert all(entry["exists"] is False for entry in snapshot)

    cookie_path.mkdir()
    (cookie_path / "candidate").write_bytes(b"new cookie data")
    cert_dir.mkdir()
    (cert_dir / "candidate.key").write_bytes(b"new certificate data")

    helper._ntpd_restore_nts_server_material(snapshot)

    assert not cookie_path.exists()
    assert not cert_dir.exists()


def test_invalid_manifest_is_rejected_before_live_tree_changes(monkeypatch, tmp_path):
    """Verify invalid manifest is rejected before live tree changes.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper, cookie_path, cert_dir = _configure_roots(monkeypatch, tmp_path)
    cookie_path.mkdir()
    original = cookie_path / "candidate"
    original.write_bytes(b"keep on refusal")
    snapshot = helper._ntpd_snapshot_nts_server_material()
    snapshot[0]["path"] = tmp_path / "outside" / "secret"

    with pytest.raises(RuntimeError, match="fixed roots"):
        helper._ntpd_restore_nts_server_material(snapshot)

    assert original.read_bytes() == b"keep on refusal"
    assert not cert_dir.exists()


@pytest.mark.parametrize("unsafe_kind", ["symlink", "hardlink"])
def test_unsafe_live_node_in_either_root_refuses_before_any_deletion(
    monkeypatch, tmp_path, unsafe_kind
):
    """Verify unsafe live node in either root refuses before any deletion.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
        unsafe_kind: Unsafe filesystem node type used by the refusal case.
    """
    helper, cookie_path, cert_dir = _configure_roots(monkeypatch, tmp_path)
    cookie_path.mkdir()
    cookie_file = cookie_path / "candidate"
    cookie_file.write_bytes(b"first root remains untouched")
    snapshot = helper._ntpd_snapshot_nts_server_material()
    cert_dir.mkdir()
    unsafe_path = cert_dir / "unsafe"
    if unsafe_kind == "symlink":
        try:
            unsafe_path.symlink_to(cookie_file)
        except (OSError, NotImplementedError):
            pytest.skip("Symlink creation is unavailable on this host.")
    else:
        os.link(cookie_file, unsafe_path)

    with pytest.raises(RuntimeError, match="unsafe link or file type"):
        helper._ntpd_restore_nts_server_material(snapshot)

    assert cookie_file.read_bytes() == b"first root remains untouched"
    assert unsafe_path.exists() or unsafe_path.is_symlink()


def test_cleanup_failure_does_not_partially_recreate_snapshot(monkeypatch, tmp_path):
    """Verify cleanup failure does not partially recreate snapshot.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper, cookie_path, cert_dir = _configure_roots(monkeypatch, tmp_path)
    cookie_path.mkdir()
    original = cookie_path / "candidate"
    original.write_bytes(b"live candidate")
    snapshot = helper._ntpd_snapshot_nts_server_material()
    cert_dir.mkdir()
    (cert_dir / "candidate.key").write_bytes(b"candidate key")

    def fail_removal(_path):
        """Simulate an inability to remove the candidate NTS tree.

        Args:
            _path: Filesystem path accepted by the mocked remover but intentionally unused.
        """
        raise OSError("synthetic cleanup failure")

    fail_removal.avoids_symlink_attacks = True
    monkeypatch.setattr(helper.shutil, "rmtree", fail_removal)
    with pytest.raises(OSError, match="synthetic cleanup failure"):
        helper._ntpd_restore_nts_server_material(snapshot)

    assert original.read_bytes() == b"live candidate"
    assert (cert_dir / "candidate.key").read_bytes() == b"candidate key"


def test_directory_restore_requires_symlink_safe_rmtree_before_mutation(
    monkeypatch, tmp_path
):
    """Verify directory restore requires symlink safe rmtree before mutation.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper, cookie_path, cert_dir = _configure_roots(monkeypatch, tmp_path)
    cookie_path.mkdir()
    cookie_candidate = cookie_path / "candidate"
    cookie_candidate.write_bytes(b"cookie remains")
    snapshot = helper._ntpd_snapshot_nts_server_material()
    cert_dir.mkdir()
    cert_candidate = cert_dir / "candidate"
    cert_candidate.write_bytes(b"certificate remains")
    monkeypatch.setattr(
        helper.shutil.rmtree, "avoids_symlink_attacks", False, raising=False
    )

    with pytest.raises(RuntimeError, match="Safe NTS rollback tree removal"):
        helper._ntpd_restore_nts_server_material(snapshot)

    assert cookie_candidate.read_bytes() == b"cookie remains"
    assert cert_candidate.read_bytes() == b"certificate remains"


def test_absent_roots_restore_from_candidate_files_without_tree_remover(
    monkeypatch, tmp_path
):
    """Verify absent roots restore from candidate files without tree remover.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper, cookie_path, cert_dir = _configure_roots(monkeypatch, tmp_path)
    snapshot = helper._ntpd_snapshot_nts_server_material()
    cookie_path.write_bytes(b"candidate cookie")
    cert_dir.write_bytes(b"candidate certificate")
    monkeypatch.setattr(
        helper.shutil.rmtree, "avoids_symlink_attacks", False, raising=False
    )

    helper._ntpd_restore_nts_server_material(snapshot)

    assert not cookie_path.exists()
    assert not cert_dir.exists()


def test_interrupted_nts_rollback_marker_stops_and_retains_recovery_state(
    monkeypatch, tmp_path
):
    """Verify interrupted nts rollback marker stops and retains recovery state.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper, cookie_path, cert_dir = _configure_roots(monkeypatch, tmp_path)
    cookie_path.mkdir()
    cookie_file = cookie_path / "prior-cookie"
    cookie_file.write_bytes(b"in-memory-only-prior-cookie")
    cert_dir.mkdir()
    cert_file = cert_dir / "prior-cert"
    cert_file.write_bytes(b"in-memory-only-prior-cert")
    nts_material = helper._ntpd_snapshot_nts_server_material()

    config = tmp_path / "etc" / "ntp.conf"
    config.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", config)
    snapshot = {
        "exists": False,
        "managed": False,
        "mode": None,
        "data": None,
        "link_target": None,
        "file_mode": None,
        "uid": None,
        "gid": None,
        "nts_material": nts_material,
    }
    helper._ntpd_begin_transaction(snapshot)
    candidate_config = b"# unverified candidate config\n"
    config.write_bytes(candidate_config)
    monkeypatch.setattr(helper, "_release_transaction_owner_alive", lambda _owner: False)
    stops = []
    monkeypatch.setattr(
        helper, "_ntpd_fail_closed_stop", lambda: stops.append("stop") or []
    )
    monkeypatch.setattr(
        helper,
        "_ntpd_restore_applied_config",
        lambda *_args, **_kwargs: pytest.fail("Recovery must not restore config-only state."),
    )

    with pytest.raises(RuntimeError, match="lacks in-memory exact material proof"):
        helper._ntpd_recover_interrupted_apply()

    journal = helper._ntpd_read_transaction()
    assert stops == ["stop"]
    assert journal is not None
    assert journal["nts_restore_pending"] is True
    assert helper._ntpd_transaction_path().exists()
    assert config.read_bytes() == candidate_config
    assert cookie_file.read_bytes() == b"in-memory-only-prior-cookie"
    assert cert_file.read_bytes() == b"in-memory-only-prior-cert"
    serialized = helper._ntpd_transaction_path().read_bytes()
    assert b"nts_restore_pending" in serialized
    assert b"in-memory-only-prior-cookie" not in serialized
    assert b"in-memory-only-prior-cert" not in serialized


def test_transaction_rewrite_preserves_nts_restore_barrier(monkeypatch, tmp_path):
    """Verify transaction rewrite preserves nts restore barrier.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies at the test boundary.
        tmp_path: Per-test temporary filesystem root for the NTS material snapshot.
    """
    helper, _cookie_path, _cert_dir = _configure_roots(monkeypatch, tmp_path)
    config = tmp_path / "etc" / "ntp.conf"
    config.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(helper, "NTP_CONFIG_PATH", config)
    snapshot = {
        "exists": False,
        "managed": False,
        "mode": None,
        "data": None,
        "link_target": None,
        "file_mode": None,
        "uid": None,
        "gid": None,
        "nts_material": [],
    }

    helper._ntpd_begin_transaction(snapshot)
    snapshot.pop("nts_material")
    helper._ntpd_begin_transaction(snapshot)

    payload = helper._ntpd_read_transaction()
    assert payload is not None
    assert payload["nts_restore_pending"] is True
