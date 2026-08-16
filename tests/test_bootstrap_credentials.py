"""Focused bootstrap administrator credential-verifier coverage."""

from __future__ import annotations

from atlaso.app.services import bootstrap_credentials


def test_bootstrap_password_uses_configured_value_before_rotation(tmp_path):
    """An appliance without a rotated verifier retains its image credential.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated verifier state.
    """
    verifier = tmp_path / "bootstrap-admin-password.hash"

    assert bootstrap_credentials.bootstrap_admin_password_matches(
        "Image-Password1!",
        "Image-Password1!",
        verifier_path=verifier,
    )
    assert not bootstrap_credentials.bootstrap_admin_password_matches(
        "wrong",
        "Image-Password1!",
        verifier_path=verifier,
    )


def test_bootstrap_password_rotation_writes_argon2_and_replaces_fallback(monkeypatch, tmp_path):
    """A rotated verifier authenticates only the selected new password.

    Args:
        monkeypatch: Pytest fixture used to replace privileged ownership handling.
        tmp_path: Temporary directory provided by pytest for isolated verifier state.
    """
    verifier = tmp_path / "etc" / "atlaso" / "bootstrap-admin-password.hash"
    password = "Selected-New1!"
    monkeypatch.setattr(bootstrap_credentials.shutil, "chown", lambda *_args, **_kwargs: None)

    bootstrap_credentials.write_bootstrap_admin_password_verifier(
        password,
        verifier_path=verifier,
    )

    assert verifier.read_text(encoding="utf-8").startswith("$argon2")
    assert bootstrap_credentials.bootstrap_admin_password_matches(
        password,
        "Image-Password1!",
        verifier_path=verifier,
    )
    assert not bootstrap_credentials.bootstrap_admin_password_matches(
        "Image-Password1!",
        "Image-Password1!",
        verifier_path=verifier,
    )


def test_malformed_bootstrap_verifier_fails_closed(tmp_path):
    """Malformed persisted verifier state cannot reactivate the image password.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated verifier state.
    """
    verifier = tmp_path / "bootstrap-admin-password.hash"
    verifier.write_text("not-an-argon2-verifier\n", encoding="utf-8")

    assert not bootstrap_credentials.bootstrap_admin_password_matches(
        "Image-Password1!",
        "Image-Password1!",
        verifier_path=verifier,
    )


def test_broken_symlink_bootstrap_verifier_fails_closed(tmp_path):
    """A broken verifier symlink cannot reactivate the image password.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated verifier state.
    """
    verifier = tmp_path / "bootstrap-admin-password.hash"
    verifier.symlink_to(tmp_path / "missing-verifier")

    assert not bootstrap_credentials.bootstrap_admin_password_matches(
        "Image-Password1!",
        "Image-Password1!",
        verifier_path=verifier,
    )
