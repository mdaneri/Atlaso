"""Tests for initrd trust verification before media installer execution."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _load_bootstrap():
    """Load the initrd entrypoint without executing its CLI."""
    path = Path("scripts/installation/bootstrap.py")
    spec = importlib.util.spec_from_file_location("installation_bootstrap_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _configure_cli(monkeypatch: pytest.MonkeyPatch, module, tmp_path: Path) -> Path:
    """Point the bootstrap at an untrusted-media fixture and local scratch."""
    media = tmp_path / "media"
    installer = media / "source/scripts/installation/installer.py"
    installer.parent.mkdir(parents=True)
    installer.write_text("raise RuntimeError('untrusted media executed')\n", encoding="utf-8")
    monkeypatch.setattr(module.sys, "argv", ["bootstrap.py", "--media", str(media)])

    class Scratch:
        def __enter__(self) -> str:
            return str(tmp_path)

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", lambda **_kwargs: Scratch())
    return media


def test_bootstrap_uses_initrd_pinned_verifier_and_executes_only_after_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_bootstrap()
    media = _configure_cli(monkeypatch, module, tmp_path)
    trusted_manifest = Path(module.verify_media.__globals__["__file__"]).resolve()
    events = []

    def verify(candidate: Path, trust_key: Path, *, scratch: Path) -> dict:
        events.append(("verify", candidate, trust_key, scratch))
        assert str(candidate) not in module.sys.path
        return {"schema": 1}

    def execv(executable: str, arguments: list[str]) -> None:
        events.append(("exec", executable, arguments))

    monkeypatch.setattr(module, "verify_media", verify)
    monkeypatch.setattr(module.os, "execv", execv)

    module.main()

    assert [event[0] for event in events] == ["verify", "exec"]
    assert events[0][1:] == (media, Path("/etc/atlaso-installer/trust.pem"), tmp_path)
    assert events[1][1] == module.sys.executable
    assert events[1][2] == [
        module.sys.executable,
        str(media / "source/scripts/installation/installer.py"),
        "--media",
        str(media),
    ]
    assert trusted_manifest == Path(module.__file__).with_name("manifest.py").resolve()


def test_failed_trusted_verification_never_executes_media_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_bootstrap()
    _configure_cli(monkeypatch, module, tmp_path)
    events = []

    def reject_media(*_args, **_kwargs) -> None:
        events.append("verify")
        raise ValueError("signature rejected")

    monkeypatch.setattr(module, "verify_media", reject_media)
    monkeypatch.setattr(module.os, "execv", lambda *_args: events.append("exec"))

    with pytest.raises(ValueError, match="signature rejected"):
        module.main()

    assert events == ["verify"]


def test_bootstrap_does_not_load_untrusted_media_module_before_exec(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_bootstrap()
    media = _configure_cli(monkeypatch, module, tmp_path)
    events = []
    monkeypatch.setattr(module, "verify_media", lambda *_args, **_kwargs: events.append("verified"))

    def execv(_executable: str, arguments: list[str]) -> None:
        events.append("exec")
        assert arguments[1] == str(media / "source/scripts/installation/installer.py")
        assert "installation_adapter" not in module.sys.modules
        assert "installer" not in module.sys.modules

    monkeypatch.setattr(module.os, "execv", execv)
    module.main()

    assert events == ["verified", "exec"]
