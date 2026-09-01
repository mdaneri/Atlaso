"""Test the temporary CPython 3.14 1Password wheel trust boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/windows/vmware/download-onepassword-wheel.py"
MANIFEST = ROOT / "scripts/windows/vmware/onepassword-sdk-cp314-wheel.json"


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("onepassword_wheel_download", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_checked_in_manifest_has_the_exact_approved_identity() -> None:
    module = _load_module()
    manifest = module.load_manifest(MANIFEST)

    assert manifest["asset_name"] == module.EXPECTED_ASSET
    assert manifest["wheel_tag"] == "cp314-cp314-win_amd64"
    assert manifest["license"] == "MIT"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("release_tag", "replaceable"),
        ("asset_name", "onepassword_sdk-0.4.1-cp314t-cp314t-win_amd64.whl"),
        ("asset_url", "https://example.invalid/wheel.whl"),
        ("asset_sha256", "0" * 63),
        ("wheel_tag", "cp314t-cp314t-win_amd64"),
    ),
)
def test_manifest_rejects_identity_drift(tmp_path: Path, field: str, value: Any) -> None:
    module = _load_module()
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload[field] = value
    candidate = tmp_path / "manifest.json"
    candidate.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="manifest|URL"):
        module.load_manifest(candidate)


def test_redirect_policy_rejects_non_github_hosts() -> None:
    module = _load_module()
    handler = module.ApprovedRedirectHandler()

    with pytest.raises(ValueError, match="unapproved"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.invalid/x")


class _Response(io.BytesIO):
    def __init__(self, content: bytes, *, url: str, declared_length: int | None = None):
        super().__init__(content)
        self._url = url
        self.headers = {}
        if declared_length is not None:
            self.headers["Content-Length"] = str(declared_length)

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class _Opener:
    def __init__(self, response: _Response):
        self.response = response
        self.timeout: int | None = None

    def open(self, request: object, timeout: int) -> _Response:
        self.timeout = timeout
        return self.response


def test_download_enforces_digest_size_timeout_and_filename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    content = b"verified-wheel"
    manifest = module.load_manifest(MANIFEST)
    manifest["asset_size"] = len(content)
    manifest["asset_sha256"] = hashlib.sha256(content).hexdigest()
    opener = _Opener(
        _Response(
            content,
            url="https://release-assets.githubusercontent.com/approved",
            declared_length=len(content),
        )
    )
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *args: opener)

    path = module.download(manifest, tmp_path, timeout=7, max_size=1024)

    assert path.name == module.EXPECTED_ASSET
    assert path.read_bytes() == content
    assert opener.timeout == 7


@pytest.mark.parametrize(("content", "declared_size"), ((b"bad", 3), (b"too-large", 3)))
def test_download_failure_leaves_no_wheel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
    declared_size: int,
) -> None:
    module = _load_module()
    manifest = module.load_manifest(MANIFEST)
    manifest["asset_size"] = declared_size
    manifest["asset_sha256"] = "f" * 64
    opener = _Opener(
        _Response(content, url="https://objects.githubusercontent.com/approved")
    )
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *args: opener)

    with pytest.raises(ValueError, match="approved size|digest and size"):
        module.download(manifest, tmp_path, timeout=1, max_size=4)

    assert not (tmp_path / module.EXPECTED_ASSET).exists()
    assert list(tmp_path.glob(".onepassword-wheel-*")) == []


def test_missing_release_fails_without_an_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()

    class MissingOpener:
        def open(self, request: object, timeout: int) -> None:
            raise module.urllib.error.URLError("release missing")

    monkeypatch.setattr(
        module.urllib.request, "build_opener", lambda *args: MissingOpener()
    )

    with pytest.raises(module.urllib.error.URLError, match="release missing"):
        module.download(
            module.load_manifest(MANIFEST), tmp_path, timeout=1, max_size=10_000_000
        )

    assert list(tmp_path.iterdir()) == []
