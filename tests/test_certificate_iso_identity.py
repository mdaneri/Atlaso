"""Exercise original ISO helper admission independently of signed wheel identity."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_iso_identity as identity  # noqa: E402 - Reviewed interop namespace.

from scripts.installation import inspection  # noqa: E402 - Repository media inspector.


@pytest.mark.parametrize("mismatch", [None, "software", "wheel", "helper"])
def test_iso_helper_uses_media_installer_source_and_refuses_unrelated_bytes(monkeypatch, mismatch):
    """Bind source choice, media, installed wheel, and concealed child environment.

    Args:
        monkeypatch: Replace media I/O and exact Git object reads.
        mismatch: Independent identity boundary to corrupt.
    """
    plan = {"trust_model": "trusted-host", "deployed_commit": "b" * 40,
            "appliance_ownership": {"path": "ownership"}, "installed_inspection": {"path": "installed"}}
    media = {"path": "original.iso", "sha256": "a" * 64}
    records = {"ownership": {"phase": "original-installation-vm-created", "installation_iso": media},
               "installed": {"source_commit": "b" * 40, "wheel_sha256": "d" * 64}}
    expected = {"source_commit": "b" * 40, "installer_source_commit": "c" * 40,
                "wheel_sha256": "d" * 64, "helper_sha256": hashlib.sha256(b"installer helper\n").hexdigest()}
    if mismatch == "software":
        records["installed"]["source_commit"] = "e" * 40
    if mismatch == "wheel":
        records["installed"]["wheel_sha256"] = "e" * 64
    monkeypatch.setattr(identity, "bound_json", lambda ref: records[ref["path"]])
    observed = []

    def inputs(path, checksum):
        """Require the original media reference before returning its public identities.

        Args:
            path: Original media path from the VM receipt.
            checksum: Original independently recorded media digest.
        """
        assert path == Path(media["path"]) and checksum == media["sha256"]
        return expected

    def git(arguments, **kwargs):
        """Allow only the installer Git object with native secret variables removed.

        Args:
            arguments: Exact Git object read.
            **kwargs: Bounded process options, including the sanitized environment.
        """
        observed.append(arguments[-1])
        assert arguments[-1] == "c" * 40 + ":scripts/appliance/atlaso-helper"
        assert not any(key.startswith("ATLASO_NATIVE_") for key in kwargs["env"])
        return SimpleNamespace(stdout=b"changed\n" if mismatch == "helper" else b"installer helper\r\n")

    monkeypatch.setattr(inspection, "helper_inputs", inputs)
    monkeypatch.setattr(identity.subprocess, "run", git)
    monkeypatch.setenv("ATLASO_NATIVE_PEER_KEY", "synthetic-never-propagated")
    if mismatch:
        with pytest.raises(ValueError, match="helper differs" if mismatch == "helper" else "software identity differs"):
            identity.reviewed_helper_identity(plan)
        assert bool(observed) is (mismatch == "helper")
    else:
        assert identity.reviewed_helper_identity(plan) == {
            "helper_source_commit": "c" * 40, "helper_sha256": expected["helper_sha256"]}
        assert len(observed) == 1
