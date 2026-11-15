"""Keep the original ISO's installer helper distinct from its signed wheel."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

from certificate_iso_deployment import admit_deployment
from certificate_peer_proof import bound_json


def reviewed_helper_identity(plan: dict) -> dict:
    """Admit exact helper bytes without relabelling the installed wheel's source.

    Args:
        plan: Original receipt-bound certificate validation plan.
    """
    commit = plan["deployed_commit"]
    expected = None
    ova_selected = plan.get("appliance_media") == "ova"
    if ova_selected and plan.get("trust_model") != "trusted-host":
        raise ValueError("original OVA requires trusted-host identity")
    if plan.get("trust_model") == "trusted-host":
        ownership = bound_json(plan["appliance_ownership"])
        if not ova_selected and ownership.get("phase") == "original-installation-vm-created":
            from scripts.installation.inspection import helper_inputs

            media = ownership["installation_iso"]
            expected = helper_inputs(Path(media["path"]), media["sha256"])
            installed = bound_json(plan["installed_inspection"])
            if (installed.get("source_commit") != expected["source_commit"]
                    or installed.get("wheel_sha256") != expected["wheel_sha256"]):
                raise ValueError("original ISO software identity differs")
            if "iso_wheel_deployment" in plan:
                admit_deployment(plan)
            elif expected["source_commit"] != plan["deployed_commit"]:
                raise ValueError("original ISO software identity differs")
            commit = expected["installer_source_commit"]
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ATLASO_NATIVE_")}
    repository = Path(__file__).resolve().parents[2]
    if ova_selected:
        from scripts.interop.certificate_ova_identity import admit_ova_runtime
        from scripts.interop.certificate_peer_factory import require_ancestor

        if ownership.get("phase") != "ova-import-original":
            raise ValueError("original OVA ownership receipt required")
        repository = Path(ownership["worktree"])
        require_ancestor(repository, commit, plan["source_commit"])
        ova = admit_ova_runtime(plan)
    else:
        ova = None
    raw = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repository), "show", commit + ":scripts/appliance/atlaso-helper"],
        capture_output=True, check=True, env=environment, timeout=15,
    ).stdout
    checksum = hashlib.sha256(raw.replace(b"\r\n", b"\n") if expected else raw).hexdigest()
    if ova is not None and checksum != ova["helper_sha256"]:
        raise ValueError("original OVA helper differs from exact deployed source")
    if expected and checksum != expected["helper_sha256"]:
        raise ValueError("original ISO helper differs from exact installer source")
    return {"helper_source_commit": commit, "helper_sha256": checksum}
