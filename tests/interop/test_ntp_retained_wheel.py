"""The original NTP wheel must survive reboot without weakening payload proof."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_native as fixture  # noqa: E402 - Local interop entrypoint.
from certificate_peer_proof import Refusal as ReceiptRefusal  # noqa: E402 - Local receipt module.


def write_receipt(path, value):
    """Publish a test receipt and its independent content reference.

    Args:
        path: New test receipt path.
        value: Public synthetic receipt fields.
    """
    payload = json.dumps(value).encode()
    path.write_bytes(payload)
    return {"path": str(path), "sha256": hashlib.sha256(payload).hexdigest()}


@pytest.fixture
def retained_plan(tmp_path):
    """Build independently hashed original intent and result receipts.

    Args:
        tmp_path: Isolated pytest resource root.
    """
    common = {"schema": 1, "task_id": "task", "repository": "mdaneri/Atlaso", "pr": 1121,
              "source_commit": "a" * 40, "wheel_name": "atlaso-0.9.485-py3-none-any.whl",
              "wheel_sha256": "b" * 64, "appliance_vmx": "original.vmx",
              "appliance_ownership_sha256": "c" * 64, "deployed_runtime_sha256": "d" * 64}
    common["guest_path"] = "/var/lib/atlaso/ntp-acceptance/" + common["wheel_name"]
    intent = {**common, "kind": "ntp-wheel-retention-intent", "source_path": "/tmp/" + common["wheel_name"]}
    intent_ref = write_receipt(tmp_path / "ntp-wheel-retention-intent.json", intent)
    retained = {**common, "kind": "ntp-retained-wheel", "retention_intent_sha256": intent_ref["sha256"],
                "owner_uid": 0, "owner_gid": 0, "mode": "0600", "links": 1, "verified_before_reboot": True}
    plan = {key: common[key] for key in ("task_id", "repository", "pr", "source_commit", "wheel_name", "wheel_sha256")}
    plan.update(trusted_host={"appliance_vmx": common["appliance_vmx"]},
                appliance_ownership={"sha256": common["appliance_ownership_sha256"]},
                deployed_runtime={"sha256": common["deployed_runtime_sha256"]},
                retained_wheel=write_receipt(tmp_path / "ntp-retained-wheel.json", retained))
    return plan


def test_original_wheel_receipts_admit_only_the_fixed_persistent_path(retained_plan):
    """An original intent/result pair identifies the pre-reboot measured artifact.

    Args:
        retained_plan: Plan with independently hashed synthetic receipts.
    """
    assert fixture.retained_wheel_path(retained_plan) == "/var/lib/atlaso/ntp-acceptance/" + retained_plan["wheel_name"]


@pytest.mark.parametrize(("field", "value"), [
    ("task_id", "foreign"), ("source_commit", "e" * 40), ("appliance_vmx", "foreign.vmx"),
    ("appliance_ownership_sha256", "e" * 64), ("deployed_runtime_sha256", "e" * 64),
    ("wheel_sha256", "e" * 64), ("guest_path", "/tmp/substitute.whl"),
    ("owner_uid", 1), ("owner_gid", 1), ("mode", "0644"), ("links", 2), ("verified_before_reboot", False),
])
def test_rehashed_foreign_or_unsafe_retention_is_refused(retained_plan, field, value):
    """A self-consistent substituted result cannot change original custody bindings.

    Args:
        retained_plan: Original synthetic plan.
        field: Receipt binding to substitute.
        value: Foreign or unsafe replacement value.
    """
    path = Path(retained_plan["retained_wheel"]["path"])
    receipt = json.loads(path.read_bytes())
    receipt[field] = value
    retained_plan["retained_wheel"] = write_receipt(path, receipt)
    with pytest.raises(fixture.Refusal, match="retained_wheel_binding_invalid"):
        fixture.retained_wheel_path(retained_plan)


def test_modified_original_intent_is_refused_before_guest_access(retained_plan):
    """Changing the intent bytes cannot be hidden by rehashing only the result.

    Args:
        retained_plan: Plan with the original independent intent digest.
    """
    path = Path(retained_plan["retained_wheel"]["path"]).with_name("ntp-wheel-retention-intent.json")
    value = json.loads(path.read_bytes())
    value["source_path"] = "/tmp/foreign.whl"
    write_receipt(path, value)
    with pytest.raises(ReceiptRefusal, match="receipt_digest_changed"):
        fixture.retained_wheel_path(retained_plan)


@pytest.mark.parametrize("changed", [False, True])
def test_post_reboot_payload_still_requires_the_complete_original_measurement(retained_plan, monkeypatch, changed):
    """Using persistent storage must preserve the complete wheel/installed payload proof.

    Args:
        retained_plan: Original admitted wheel plan.
        monkeypatch: Scoped inspection and transport substitutions.
        changed: Whether the installed payload differs after reboot.
    """
    expected = {"helper_sha256": "e" * 64, "wheel_sha256": "b" * 64,
                "wheel_payload_sha256": "f" * 64, "installed_payload_sha256": "f" * 64,
                "verified_payload_files": 123}
    retained_plan["deployment_measurement"] = write_receipt(
        Path(retained_plan["retained_wheel"]["path"]).with_name("measurement.json"), expected)
    observed = {**expected, "installed_payload_sha256": "0" * 64} if changed else expected
    programs = []
    monkeypatch.setattr(fixture, "guest_python_command", lambda program: programs.append(program) or "inspection")
    monkeypatch.setattr(fixture, "sudo_read", lambda *_args: json.dumps(observed))
    if changed:
        with pytest.raises(fixture.Refusal, match="installed_payload_changed"):
            fixture.payload_identity(None, retained_plan, "synthetic")
    else:
        assert fixture.payload_identity(None, retained_plan, "synthetic") == expected
    assert repr(fixture.retained_wheel_path(retained_plan)) in programs[0]
    assert "'/tmp/atlaso-" not in programs[0]
