"""Pure state and boundary checks for the reusable ISO refresh plan."""

from __future__ import annotations

import copy

import pytest

from scripts.installation.refresh_plan import (
    MIN_FREE_GIB,
    PHASES,
    TIMEOUT_SECONDS,
    authorize_phase,
    canonical_plan_sha256,
    next_phase,
    validate_plan,
)

TASK_ID = "01a19320-0e85-76f0-a1ba-e68ff3ac6d71"
OPERATION_ID = "0123456789abcdef0123456789abcdef"
INSTALLER_COMMIT = "a" * 40
SOFTWARE_COMMIT = "b" * 40
DIGEST = "c" * 64
ROOT = r"E:\.codex\worktree"
WORKTREE = ROOT + r"\issue1076-iso-refresh\Atlaso"


def plan(*, fresh_capture: bool = False) -> dict:
    """Return one well-formed plan for the tested path profile.

    Args:
        fresh_capture: Select newly captured inputs under the durable evidence root.
    """
    output_root = WORKTREE + r"\refresh-" + OPERATION_ID
    return {
        "schema": 1,
        "operation_id": OPERATION_ID,
        "task_id": TASK_ID,
        "installer_commit": INSTALLER_COMMIT,
        "software": {
            "path": r"E:\software\verified",
            "version": "0.9.469",
            "source_commit": SOFTWARE_COMMIT,
        },
        "source_iso": r"E:\photon\photon.iso",
        "rpms": ROOT + r"\.evidence\fixture-op\captured-archives\rpms" if fresh_capture else r"E:\capture\rpms",
        "powercli": ROOT + r"\.evidence\fixture-op\captured-archives\powercli" if fresh_capture else r"E:\capture\powercli",
        "output_root": output_root,
        "pull_request_number": 1076,
        "native_distribution": None,
        "protected_files": [{"path": r"E:\evidence\profile.json", "sha256": DIGEST}],
        "capture_receipt": None if fresh_capture else {"path": r"E:\evidence\capture.json", "sha256": DIGEST},
    }


def record(status: str, *, disposition: str | None = None, **extra: object) -> dict:
    """Bind a recorded phase result to the example plan identities.

    Args:
        status: Recorded terminal or pending phase status.
        disposition: Optional drift outcome attached to the phase result.
        **extra: Additional result fields for the scenario under test.
    """
    result = {
        "status": status,
        "operation_id": OPERATION_ID,
        "task_id": TASK_ID,
        "installer_commit": INSTALLER_COMMIT,
        "whole_job_quiescent": True,
        "start_intent_id": OPERATION_ID,
    }
    if disposition is not None:
        result["disposition"] = disposition
    result.update(extra)
    return result


def context(*, disposition: str = "reuse") -> tuple[dict[str, dict], dict[str, dict]]:
    """Return a successful drift result and its immutable original start selector.

    Args:
        disposition: Drift disposition to include in the result.
    """
    return (
        {"drift": record("succeeded", disposition=disposition)},
        {"drift": start_intent()},
    )


def start_intent() -> dict:
    """Bind a durable original phase start to this plan."""
    return {
        "intent_id": OPERATION_ID,
        "operation_id": OPERATION_ID,
        "task_id": TASK_ID,
        "installer_commit": INSTALLER_COMMIT,
    }


def test_valid_plan_and_canonical_digest() -> None:
    value = plan()
    validated = validate_plan(value, configured_root=ROOT, worktree=WORKTREE)
    reordered = dict(reversed(list(value.items())))

    assert validated == value
    assert canonical_plan_sha256(value, configured_root=ROOT, worktree=WORKTREE) == canonical_plan_sha256(
        reordered, configured_root=ROOT, worktree=WORKTREE
    )


def test_fresh_capture_paths_must_be_retained_outside_worktree_and_have_no_receipt_yet() -> None:
    value = plan(fresh_capture=True)

    assert validate_plan(value, configured_root=ROOT, worktree=WORKTREE)["capture_receipt"] is None
    value["rpms"] = value["output_root"] + r"\capture\rpms"
    with pytest.raises(ValueError, match="output root overlaps"):
        validate_plan(value, configured_root=ROOT, worktree=WORKTREE)

    value = plan(fresh_capture=True)
    value["powercli"] = WORKTREE + r"\capture\powercli"
    with pytest.raises(ValueError, match="fresh capture inputs"):
        validate_plan(value, configured_root=ROOT, worktree=WORKTREE)

    value = plan(fresh_capture=True)
    value["rpms"] = WORKTREE + r"\test-results\capture\rpms"
    with pytest.raises(ValueError, match="fresh capture inputs"):
        validate_plan(value, configured_root=ROOT, worktree=WORKTREE)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("source_iso", r"E:\outside\..\photon.iso"),
        ("source_iso", r"\\server\share\photon.iso"),
        ("output_root", "file:///E:/output"),
        ("pull_request_number", True),
    ],
)

def test_plan_rejects_noncanonical_or_untrusted_values(field: str, bad_value: object) -> None:
    """Reject invalid values for selected plan fields.

    Args:
        field: Plan key receiving the invalid value.
        bad_value: Invalid path or scalar value to validate.
    """
    value = plan()
    value[field] = bad_value

    with pytest.raises(ValueError):
        validate_plan(value, configured_root=ROOT, worktree=WORKTREE)


def test_native_distribution_is_optional_and_strictly_validated() -> None:
    value = plan()
    assert validate_plan(value, configured_root=ROOT, worktree=WORKTREE)["native_distribution"] is None

    value["native_distribution"] = "AlmaLinux-10"
    assert validate_plan(value, configured_root=ROOT, worktree=WORKTREE)["native_distribution"] == "AlmaLinux-10"

    for invalid in ("", " leading", "-leading", "name with spaces", "name/name", "x" * 65, 10):
        value["native_distribution"] = invalid
        with pytest.raises(ValueError, match="native distribution selector"):
            validate_plan(value, configured_root=ROOT, worktree=WORKTREE)


def test_plan_rejects_output_overlap_with_source_and_protected_paths() -> None:
    value = plan()
    value["output_root"] = "E:\\"

    with pytest.raises(ValueError, match="overlaps an input"):
        validate_plan(value, configured_root=ROOT, worktree=WORKTREE)

    value = plan()
    value["protected_files"] = [{"path": value["output_root"] + r"\profile.json", "sha256": DIGEST}]
    with pytest.raises(ValueError, match="overlaps a protected"):
        validate_plan(value, configured_root=ROOT, worktree=WORKTREE)


def test_plan_requires_task_worktree_and_receipt_containment() -> None:
    value = plan()

    with pytest.raises(ValueError, match="configured root"):
        validate_plan(value, configured_root=ROOT, worktree=ROOT)
    value["capture_receipt"]["path"] = WORKTREE + r"\state\capture.json"
    with pytest.raises(ValueError, match="outside the task worktree"):
        validate_plan(value, configured_root=ROOT, worktree=WORKTREE)


def test_drift_is_first_and_capture_requires_drift_disposition() -> None:
    results, started = {}, {}

    assert next_phase(results, started, plan=plan())["phase"] == "drift"
    assert authorize_phase("capture", results, started, plan=plan())["status"] == "pending"

    results, started = context(disposition="requires_capture")
    assert authorize_phase("capture", results, started, plan=plan())["status"] == "authorized"
    assert next_phase(results, started, plan=plan())["phase"] == "capture"
    assert authorize_phase("build", results, started, plan=plan())["status"] == "pending"


def test_review_required_drift_blocks_capture_and_build() -> None:
    results, started = context(disposition="requires_review")

    for phase in ("capture", "admit", "build"):
        assert authorize_phase(phase, results, started, plan=plan())["status"] == "refused"
    assert next_phase(results, started, plan=plan())["status"] == "refused"


def test_reuse_skips_capture_and_admission_precedes_build() -> None:
    results, started = context()

    assert authorize_phase("capture", results, started, plan=plan())["status"] == "refused"
    assert next_phase(results, started, plan=plan())["phase"] == "admit"
    results["admit"] = record("succeeded")
    started["admit"] = start_intent()
    assert next_phase(results, started, plan=plan())["phase"] == "build"


def test_failed_started_phase_never_replays() -> None:
    results, started = context()
    results["admit"] = record("failed")
    started["admit"] = start_intent()

    authorization = authorize_phase("admit", results, started, plan=plan())
    assert authorization == {"status": "refused", "reason": "phase already has an original start intent"}
    assert next_phase(results, started, plan=plan())["status"] == "refused"


def test_pending_dependency_and_source_mismatch_fail_closed() -> None:
    results, started = context()
    results["admit"] = record("pending")
    started["admit"] = start_intent()
    assert authorize_phase("build", results, started, plan=plan())["status"] == "pending"

    mismatched = copy.deepcopy(results)
    mismatched["drift"]["installer_commit"] = SOFTWARE_COMMIT
    assert authorize_phase("build", mismatched, started, plan=plan())["status"] == "refused"


def test_verify_requires_terminal_quiescent_install_even_when_install_failed() -> None:
    results, started = context()
    for phase in ("admit", "build", "readback"):
        results[phase] = record("succeeded")
        started[phase] = start_intent()
    started["install"] = start_intent()
    results["install"] = record("failed", whole_job_quiescent=False)
    assert authorize_phase("verify", results, started, plan=plan())["status"] == "refused"
    results["install"]["whole_job_quiescent"] = True
    assert authorize_phase("verify", results, started, plan=plan())["status"] == "authorized"


def test_cleanup_and_protected_require_successful_prior_gates() -> None:
    results, started = context()
    for phase in ("admit", "build", "readback"):
        results[phase] = record("succeeded")
        started[phase] = start_intent()
    results["install"] = record("succeeded", whole_job_quiescent=True)
    started["install"] = start_intent()
    results["verify"] = record("failed")
    started["verify"] = start_intent()

    assert authorize_phase("cleanup", results, started, plan=plan())["status"] == "refused"
    results["verify"] = record("succeeded")
    assert authorize_phase("cleanup", results, started, plan=plan())["status"] == "authorized"
    results["cleanup"] = record("succeeded")
    started["cleanup"] = start_intent()
    assert authorize_phase("protected", results, started, plan=plan())["status"] == "authorized"


def test_phase_bounds_are_fixed() -> None:
    assert set(MIN_FREE_GIB) == set(PHASES)
    assert set(TIMEOUT_SECONDS) == set(PHASES)
    assert MIN_FREE_GIB["capture"] == 120
    assert MIN_FREE_GIB["install"] == 74
    assert TIMEOUT_SECONDS["drift"] == 900
    assert TIMEOUT_SECONDS["protected"] == 300
