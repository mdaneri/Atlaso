"""Shared fixed vocabulary for retained diagnostic evidence; no application imports."""

from collections.abc import Iterable
from datetime import datetime
from typing import Any

COMPONENTS = frozenset({
    "task", "local_users", "appliance_settings", "network", "wan", "nat", "firewall",
    "dnsmasq", "esxi_pxe", "esx_storage", "ca", "kms", "ldap", "ntpd", "vcf_backups",
    "vcf_offline_depot", "vcf_private_registry", "public_services",
    "logs", "staging", "nginx", "management_handoff", "web_terminal", "appliance_update",
    "automation", "appliance_power", "factory_reset", "diagnostics",
    "photon_os", "powershell_modules", "atlaso_release", "stage-tool", "apply-properties",
    "apply-ceip", "generate-software-depot-id",
})
STAGES = frozenset({"queued", "started", "completed", "validation", "execution", "readiness",
                    "rollback", "cleanup", "recovery", "cancellation", "interrupted"})
OUTCOMES = frozenset({"pending", "running", "succeeded", "failed", "cancelled", "skipped", "no-op",
                     "partial", "partial-failure"})
REASONS = {
    "none": "The recorded stage completed or is in progress.",
    "validation_rejected": "Validation rejected the candidate. Review the component's Validation panel before resubmitting.",
    "helper_failed": "The constrained helper returned a failure. Inspect the preceding component stages and return code.",
    "timed_out": "The stage exceeded its deadline. Check component readiness and connectivity before retrying.",
    "cancelled": "A safe cancellation was requested or confirmed. Check cleanup and recovery outcomes before restarting.",
    "completion_won": "The task reached its recorded terminal outcome before cancellation. Cancellation was not confirmed.",
    "interrupted": "Execution was interrupted. Inspect recovery evidence before submitting another task.",
    "rollback_failed": "Restoration could not be verified. Retain recovery evidence and use the supported recovery workflow.",
    "cleanup_required": "Cleanup remains pending. Inspect the retained task and retry through its supported workflow.",
    "evidence_unavailable": "The producer did not retain a typed cause. Missing evidence does not establish health.",
    "permission_denied": "The stage reported a permission denial. Check the installed helper and service permissions.",
    "connection_refused": "The stage could not connect to its target. Check the target service and listener readiness.",
    "status_surface_unproven": "The update-only status surface could not be proven continuously. Inspect browser listener and status recovery evidence before retrying.",
    "status_identity_unavailable": "Appliance Update has no compatible durable status identity. Inspect the installed helper and status recovery evidence before retrying.",
    "managed_script_unavailable": "The queued managed script revision or selected vault is missing, disabled, or changed. Review the script revision and vault before resubmitting.",
    "managed_script_arguments_invalid": "The scheduled managed script arguments are invalid. Review the script parameter configuration before resubmitting.",
    "execution_contract_failed": "The task could not prove its required durable execution contract. Inspect retained task and recovery evidence before retrying.",
    "unsupported_task": "No worker handler is registered for this task type. Check the installed Atlaso release before resubmitting.",
    "unknown_failure": "The stage failed without a recognized safe cause. Inspect correlated Tasks and diagnostics.",
}
EVENT_LIMIT = 64


def canonical_value(value: Any, vocabulary: Iterable[str]) -> str | None:
    """Return the repository-owned spelling for a member of a fixed vocabulary.

    Args:
        value: Untrusted persisted or producer-owned value.
        vocabulary: Repository-owned set of allowed values.
    """
    if not isinstance(value, str):
        return None
    return next((candidate for candidate in vocabulary if value == candidate), None)


def validate_event(value: Any) -> dict[str, Any] | None:
    """Revalidate persisted evidence without admitting any free-form source text.

    Args:
        value: Untrusted checkpoint or producer event.
    """
    if not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1:
        return None
    vocabularies = (
        ("severity", ("INFO", "WARNING", "ERROR")),
        ("component", COMPONENTS),
        ("stage", STAGES),
        ("outcome", OUTCOMES),
        ("reason", REASONS.keys()),
    )
    canonical = {key: canonical_value(value.get(key), allowed) for key, allowed in vocabularies}
    if any(item is None for item in canonical.values()):
        return None
    at = value.get("at")
    if not isinstance(at, str) or len(at) > 40:
        return None
    try:
        parsed_at = datetime.fromisoformat(at)
        if parsed_at.tzinfo is None:
            return None
    except ValueError:
        return None
    code = value.get("returncode")
    if code is not None and (type(code) is not int or not -65536 <= code <= 65536):
        return None
    return {"schema": 1, "at": parsed_at.isoformat(), **canonical, "returncode": int(code) if code is not None else None}


def failure_reason(text: Any, returncode: Any = None) -> str:
    """Classify known producer failure signals; never copy or scrub arbitrary text.

    Args:
        text: Producer-owned evidence inspected in memory only.
        returncode: Optional bounded execution exit code.
    """
    if returncode == 124:
        return "timed_out"
    if isinstance(text, str):
        lowered = text[:65536].lower()
        for fragment, code in (("managed script revision is missing or disabled", "managed_script_unavailable"),
                               ("managed script vault is missing", "managed_script_unavailable"),
                               ("managed script vault no longer matches", "managed_script_unavailable"),
                               ("managed script arguments are invalid", "managed_script_arguments_invalid"),
                               ("has no durable task record", "execution_contract_failed"),
                               ("did not defer its filesystem commit", "execution_contract_failed"),
                               ("no worker handler is registered", "unsupported_task"),
                               ("status surface could not be proven", "status_surface_unproven"),
                               ("no compatible durable status identity", "status_identity_unavailable"),
                               ("permission denied", "permission_denied"), ("connection refused", "connection_refused"),
                               ("timed out", "timed_out"), ("timeout", "timed_out"),
                               ("interrupted", "interrupted"), ("restarted while this task was running", "interrupted"),
                               ("restarted during", "interrupted"), ("cancelled", "cancelled")):
            if fragment in lowered:
                return code
    return "helper_failed" if type(returncode) is int and returncode else "unknown_failure"


def format_event(event: dict[str, Any]) -> str:
    """Render only a validated event using fixed explanations.

    Args:
        event: Strict typed important-event projection.
    """
    safe = validate_event(event)
    if safe is None:
        raise ValueError("Invalid important event.")
    return (f"{safe['at']} {safe['severity']} component={safe['component']} stage={safe['stage']} "
            f"outcome={safe['outcome']} reason={safe['reason']} returncode={safe['returncode']}: {REASONS[safe['reason']]}")
