"""Shared fixed vocabulary for retained diagnostic evidence; no application imports."""

import ipaddress
import json
import re
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
    "management_route_conflict": "A live route conflicts with the previous management path. Review the expected and observed route identity before retrying.",
    "dependent_work_rolled_back": "The failed management handoff restored the previous path. Review the original failure before retrying.",
    "dependent_work_skipped": "This component was skipped because an earlier management handoff failed. Review that failure before retrying.",
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
    result: dict[str, Any] = {"schema": 1, "at": parsed_at.isoformat(), **canonical,
                              "returncode": int(code) if code is not None else None}
    route_conflict = value.get("route_conflict")
    if route_conflict is not None:
        if (canonical["reason"] != "management_route_conflict"
                or canonical["stage"] != "execution" or canonical["outcome"] != "failed"
                or (validated := validate_route_conflict(route_conflict)) is None):
            return None
        result["route_conflict"] = validated
    return result


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
        for line in reversed(lowered.splitlines()[-32:]):
            try:
                evidence = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue
            handoff = evidence.get("management_handoff") if isinstance(evidence, dict) else None
            if (isinstance(handoff, str) and evidence.get("reason_code") == "management_route_conflict"
                    and validate_route_conflict(evidence.get("route_conflict")) is not None):
                return "management_route_conflict"
        if "previous management route conflicts with live domain" in lowered:
            return "management_route_conflict"
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


def validate_route_conflict(value: Any) -> dict[str, Any] | None:
    """Return a strict, bounded projection of a management route collision.

    Args:
        value: Untrusted helper or persisted route-conflict evidence.
    """
    if not isinstance(value, dict) or set(value) != {
        "condition", "interface", "family", "table", "expected", "observed",
    }:
        return None
    conditions = {
        "gateway_mismatch", "protocol_not_supported", "metric_not_equivalent",
        "route_not_usable", "same_destination_without_successor",
    }
    condition = canonical_value(value.get("condition"), conditions)
    interface = value.get("interface")
    family = value.get("family")
    table = value.get("table")
    if (condition is None or not isinstance(interface, str) or len(interface) > 15
            or re.fullmatch(r"[A-Za-z0-9_.:-]+", interface) is None
            or type(family) is not int or family not in {4, 6}
            or type(table) is not int or table not in {100, 200}):
        return None

    def route_identity(raw: Any) -> dict[str, Any] | None:
        """Validate one bounded route identity.

        Args:
            raw: Untrusted route identity fields.
        """
        if not isinstance(raw, dict) or set(raw) != {"destination", "gateway", "protocol", "metric"}:
            return None
        destination_raw = raw.get("destination")
        gateway_raw = raw.get("gateway")
        if (not isinstance(destination_raw, str) or len(destination_raw) > 64
                or not isinstance(gateway_raw, str) or len(gateway_raw) > 45 or "%" in gateway_raw):
            return None
        try:
            destination = ipaddress.ip_network(destination_raw, strict=False)
            gateway = "" if gateway_raw == "" else str(ipaddress.ip_address(gateway_raw))
        except (TypeError, ValueError):
            return None
        if str(destination) != destination_raw or gateway != gateway_raw:
            return None
        protocol = raw.get("protocol")
        if not isinstance(protocol, str) or protocol not in {
            "kernel", "boot", "static", "ra", "dhcp", "unknown", "other",
        }:
            if not isinstance(protocol, str) or re.fullmatch(r"(?:0|[1-9][0-9]{0,2})", protocol) is None:
                return None
            if int(protocol) > 255:
                return None
        metric = raw.get("metric")
        if (destination.version != family or gateway and ipaddress.ip_address(gateway).version != family
                or type(metric) is not int or not 0 <= metric <= 0xFFFFFFFF):
            return None
        return {"destination": str(destination), "gateway": gateway, "protocol": protocol, "metric": metric}

    expected = route_identity(value.get("expected"))
    observed = route_identity(value.get("observed"))
    if expected is None or observed is None or expected["destination"] != observed["destination"]:
        return None
    return {"condition": condition, "interface": interface, "family": family, "table": table,
            "expected": expected, "observed": observed}


def format_event(event: dict[str, Any]) -> str:
    """Render only a validated event using fixed explanations.

    Args:
        event: Strict typed important-event projection.
    """
    safe = validate_event(event)
    if safe is None:
        raise ValueError("Invalid important event.")
    rendered = (f"{safe['at']} {safe['severity']} component={safe['component']} stage={safe['stage']} "
                f"outcome={safe['outcome']} reason={safe['reason']} returncode={safe['returncode']}: "
                f"{REASONS[safe['reason']]}")
    conflict = safe.get("route_conflict")
    if conflict:
        expected, observed = conflict["expected"], conflict["observed"]
        rendered += (f" condition={conflict['condition']} interface={conflict['interface']}"
                     f" family=IPv{conflict['family']} table={conflict['table']}"
                     f" expected={expected['destination']} via={expected['gateway'] or 'on-link'}"
                     f" protocol={expected['protocol']} metric={expected['metric']}"
                     f" observed={observed['destination']} via={observed['gateway'] or 'on-link'}"
                     f" protocol={observed['protocol']} metric={observed['metric']}")
    return rendered
