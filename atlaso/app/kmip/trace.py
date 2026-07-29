"""Validate privacy-safe KMIP interoperability traces against a bounded contract."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


CONTRACT_PATH = Path(__file__).with_name("contracts") / "vcf_9_1.json"
TRACE_SCHEMA_VERSION = 1
REQUIRED_FIELDS = {
    "schema_version",
    "timestamp",
    "connection_id",
    "client_cert_sha256",
    "provider_id",
    "protocol_version",
    "operation",
    "object_type",
    "algorithm",
    "key_length",
    "key_format_type",
    "attribute_names",
    "result_status",
    "result_reason",
    "request_digest",
}
FORBIDDEN_FIELD_FRAGMENTS = {
    "credential",
    "keyblock",
    "keybytes",
    "keymaterial",
    "password",
    "privatekey",
    "rawpayload",
    "secret",
}
CONTRACT_FIELDS = {
    "schema_version",
    "contract_id",
    "target",
    "status",
    "promotion_gate",
    "transport",
    "protocol_versions",
    "objects",
    "algorithms",
    "candidate_operations",
    "candidate_attributes",
    "result_statuses",
    "result_reasons",
    "explicitly_unsupported",
    "sources",
}


class TraceValidationError(ValueError):
    """Raised when an interoperability trace violates the evidence contract."""


@dataclass(frozen=True)
class TraceSummary:
    """Deterministic metadata summary for a validated trace."""

    contract_id: str
    contract_sha256: str
    event_count: int
    operations: dict[str, int]
    protocol_versions: list[str]
    providers: list[str]
    result_statuses: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_id": self.contract_id,
            "contract_sha256": self.contract_sha256,
            "event_count": self.event_count,
            "operations": self.operations,
            "protocol_versions": self.protocol_versions,
            "providers": self.providers,
            "result_statuses": self.result_statuses,
        }


def validate_contract(contract: dict[str, Any]) -> dict[str, Any]:
    if set(contract) != CONTRACT_FIELDS:
        missing = sorted(CONTRACT_FIELDS - contract.keys())
        extra = sorted(contract.keys() - CONTRACT_FIELDS)
        detail = []
        if missing:
            detail.append(f"missing {', '.join(missing)}")
        if extra:
            detail.append(f"unexpected {', '.join(extra)}")
        raise TraceValidationError(f"KMIP contract fields are invalid: {'; '.join(detail)}.")
    if contract.get("schema_version") != 1:
        raise TraceValidationError("KMIP contract schema_version must be 1.")
    if contract.get("status") not in {"candidate-unverified", "observed"}:
        raise TraceValidationError("KMIP contract status is invalid.")
    for field in (
        "protocol_versions",
        "objects",
        "candidate_operations",
        "candidate_attributes",
        "result_statuses",
        "result_reasons",
    ):
        values = contract.get(field)
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and value.strip() for value in values)
            or len(values) != len(set(values))
        ):
            raise TraceValidationError(
                f"KMIP contract {field} must be a non-empty list of unique names."
            )
    algorithms = contract.get("algorithms")
    if not isinstance(algorithms, dict) or not algorithms:
        raise TraceValidationError("KMIP contract algorithms must be a non-empty object.")
    for name, algorithm in algorithms.items():
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(algorithm, dict)
            or set(algorithm) != {"lengths", "key_format_types"}
            or not isinstance(algorithm["lengths"], list)
            or not algorithm["lengths"]
            or not all(
                isinstance(length, int) and not isinstance(length, bool) and length > 0
                for length in algorithm["lengths"]
            )
            or len(algorithm["lengths"]) != len(set(algorithm["lengths"]))
            or not isinstance(algorithm["key_format_types"], list)
            or not algorithm["key_format_types"]
            or not all(
                isinstance(key_format, str) and key_format.strip()
                for key_format in algorithm["key_format_types"]
            )
            or len(algorithm["key_format_types"]) != len(set(algorithm["key_format_types"]))
        ):
            raise TraceValidationError(f"KMIP contract algorithm {name!r} is invalid.")
    transport = contract.get("transport")
    if (
        not isinstance(transport, dict)
        or transport.get("encoding") != "TTLV"
        or transport.get("mutual_tls_required") is not True
        or transport.get("port") != 5696
    ):
        raise TraceValidationError("KMIP contract transport must require mutual TLS TTLV on TCP 5696.")
    return contract


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    contract = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(contract, dict):
        raise TraceValidationError("KMIP contract must be a JSON object.")
    return validate_contract(contract)


def _normalized_field(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _reject_secret_fields(value: Any, *, location: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = _normalized_field(str(key))
            if any(fragment in normalized for fragment in FORBIDDEN_FIELD_FRAGMENTS):
                raise TraceValidationError(
                    f"{location} contains forbidden secret-bearing field {key!r}."
                )
            _reject_secret_fields(child, location=f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_fields(child, location=f"{location}[{index}]")


def _require_sha256(value: object, *, field: str, line: int) -> str:
    text = str(value)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise TraceValidationError(f"line {line}: {field} must be a lowercase SHA-256 digest.")
    return text


def _validate_event(
    event: dict[str, Any],
    *,
    contract: dict[str, Any],
    line: int,
) -> None:
    _reject_secret_fields(event, location=f"line {line}")
    missing = sorted(REQUIRED_FIELDS - event.keys())
    extra = sorted(event.keys() - REQUIRED_FIELDS)
    if missing:
        raise TraceValidationError(f"line {line}: missing fields: {', '.join(missing)}.")
    if extra:
        raise TraceValidationError(f"line {line}: unexpected fields: {', '.join(extra)}.")
    if event["schema_version"] != TRACE_SCHEMA_VERSION:
        raise TraceValidationError(f"line {line}: schema_version must be {TRACE_SCHEMA_VERSION}.")
    _require_sha256(event["client_cert_sha256"], field="client_cert_sha256", line=line)
    _require_sha256(event["request_digest"], field="request_digest", line=line)
    if event["protocol_version"] not in contract["protocol_versions"]:
        raise TraceValidationError(f"line {line}: protocol_version is outside the contract.")
    if event["operation"] not in contract["candidate_operations"]:
        raise TraceValidationError(f"line {line}: operation is outside the candidate allowlist.")
    object_type = event["object_type"]
    if object_type is not None and object_type not in contract["objects"]:
        raise TraceValidationError(f"line {line}: object_type is outside the contract.")
    algorithm = event["algorithm"]
    key_length = event["key_length"]
    key_format_type = event["key_format_type"]
    if event["operation"] == "Create" and (
        algorithm is None or key_length is None or key_format_type is None
    ):
        raise TraceValidationError(
            f"line {line}: Create must record algorithm, key_length, and key_format_type."
        )
    if algorithm is None:
        if key_length is not None or key_format_type is not None:
            raise TraceValidationError(
                f"line {line}: key_length and key_format_type require an algorithm."
            )
    else:
        algorithm_contract = contract["algorithms"].get(algorithm)
        if not isinstance(algorithm_contract, dict):
            raise TraceValidationError(f"line {line}: algorithm is outside the contract.")
        if (
            isinstance(key_length, bool)
            or not isinstance(key_length, int)
            or key_length not in algorithm_contract["lengths"]
        ):
            raise TraceValidationError(f"line {line}: key_length is outside the contract.")
        if key_format_type not in algorithm_contract["key_format_types"]:
            raise TraceValidationError(f"line {line}: key_format_type is outside the contract.")
    attributes = event["attribute_names"]
    if not isinstance(attributes, list) or not all(isinstance(item, str) for item in attributes):
        raise TraceValidationError(f"line {line}: attribute_names must be a list of names.")
    unsupported_attributes = sorted(set(attributes) - set(contract["candidate_attributes"]))
    if unsupported_attributes:
        raise TraceValidationError(
            f"line {line}: attributes are outside the candidate allowlist: "
            f"{', '.join(unsupported_attributes)}."
        )
    if event["result_status"] not in contract["result_statuses"]:
        raise TraceValidationError(f"line {line}: result_status is outside the contract.")
    for field in ("timestamp", "connection_id", "provider_id", "operation"):
        if not isinstance(event[field], str) or not event[field].strip():
            raise TraceValidationError(f"line {line}: {field} must be a non-empty string.")
    if (
        event["result_reason"] is not None
        and event["result_reason"] not in contract["result_reasons"]
    ):
        raise TraceValidationError(
            f"line {line}: result_reason must be null or an allowlisted KMIP reason."
        )


def validate_trace(
    lines: Iterable[str],
    *,
    contract: dict[str, Any] | None = None,
    contract_bytes: bytes | None = None,
) -> TraceSummary:
    selected_contract = validate_contract(contract) if contract is not None else load_contract()
    events: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise TraceValidationError(f"line {line_number}: invalid JSON: {exc.msg}.") from exc
        if not isinstance(event, dict):
            raise TraceValidationError(f"line {line_number}: each event must be a JSON object.")
        _validate_event(event, contract=selected_contract, line=line_number)
        events.append(event)
    if not events:
        raise TraceValidationError("trace must contain at least one event.")

    serialized_contract = contract_bytes or (
        json.dumps(selected_contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    operation_counts = Counter(str(event["operation"]) for event in events)
    status_counts = Counter(str(event["result_status"]) for event in events)
    return TraceSummary(
        contract_id=str(selected_contract["contract_id"]),
        contract_sha256=hashlib.sha256(serialized_contract).hexdigest(),
        event_count=len(events),
        operations=dict(sorted(operation_counts.items())),
        protocol_versions=sorted({str(event["protocol_version"]) for event in events}),
        providers=sorted({str(event["provider_id"]) for event in events}),
        result_statuses=dict(sorted(status_counts.items())),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="Redacted JSONL trace to validate.")
    parser.add_argument(
        "--contract",
        type=Path,
        default=CONTRACT_PATH,
        help="KMIP contract JSON. Defaults to the checked-in VCF 9.1 candidate contract.",
    )
    parser.add_argument("--output", type=Path, help="Optional path for the deterministic JSON summary.")
    args = parser.parse_args(argv)

    try:
        contract_bytes = args.contract.read_bytes()
        contract = json.loads(contract_bytes)
        summary = validate_trace(
            args.trace.read_text(encoding="utf-8").splitlines(),
            contract=contract,
            contract_bytes=contract_bytes,
        )
    except (OSError, json.JSONDecodeError, TraceValidationError) as exc:
        parser.error(str(exc))

    rendered = json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
