"""Test kmip contract behavior."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from atlaso.app.kmip.trace import (
    TraceValidationError,
    load_contract,
    validate_contract,
    validate_trace,
)

SHA256 = "a" * 64


def event(**overrides: object) -> str:
    """Return event.

    Args:
        **overrides: Additional keyword arguments accepted by the callable.
    """
    value: dict[str, object] = {
        "schema_version": 1,
        "timestamp": "2026-07-28T00:00:00Z",
        "connection_id": "connection-1",
        "client_cert_sha256": SHA256,
        "provider_id": "provider-1",
        "protocol_version": "1.4",
        "operation": "Create",
        "object_type": "Symmetric Key",
        "algorithm": "AES",
        "key_length": 256,
        "key_format_type": "Raw",
        "attribute_names": [
            "Cryptographic Algorithm",
            "Cryptographic Length",
            "Object Type",
        ],
        "result_status": "Success",
        "result_reason": None,
        "request_digest": "b" * 64,
    }
    value.update(overrides)
    return json.dumps(value)


def test_vcf_9_1_contract_is_explicitly_unverified() -> None:
    """Verify that vcf 9 1 contract is explicitly unverified."""
    contract = load_contract()

    assert contract["target"] == {
        "product": "VMware Cloud Foundation",
        "version": "9.1",
    }
    assert contract["status"] == "candidate-unverified"
    assert contract["transport"]["mutual_tls_required"] is True
    assert contract["protocol_versions"] == ["1.4"]
    assert contract["algorithms"]["AES"]["lengths"] == [256]


def test_trace_validator_summarizes_only_allowlisted_metadata() -> None:
    """Verify that trace validator summarizes only allowlisted metadata."""
    summary = validate_trace(
        [
            event(),
            event(
                operation="Get",
                algorithm=None,
                key_length=None,
                key_format_type=None,
                attribute_names=["Unique Identifier"],
                request_digest="c" * 64,
            ),
        ]
    )

    assert summary.event_count == 2
    assert summary.operations == {"Create": 1, "Get": 1}
    assert summary.protocol_versions == ["1.4"]
    assert summary.providers == ["provider-1"]
    assert len(summary.contract_sha256) == 64


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"operation": "Destroy"}, "operation is outside"),
        ({"protocol_version": "2.0"}, "protocol_version is outside"),
        ({"object_type": "Private Key"}, "object_type is outside"),
        ({"attribute_names": ["Key Material"]}, "attributes are outside"),
        ({"algorithm": "DES"}, "algorithm is outside"),
        ({"key_length": 128}, "key_length is outside"),
        ({"key_format_type": "Transparent Symmetric Key"}, "key_format_type is outside"),
        ({"algorithm": None}, "Create must record"),
        ({"result_reason": "password=secret"}, "allowlisted KMIP reason"),
        ({"client_cert_sha256": "not-a-digest"}, "lowercase SHA-256"),
        ({"raw_payload": "redacted"}, "forbidden secret-bearing field"),
        ({"key_material": "redacted"}, "forbidden secret-bearing field"),
    ],
)
def test_trace_validator_fails_closed(overrides: dict[str, object], message: str) -> None:
    """Verify that trace validator fails closed.

    Args:
        overrides: Overrides supplied to the test scenario.
        message: Human-readable message associated with the operation.
    """
    with pytest.raises(TraceValidationError, match=message):
        validate_trace([event(**overrides)])


def test_trace_validator_rejects_empty_input() -> None:
    """Verify that trace validator rejects empty input."""
    with pytest.raises(TraceValidationError, match="at least one event"):
        validate_trace([])


def test_trace_validator_rejects_unvalidated_caller_contract() -> None:
    """Verify that trace validator rejects unvalidated caller contract."""
    contract = load_contract()
    contract["status"] = "supported"

    with pytest.raises(TraceValidationError, match="status is invalid"):
        validate_trace([event()], contract=contract)


def test_contract_validator_rejects_duplicate_allowlist_values() -> None:
    """Verify that contract validator rejects duplicate allowlist values."""
    contract = load_contract()
    contract["candidate_operations"].append("Create")

    with pytest.raises(TraceValidationError, match="unique names"):
        validate_contract(contract)


def test_documented_validator_runs_from_outside_the_checkout(tmp_path: Path) -> None:
    """Verify that documented validator runs from outside the checkout.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    root = Path(__file__).resolve().parents[1]
    trace = tmp_path / "trace.jsonl"
    trace.write_text(event(), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "kmip" / "validate_interop_trace.py"),
            str(trace),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["event_count"] == 1
