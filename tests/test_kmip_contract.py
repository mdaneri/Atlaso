from __future__ import annotations

import json

import pytest

from atlaso.app.kmip.trace import (
    TraceValidationError,
    load_contract,
    validate_contract,
    validate_trace,
)


SHA256 = "a" * 64


def event(**overrides: object) -> str:
    value: dict[str, object] = {
        "schema_version": 1,
        "timestamp": "2026-07-28T00:00:00Z",
        "connection_id": "connection-1",
        "client_cert_sha256": SHA256,
        "provider_id": "provider-1",
        "protocol_version": "1.4",
        "operation": "Create",
        "object_type": "Symmetric Key",
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
    summary = validate_trace(
        [
            event(),
            event(
                operation="Get",
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
        ({"client_cert_sha256": "not-a-digest"}, "lowercase SHA-256"),
        ({"raw_payload": "redacted"}, "forbidden secret-bearing field"),
        ({"key_material": "redacted"}, "forbidden secret-bearing field"),
    ],
)
def test_trace_validator_fails_closed(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(TraceValidationError, match=message):
        validate_trace([event(**overrides)])


def test_trace_validator_rejects_empty_input() -> None:
    with pytest.raises(TraceValidationError, match="at least one event"):
        validate_trace([])


def test_trace_validator_rejects_unvalidated_caller_contract() -> None:
    contract = load_contract()
    contract["status"] = "supported"

    with pytest.raises(TraceValidationError, match="status is invalid"):
        validate_trace([event()], contract=contract)


def test_contract_validator_rejects_duplicate_allowlist_values() -> None:
    contract = load_contract()
    contract["candidate_operations"].append("Create")

    with pytest.raises(TraceValidationError, match="unique names"):
        validate_contract(contract)
