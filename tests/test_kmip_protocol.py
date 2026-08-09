"""Test kmip protocol behavior."""

from __future__ import annotations

import uuid
from pathlib import Path

from atlaso.app.kmip.protocol import (
    CRYPTOGRAPHIC_ALGORITHM_AES,
    KEY_FORMAT_TYPE_RAW,
    NAME_TYPE_UNINTERPRETED_TEXT_STRING,
    OBJECT_TYPE_SYMMETRIC_KEY,
    STATE_ACTIVE,
    KmipDispatcher,
    Operation,
    QueryFunction,
    ResultReason,
    ResultStatus,
    Tag,
)
from atlaso.app.kmip.store import WrappedKeyStore
from atlaso.app.kmip.ttlv import (
    Ttlv,
    byte_string,
    enumeration,
    integer,
    structure,
    text_string,
)


def dispatcher(tmp_path: Path) -> tuple[KmipDispatcher, str]:
    """Return dispatcher."""
    provider_id = str(uuid.uuid4())
    store = WrappedKeyStore(
        tmp_path / "store.db",
        tmp_path / "kek.json",
        secrets_key="appliance-secrets-key",
    )
    return KmipDispatcher(store), provider_id


def request(operation: int, *payload: Ttlv) -> Ttlv:
    """Return request."""
    return structure(
        Tag.REQUEST_MESSAGE,
        structure(
            Tag.REQUEST_HEADER,
            structure(
                Tag.PROTOCOL_VERSION,
                integer(Tag.PROTOCOL_VERSION_MAJOR, 1),
                integer(Tag.PROTOCOL_VERSION_MINOR, 4),
            ),
            integer(Tag.BATCH_COUNT, 1),
        ),
        structure(
            Tag.BATCH_ITEM,
            enumeration(Tag.OPERATION, operation),
            structure(Tag.REQUEST_PAYLOAD, *payload),
        ),
    )


def batch_item(response: Ttlv) -> Ttlv:
    """Return batch item."""
    return response.children(Tag.BATCH_ITEM)[0]


def response_payload(response: Ttlv) -> Ttlv:
    """Return response payload."""
    payload = batch_item(response).child(Tag.RESPONSE_PAYLOAD)
    assert payload is not None
    return payload


def result_status(response: Ttlv) -> int:
    """Return result status."""
    node = batch_item(response).child(Tag.RESULT_STATUS)
    assert node is not None
    assert isinstance(node.value, int)
    return node.value


def create_request() -> Ttlv:
    """Create request.

    Returns:
        The created request.
    """
    return request(
        Operation.CREATE,
        enumeration(Tag.OBJECT_TYPE, OBJECT_TYPE_SYMMETRIC_KEY),
        structure(
            Tag.TEMPLATE_ATTRIBUTE,
            structure(
                Tag.ATTRIBUTE,
                text_string(Tag.ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                enumeration(Tag.ATTRIBUTE_VALUE, CRYPTOGRAPHIC_ALGORITHM_AES),
            ),
            structure(
                Tag.ATTRIBUTE,
                text_string(Tag.ATTRIBUTE_NAME, "Cryptographic Length"),
                integer(Tag.ATTRIBUTE_VALUE, 256),
            ),
            structure(
                Tag.ATTRIBUTE,
                text_string(Tag.ATTRIBUTE_NAME, "Cryptographic Usage Mask"),
                integer(Tag.ATTRIBUTE_VALUE, 0x0C),
            ),
        ),
    )


def name_attribute(value: str) -> Ttlv:
    """Return name attribute."""
    return structure(
        Tag.ATTRIBUTE,
        text_string(Tag.ATTRIBUTE_NAME, "Name"),
        structure(
            Tag.ATTRIBUTE_VALUE,
            text_string(Tag.NAME_VALUE, value),
            enumeration(Tag.NAME_TYPE, NAME_TYPE_UNINTERPRETED_TEXT_STRING),
        ),
    )


def created_key_id(service: KmipDispatcher, provider_id: str) -> str:
    """Return created key id."""
    response = service.dispatch(provider_id, create_request())
    assert result_status(response) == ResultStatus.SUCCESS
    node = response_payload(response).child(Tag.UNIQUE_IDENTIFIER)
    assert node is not None
    assert isinstance(node.value, str)
    return node.value


def test_create_activate_get_round_trip_returns_only_active_key(tmp_path: Path) -> None:
    """Verify that create activate get round trip returns only active key."""
    service, provider_id = dispatcher(tmp_path)
    key_id = created_key_id(service, provider_id)

    pre_active_get = service.dispatch(
        provider_id,
        request(Operation.GET, text_string(Tag.UNIQUE_IDENTIFIER, key_id)),
    )
    assert result_status(pre_active_get) == ResultStatus.OPERATION_FAILED

    activated = service.dispatch(
        provider_id,
        request(Operation.ACTIVATE, text_string(Tag.UNIQUE_IDENTIFIER, key_id)),
    )
    assert result_status(activated) == ResultStatus.SUCCESS

    retrieved = service.dispatch(
        provider_id,
        request(
            Operation.GET,
            text_string(Tag.UNIQUE_IDENTIFIER, key_id),
            enumeration(Tag.KEY_FORMAT_TYPE, KEY_FORMAT_TYPE_RAW),
        ),
    )
    key_block = (
        response_payload(retrieved)
        .child(Tag.SYMMETRIC_KEY)
        .child(Tag.KEY_BLOCK)
    )
    key_material = key_block.child(Tag.KEY_VALUE).child(Tag.KEY_MATERIAL)

    assert result_status(retrieved) == ResultStatus.SUCCESS
    assert isinstance(key_material.value, bytes)
    assert len(key_material.value) == 32


def test_cross_provider_get_does_not_reveal_key_existence(tmp_path: Path) -> None:
    """Verify that cross provider get does not reveal key existence."""
    service, provider_id = dispatcher(tmp_path)
    key_id = created_key_id(service, provider_id)

    response = service.dispatch(
        str(uuid.uuid4()),
        request(Operation.GET, text_string(Tag.UNIQUE_IDENTIFIER, key_id)),
    )
    reason = batch_item(response).child(Tag.RESULT_REASON)

    assert result_status(response) == ResultStatus.OPERATION_FAILED
    assert reason is not None
    assert reason.value == ResultReason.ITEM_NOT_FOUND


def test_query_and_discover_versions_expose_only_bounded_contract(tmp_path: Path) -> None:
    """Verify that query and discover versions expose only bounded contract."""
    service, provider_id = dispatcher(tmp_path)

    query = service.dispatch(
        provider_id,
        request(
            Operation.QUERY,
            enumeration(Tag.QUERY_FUNCTION, QueryFunction.OPERATIONS),
            enumeration(Tag.QUERY_FUNCTION, QueryFunction.OBJECTS),
            enumeration(Tag.QUERY_FUNCTION, QueryFunction.SERVER_INFORMATION),
        ),
    )
    payload = response_payload(query)
    operations = {node.value for node in payload.children(Tag.OPERATION)}

    assert operations == set(Operation)
    assert [node.value for node in payload.children(Tag.OBJECT_TYPE)] == [
        OBJECT_TYPE_SYMMETRIC_KEY
    ]
    assert payload.child(Tag.VENDOR_IDENTIFICATION).value == "Atlaso"

    versions = service.dispatch(
        provider_id,
        request(
            Operation.DISCOVER_VERSIONS,
            structure(
                Tag.PROTOCOL_VERSION,
                integer(Tag.PROTOCOL_VERSION_MAJOR, 1),
                integer(Tag.PROTOCOL_VERSION_MINOR, 4),
            ),
        ),
    )
    assert result_status(versions) == ResultStatus.SUCCESS
    assert len(response_payload(versions).children(Tag.PROTOCOL_VERSION)) == 1


def test_unsupported_and_destructive_operations_fail_closed(tmp_path: Path) -> None:
    """Verify that unsupported and destructive operations fail closed."""
    service, provider_id = dispatcher(tmp_path)

    response = service.dispatch(provider_id, request(0x14))
    reason = batch_item(response).child(Tag.RESULT_REASON)

    assert result_status(response) == ResultStatus.OPERATION_FAILED
    assert reason is not None
    assert reason.value == ResultReason.OPERATION_NOT_SUPPORTED
    assert batch_item(response).child(Tag.RESPONSE_PAYLOAD, required=False) is None


def test_get_attributes_and_locate_stay_inside_provider(tmp_path: Path) -> None:
    """Verify that get attributes and locate stay inside provider."""
    service, provider_id = dispatcher(tmp_path)
    key_id = created_key_id(service, provider_id)
    service.dispatch(
        provider_id,
        request(Operation.ACTIVATE, text_string(Tag.UNIQUE_IDENTIFIER, key_id)),
    )

    attributes = service.dispatch(
        provider_id,
        request(
            Operation.GET_ATTRIBUTES,
            text_string(Tag.UNIQUE_IDENTIFIER, key_id),
            text_string(Tag.ATTRIBUTE_NAME, "State"),
            text_string(Tag.ATTRIBUTE_NAME, "Unique Identifier"),
        ),
    )
    attribute_nodes = response_payload(attributes).children(Tag.ATTRIBUTE)
    assert [node.child(Tag.ATTRIBUTE_NAME).value for node in attribute_nodes] == [
        "State",
        "Unique Identifier",
    ]
    assert attribute_nodes[0].child(Tag.ATTRIBUTE_VALUE).value == STATE_ACTIVE

    located = service.dispatch(provider_id, request(Operation.LOCATE))
    other = service.dispatch(str(uuid.uuid4()), request(Operation.LOCATE))
    assert [node.value for node in response_payload(located).children(Tag.UNIQUE_IDENTIFIER)] == [
        key_id
    ]
    assert response_payload(other).children(Tag.UNIQUE_IDENTIFIER) == []


def test_name_and_activation_date_are_persisted_attributes(tmp_path: Path) -> None:
    """Verify that name and activation date are persisted attributes."""
    service, provider_id = dispatcher(tmp_path)
    create = create_request()
    template = create.children(Tag.BATCH_ITEM)[0].child(Tag.REQUEST_PAYLOAD).child(
        Tag.TEMPLATE_ATTRIBUTE
    )
    named_template = structure(
        Tag.TEMPLATE_ATTRIBUTE,
        *template.children(),
        name_attribute("vcf-key"),
    )
    payload = create.children(Tag.BATCH_ITEM)[0].child(Tag.REQUEST_PAYLOAD)
    named_create = request(
        Operation.CREATE,
        *[
            named_template if child.tag == Tag.TEMPLATE_ATTRIBUTE else child
            for child in payload.children()
        ],
    )
    key_id_node = response_payload(service.dispatch(provider_id, named_create)).child(
        Tag.UNIQUE_IDENTIFIER
    )
    assert key_id_node is not None and isinstance(key_id_node.value, str)
    key_id = key_id_node.value

    located = service.dispatch(
        provider_id,
        request(Operation.LOCATE, name_attribute("vcf-key")),
    )
    assert [
        node.value for node in response_payload(located).children(Tag.UNIQUE_IDENTIFIER)
    ] == [key_id]

    service.dispatch(
        provider_id,
        request(Operation.ACTIVATE, text_string(Tag.UNIQUE_IDENTIFIER, key_id)),
    )
    attributes = service.dispatch(
        provider_id,
        request(
            Operation.GET_ATTRIBUTES,
            text_string(Tag.UNIQUE_IDENTIFIER, key_id),
            text_string(Tag.ATTRIBUTE_NAME, "Name"),
            text_string(Tag.ATTRIBUTE_NAME, "Activation Date"),
        ),
    )
    name, activation = response_payload(attributes).children(Tag.ATTRIBUTE)

    assert name.child(Tag.ATTRIBUTE_VALUE).child(Tag.NAME_VALUE).value == "vcf-key"
    assert (
        name.child(Tag.ATTRIBUTE_VALUE).child(Tag.NAME_TYPE).value
        == NAME_TYPE_UNINTERPRETED_TEXT_STRING
    )
    assert isinstance(activation.child(Tag.ATTRIBUTE_VALUE).value, int)


def test_create_rejects_algorithm_or_length_outside_contract(tmp_path: Path) -> None:
    """Verify that create rejects algorithm or length outside contract."""
    service, provider_id = dispatcher(tmp_path)
    invalid = request(
        Operation.CREATE,
        enumeration(Tag.OBJECT_TYPE, OBJECT_TYPE_SYMMETRIC_KEY),
        structure(
            Tag.TEMPLATE_ATTRIBUTE,
            structure(
                Tag.ATTRIBUTE,
                text_string(Tag.ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                enumeration(Tag.ATTRIBUTE_VALUE, 4),
            ),
            structure(
                Tag.ATTRIBUTE,
                text_string(Tag.ATTRIBUTE_NAME, "Cryptographic Length"),
                integer(Tag.ATTRIBUTE_VALUE, 128),
            ),
        ),
    )

    response = service.dispatch(provider_id, invalid)

    assert result_status(response) == ResultStatus.OPERATION_FAILED
    assert batch_item(response).child(Tag.RESULT_REASON).value == ResultReason.INVALID_FIELD


def test_raw_key_material_is_never_accepted_as_request_input(tmp_path: Path) -> None:
    """Verify that raw key material is never accepted as request input."""
    service, provider_id = dispatcher(tmp_path)

    response = service.dispatch(
        provider_id,
        request(
            Operation.CREATE,
            enumeration(Tag.OBJECT_TYPE, OBJECT_TYPE_SYMMETRIC_KEY),
            byte_string(Tag.KEY_MATERIAL, b"x" * 32),
        ),
    )

    assert result_status(response) == ResultStatus.OPERATION_FAILED
