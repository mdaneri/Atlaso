"""Test kmip protocol behavior."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from atlaso.app.kmip.protocol import (
    CRYPTOGRAPHIC_ALGORITHM_AES,
    KEY_FORMAT_TYPE_RAW,
    NAME_TYPE_UNINTERPRETED_TEXT_STRING,
    OBJECT_TYPE_SYMMETRIC_KEY,
    STATE_ACTIVE,
    KmipDispatcher,
    Operation,
    ProtocolFailure,
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
    """Return dispatcher.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    provider_id = str(uuid.uuid4())
    store = WrappedKeyStore(
        tmp_path / "store.db",
        tmp_path / "kek.json",
        secrets_key="appliance-secrets-key",
    )
    return KmipDispatcher(store), provider_id


def request(operation: int, *payload: Ttlv, version: tuple[int, int] = (1, 4)) -> Ttlv:
    """Return request.

    Args:
        operation: Operation supplied to the test scenario.
        *payload: Additional positional arguments accepted by the callable.
        version: KMIP protocol version to place in the request header.
    """
    return structure(
        Tag.REQUEST_MESSAGE,
        structure(
            Tag.REQUEST_HEADER,
            structure(
                Tag.PROTOCOL_VERSION,
                integer(Tag.PROTOCOL_VERSION_MAJOR, version[0]),
                integer(Tag.PROTOCOL_VERSION_MINOR, version[1]),
            ),
            integer(Tag.BATCH_COUNT, 1),
        ),
        structure(
            Tag.BATCH_ITEM,
            enumeration(Tag.OPERATION, operation),
            structure(Tag.REQUEST_PAYLOAD, *payload),
        ),
    )


def multi_request(*items: Ttlv, version: tuple[int, int] = (1, 4)) -> Ttlv:
    """Return a request containing the supplied batch items.

    Args:
        *items: Batch Item nodes included in the request.
        version: KMIP protocol version to place in the request header.
    """
    return structure(
        Tag.REQUEST_MESSAGE,
        structure(
            Tag.REQUEST_HEADER,
            structure(
                Tag.PROTOCOL_VERSION,
                integer(Tag.PROTOCOL_VERSION_MAJOR, version[0]),
                integer(Tag.PROTOCOL_VERSION_MINOR, version[1]),
            ),
            integer(Tag.BATCH_COUNT, len(items)),
        ),
        *items,
    )


def batch_item(response: Ttlv) -> Ttlv:
    """Return batch item.

    Args:
        response: HTTP or command response being inspected.
    """
    return response.children(Tag.BATCH_ITEM)[0]


def batch_item_id(item: Ttlv) -> bytes | None:
    """Return the optional batch correlation ID from an item.

    Args:
        item: Batch Item node to inspect.
    """
    node = item.child(Tag.UNIQUE_BATCH_ITEM_ID, required=False)
    if node is None:
        return None
    assert isinstance(node.value, bytes)
    return node.value


def response_payload(response: Ttlv) -> Ttlv:
    """Return response payload.

    Args:
        response: HTTP or command response being inspected.
    """
    payload = batch_item(response).child(Tag.RESPONSE_PAYLOAD)
    assert payload is not None
    return payload


def result_status(response: Ttlv) -> int:
    """Return result status.

    Args:
        response: HTTP or command response being inspected.
    """
    node = batch_item(response).child(Tag.RESULT_STATUS)
    assert node is not None
    assert isinstance(node.value, int)
    return node.value


def response_protocol_version(response: Ttlv) -> tuple[int, int]:
    """Return the protocol version from a response header.

    Args:
        response: KMIP response message being inspected.
    """
    header = response.child(Tag.RESPONSE_HEADER)
    assert header is not None
    version = header.child(Tag.PROTOCOL_VERSION)
    assert version is not None
    major = version.child(Tag.PROTOCOL_VERSION_MAJOR)
    minor = version.child(Tag.PROTOCOL_VERSION_MINOR)
    assert major is not None and isinstance(major.value, int)
    assert minor is not None and isinstance(minor.value, int)
    return major.value, minor.value


def create_request(*, version: tuple[int, int] = (1, 4)) -> Ttlv:
    """Create request.

    Returns:
        The created request.

    Args:
        version: KMIP protocol version to place in the request header.
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
        version=version,
    )


def name_attribute(value: str) -> Ttlv:
    """Return name attribute.

    Args:
        value: Candidate value consumed by name attribute.
    """
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
    """Return created key id.

    Args:
        service: Atlaso or host service affected by the operation.
        provider_id: Stable identifier of the associated provider resource.
    """
    response = service.dispatch(provider_id, create_request())
    assert result_status(response) == ResultStatus.SUCCESS
    node = response_payload(response).child(Tag.UNIQUE_IDENTIFIER)
    assert node is not None
    assert isinstance(node.value, str)
    return node.value


def test_unique_batch_item_ids_are_echoed_for_success_and_failure(tmp_path: Path) -> None:
    """Correlation IDs are copied to both successful and failed response items.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    service, provider_id = dispatcher(tmp_path)
    create_payload = create_request().children(Tag.BATCH_ITEM)[0].child(Tag.REQUEST_PAYLOAD)
    assert create_payload is not None
    response = service.dispatch(
        provider_id,
        multi_request(
            structure(
                Tag.BATCH_ITEM,
                enumeration(Tag.OPERATION, Operation.CREATE),
                byte_string(Tag.UNIQUE_BATCH_ITEM_ID, b"create-01"),
                create_payload,
            ),
            structure(
                Tag.BATCH_ITEM,
                enumeration(Tag.OPERATION, Operation.GET),
                byte_string(Tag.UNIQUE_BATCH_ITEM_ID, b"get-missing"),
                structure(
                    Tag.REQUEST_PAYLOAD,
                    text_string(Tag.UNIQUE_IDENTIFIER, "00000000-0000-0000-0000-000000000001"),
                ),
            ),
        ),
    )

    items = response.children(Tag.BATCH_ITEM)
    assert [batch_item_id(item) for item in items] == [b"create-01", b"get-missing"]
    assert [item.child(Tag.RESULT_STATUS).value for item in items] == [
        ResultStatus.SUCCESS,
        ResultStatus.OPERATION_FAILED,
    ]


def test_unique_batch_item_id_requires_byte_string(tmp_path: Path) -> None:
    """A wrongly typed correlation ID fails the item and is not echoed.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    service, provider_id = dispatcher(tmp_path)
    response = service.dispatch(
        provider_id,
        multi_request(
            structure(
                Tag.BATCH_ITEM,
                enumeration(Tag.OPERATION, Operation.QUERY),
                text_string(Tag.UNIQUE_BATCH_ITEM_ID, "wrong-type"),
                structure(Tag.REQUEST_PAYLOAD),
            )
        ),
    )

    item = batch_item(response)
    assert result_status(response) == ResultStatus.OPERATION_FAILED
    assert item.child(Tag.RESULT_REASON).value == ResultReason.INVALID_MESSAGE
    assert batch_item_id(item) is None


def test_unique_batch_item_id_is_echoed_when_operation_is_missing(tmp_path: Path) -> None:
    """A valid correlation ID is preserved when another required field is missing.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    service, provider_id = dispatcher(tmp_path)
    response = service.dispatch(
        provider_id,
        multi_request(
            structure(
                Tag.BATCH_ITEM,
                byte_string(Tag.UNIQUE_BATCH_ITEM_ID, b"operation-missing"),
                structure(Tag.REQUEST_PAYLOAD),
            )
        ),
    )

    item = batch_item(response)
    assert result_status(response) == ResultStatus.OPERATION_FAILED
    assert item.child(Tag.RESULT_REASON).value == ResultReason.MISSING_DATA
    assert batch_item_id(item) == b"operation-missing"


def test_duplicate_unique_batch_item_id_tag_is_rejected(tmp_path: Path) -> None:
    """A repeated correlation-ID field in one item is rejected as ambiguous.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    service, provider_id = dispatcher(tmp_path)
    response = service.dispatch(
        provider_id,
        multi_request(
            structure(
                Tag.BATCH_ITEM,
                enumeration(Tag.OPERATION, Operation.QUERY),
                byte_string(Tag.UNIQUE_BATCH_ITEM_ID, b"duplicate-field"),
                byte_string(Tag.UNIQUE_BATCH_ITEM_ID, b"duplicate-field"),
                structure(Tag.REQUEST_PAYLOAD),
            )
        ),
    )

    item = batch_item(response)
    assert result_status(response) == ResultStatus.OPERATION_FAILED
    assert item.child(Tag.RESULT_REASON).value == ResultReason.INVALID_MESSAGE
    assert batch_item_id(item) is None


def test_multi_item_request_requires_each_unique_batch_item_id(tmp_path: Path) -> None:
    """Each item in a multi-item request must have a correlation ID.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    service, provider_id = dispatcher(tmp_path)
    response = service.dispatch(
        provider_id,
        multi_request(
            structure(
                Tag.BATCH_ITEM,
                enumeration(Tag.OPERATION, Operation.QUERY),
                structure(Tag.REQUEST_PAYLOAD),
            ),
            structure(
                Tag.BATCH_ITEM,
                enumeration(Tag.OPERATION, Operation.QUERY),
                byte_string(Tag.UNIQUE_BATCH_ITEM_ID, b"with-id"),
                structure(
                    Tag.REQUEST_PAYLOAD,
                    enumeration(Tag.QUERY_FUNCTION, QueryFunction.OPERATIONS),
                ),
            ),
        ),
    )

    items = response.children(Tag.BATCH_ITEM)
    assert [item.child(Tag.RESULT_STATUS).value for item in items] == [
        ResultStatus.OPERATION_FAILED,
        ResultStatus.SUCCESS,
    ]
    assert items[0].child(Tag.RESULT_REASON).value == ResultReason.INVALID_MESSAGE
    assert [batch_item_id(item) for item in items] == [None, b"with-id"]


def test_duplicate_unique_batch_item_ids_fail_and_are_echoed(tmp_path: Path) -> None:
    """Every batch item with a repeated correlation ID fails but keeps its ID.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    service, provider_id = dispatcher(tmp_path)
    duplicate_id = b"duplicate-id"
    response = service.dispatch(
        provider_id,
        multi_request(
            *(
                structure(
                    Tag.BATCH_ITEM,
                    enumeration(Tag.OPERATION, Operation.QUERY),
                    byte_string(Tag.UNIQUE_BATCH_ITEM_ID, duplicate_id),
                    structure(Tag.REQUEST_PAYLOAD),
                )
                for _ in range(2)
            )
        ),
    )

    items = response.children(Tag.BATCH_ITEM)
    assert [batch_item_id(item) for item in items] == [duplicate_id, duplicate_id]
    assert [item.child(Tag.RESULT_STATUS).value for item in items] == [
        ResultStatus.OPERATION_FAILED,
        ResultStatus.OPERATION_FAILED,
    ]
    assert all(
        item.child(Tag.RESULT_REASON).value == ResultReason.INVALID_MESSAGE
        for item in items
    )


def test_create_activate_get_round_trip_returns_only_active_key(tmp_path: Path) -> None:
    """Verify that create activate get round trip returns only active key.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    assert response_protocol_version(retrieved) == (1, 4)
    assert isinstance(key_material.value, bytes)
    assert len(key_material.value) == 32


def test_kmip_1_1_supports_bounded_create_activate_get_round_trip(tmp_path: Path) -> None:
    """KMIP 1.1 requests run the same bounded key lifecycle and echo their version."""
    service, provider_id = dispatcher(tmp_path)
    discovery = service.dispatch(
        provider_id,
        request(
            Operation.DISCOVER_VERSIONS,
            structure(Tag.PROTOCOL_VERSION, integer(Tag.PROTOCOL_VERSION_MAJOR, 1),
                      integer(Tag.PROTOCOL_VERSION_MINOR, 1)),
            version=(1, 1),
        ),
    )
    assert result_status(discovery) == ResultStatus.SUCCESS
    assert response_protocol_version(discovery) == (1, 1)
    assert _protocol_versions(response_payload(discovery).children(Tag.PROTOCOL_VERSION)) == [(1, 1)]

    create = service.dispatch(provider_id, create_request(version=(1, 1)))
    assert result_status(create) == ResultStatus.SUCCESS
    assert response_protocol_version(create) == (1, 1)
    key_id_node = response_payload(create).child(Tag.UNIQUE_IDENTIFIER)
    assert key_id_node is not None and isinstance(key_id_node.value, str)
    key_id = key_id_node.value

    activated = service.dispatch(
        provider_id,
        request(Operation.ACTIVATE, text_string(Tag.UNIQUE_IDENTIFIER, key_id), version=(1, 1)),
    )
    retrieved = service.dispatch(
        provider_id,
        request(
            Operation.GET,
            text_string(Tag.UNIQUE_IDENTIFIER, key_id),
            enumeration(Tag.KEY_FORMAT_TYPE, KEY_FORMAT_TYPE_RAW),
            version=(1, 1),
        ),
    )
    key_block = response_payload(retrieved).child(Tag.SYMMETRIC_KEY).child(Tag.KEY_BLOCK)
    key_material = key_block.child(Tag.KEY_VALUE).child(Tag.KEY_MATERIAL)

    assert result_status(activated) == ResultStatus.SUCCESS
    assert response_protocol_version(activated) == (1, 1)
    assert result_status(retrieved) == ResultStatus.SUCCESS
    assert response_protocol_version(retrieved) == (1, 1)
    assert isinstance(key_material.value, bytes) and len(key_material.value) == 32


@pytest.mark.parametrize("version", [(1, 0), (1, 2), (2, 0)])
def test_unsupported_request_protocol_versions_are_rejected(
    tmp_path: Path,
    version: tuple[int, int],
) -> None:
    """Only the explicitly supported KMIP 1.1 and 1.4 versions are accepted.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        version: Unsupported protocol version to reject.
    """
    service, provider_id = dispatcher(tmp_path)

    with pytest.raises(ProtocolFailure, match="protocol version is not supported"):
        service.dispatch(provider_id, request(Operation.DISCOVER_VERSIONS, version=version))


def test_cross_provider_get_does_not_reveal_key_existence(tmp_path: Path) -> None:
    """Verify that cross provider get does not reveal key existence.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that query and discover versions expose only bounded contract.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    discovered = response_payload(versions).children(Tag.PROTOCOL_VERSION)
    assert len(discovered) == 1
    assert _protocol_versions(discovered) == [(1, 4)]


def _protocol_versions(nodes: list[Ttlv]) -> list[tuple[int, int]]:
    """Return protocol versions from version structures.

    Args:
        nodes: Version structures returned by Discover Versions.
    """
    result = []
    for node in nodes:
        major = node.child(Tag.PROTOCOL_VERSION_MAJOR)
        minor = node.child(Tag.PROTOCOL_VERSION_MINOR)
        assert major is not None and isinstance(major.value, int)
        assert minor is not None and isinstance(minor.value, int)
        result.append((major.value, minor.value))
    return result


@pytest.mark.parametrize(
    ("offered", "expected"),
    [
        ([(1, 4), (1, 1), (1, 2), (1, 0)], [(1, 4), (1, 1)]),
        ([(1, 1)], [(1, 1)]),
        ([(1, 2), (1, 0)], []),
        ([], [(1, 4), (1, 1)]),
    ],
)
def test_discover_versions_returns_supported_intersection_in_server_preference_order(
    tmp_path: Path,
    offered: list[tuple[int, int]],
    expected: list[tuple[int, int]],
) -> None:
    """Discover Versions returns only the supported intersection, newest first.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        offered: Client protocol versions offered to the server.
        expected: Supported protocol versions expected in the response.
    """
    service, provider_id = dispatcher(tmp_path)
    payload = tuple(
        structure(
            Tag.PROTOCOL_VERSION,
            integer(Tag.PROTOCOL_VERSION_MAJOR, major),
            integer(Tag.PROTOCOL_VERSION_MINOR, minor),
        )
        for major, minor in offered
    )

    response = service.dispatch(
        provider_id,
        request(Operation.DISCOVER_VERSIONS, *payload, version=(1, 1)),
    )

    assert result_status(response) == ResultStatus.SUCCESS
    assert response_protocol_version(response) == (1, 1)
    assert _protocol_versions(response_payload(response).children(Tag.PROTOCOL_VERSION)) == expected


def test_unsupported_and_destructive_operations_fail_closed(tmp_path: Path) -> None:
    """Verify that unsupported and destructive operations fail closed.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    service, provider_id = dispatcher(tmp_path)

    response = service.dispatch(provider_id, request(0x14))
    reason = batch_item(response).child(Tag.RESULT_REASON)

    assert result_status(response) == ResultStatus.OPERATION_FAILED
    assert reason is not None
    assert reason.value == ResultReason.OPERATION_NOT_SUPPORTED
    assert batch_item(response).child(Tag.RESPONSE_PAYLOAD, required=False) is None


def test_get_attributes_and_locate_stay_inside_provider(tmp_path: Path) -> None:
    """Verify that get attributes and locate stay inside provider.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that name and activation date are persisted attributes.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that create rejects algorithm or length outside contract.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that raw key material is never accepted as request input.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
