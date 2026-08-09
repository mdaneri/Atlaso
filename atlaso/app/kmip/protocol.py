"""Bounded KMIP 1.4 operation dispatcher for the vSphere Key Provider."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum

from atlaso.app.kmip.store import (
    KeyNotFoundError,
    KeyStateError,
    KeyStoreError,
    StoredKey,
    WrappedKeyStore,
)
from atlaso.app.kmip.ttlv import (
    Ttlv,
    TtlvError,
    TtlvType,
    assert_only_tags,
    byte_string,
    date_time,
    enumeration,
    integer,
    structure,
    text_string,
)


class Tag(IntEnum):
    """Represent tag.

    Attributes:
        ACTIVATION_DATE: Symbolic value representing 4325377.
        ATTRIBUTE: Symbolic value representing 4325384.
        ATTRIBUTE_NAME: Symbolic value representing 4325386.
        ATTRIBUTE_VALUE: Symbolic value representing 4325387.
        BATCH_COUNT: Symbolic value representing 4325389.
        BATCH_ITEM: Symbolic value representing 4325391.
        CRYPTOGRAPHIC_ALGORITHM: Symbolic value representing 4325416.
        CRYPTOGRAPHIC_LENGTH: Symbolic value representing 4325418.
        CRYPTOGRAPHIC_USAGE_MASK: Symbolic value representing 4325420.
        KEY_BLOCK: Symbolic value representing 4325440.
        KEY_FORMAT_TYPE: Symbolic value representing 4325442.
        KEY_MATERIAL: Symbolic value representing 4325443.
        KEY_VALUE: Symbolic value representing 4325445.
        MAXIMUM_RESPONSE_SIZE: Symbolic value representing 4325456.
        NAME: Symbolic value representing 4325459.
        NAME_TYPE: Symbolic value representing 4325460.
        NAME_VALUE: Symbolic value representing 4325461.
        OBJECT_TYPE: Symbolic value representing 4325463.
        OPERATION: Symbolic value representing 4325468.
        PROTOCOL_VERSION: Symbolic value representing 4325481.
        PROTOCOL_VERSION_MAJOR: Symbolic value representing 4325482.
        PROTOCOL_VERSION_MINOR: Symbolic value representing 4325483.
        QUERY_FUNCTION: Symbolic value representing 4325492.
        REQUEST_HEADER: Symbolic value representing 4325495.
        REQUEST_MESSAGE: Symbolic value representing 4325496.
        REQUEST_PAYLOAD: Symbolic value representing 4325497.
        RESPONSE_HEADER: Symbolic value representing 4325498.
        RESPONSE_MESSAGE: Symbolic value representing 4325499.
        RESPONSE_PAYLOAD: Symbolic value representing 4325500.
        RESULT_MESSAGE: Symbolic value representing 4325501.
        RESULT_REASON: Symbolic value representing 4325502.
        RESULT_STATUS: Symbolic value representing 4325503.
        STATE: Symbolic value representing 4325517.
        SYMMETRIC_KEY: Symbolic value representing 4325519.
        TEMPLATE_ATTRIBUTE: Symbolic value representing 4325521.
        TIME_STAMP: Symbolic value representing 4325522.
        UNIQUE_IDENTIFIER: Symbolic value representing 4325524.
        VENDOR_IDENTIFICATION: Symbolic value representing 4325533.
    """
    ACTIVATION_DATE = 0x420001
    ATTRIBUTE = 0x420008
    ATTRIBUTE_NAME = 0x42000A
    ATTRIBUTE_VALUE = 0x42000B
    BATCH_COUNT = 0x42000D
    BATCH_ITEM = 0x42000F
    CRYPTOGRAPHIC_ALGORITHM = 0x420028
    CRYPTOGRAPHIC_LENGTH = 0x42002A
    CRYPTOGRAPHIC_USAGE_MASK = 0x42002C
    KEY_BLOCK = 0x420040
    KEY_FORMAT_TYPE = 0x420042
    KEY_MATERIAL = 0x420043
    KEY_VALUE = 0x420045
    MAXIMUM_RESPONSE_SIZE = 0x420050
    NAME = 0x420053
    NAME_TYPE = 0x420054
    NAME_VALUE = 0x420055
    OBJECT_TYPE = 0x420057
    OPERATION = 0x42005C
    PROTOCOL_VERSION = 0x420069
    PROTOCOL_VERSION_MAJOR = 0x42006A
    PROTOCOL_VERSION_MINOR = 0x42006B
    QUERY_FUNCTION = 0x420074
    REQUEST_HEADER = 0x420077
    REQUEST_MESSAGE = 0x420078
    REQUEST_PAYLOAD = 0x420079
    RESPONSE_HEADER = 0x42007A
    RESPONSE_MESSAGE = 0x42007B
    RESPONSE_PAYLOAD = 0x42007C
    RESULT_MESSAGE = 0x42007D
    RESULT_REASON = 0x42007E
    RESULT_STATUS = 0x42007F
    STATE = 0x42008D
    SYMMETRIC_KEY = 0x42008F
    TEMPLATE_ATTRIBUTE = 0x420091
    TIME_STAMP = 0x420092
    UNIQUE_IDENTIFIER = 0x420094
    VENDOR_IDENTIFICATION = 0x42009D


class Operation(IntEnum):
    """Represent operation.

    Attributes:
        CREATE: Symbolic value representing 1.
        LOCATE: Symbolic value representing 8.
        GET: Symbolic value representing 10.
        GET_ATTRIBUTES: Symbolic value representing 11.
        GET_ATTRIBUTE_LIST: Symbolic value representing 12.
        ACTIVATE: Symbolic value representing 18.
        QUERY: Symbolic value representing 24.
        DISCOVER_VERSIONS: Symbolic value representing 30.
    """
    CREATE = 0x00000001
    LOCATE = 0x00000008
    GET = 0x0000000A
    GET_ATTRIBUTES = 0x0000000B
    GET_ATTRIBUTE_LIST = 0x0000000C
    ACTIVATE = 0x00000012
    QUERY = 0x00000018
    DISCOVER_VERSIONS = 0x0000001E


class ResultStatus(IntEnum):
    """Represent result status.

    Attributes:
        SUCCESS: Symbolic value representing 0.
        OPERATION_FAILED: Symbolic value representing 1.
    """
    SUCCESS = 0
    OPERATION_FAILED = 1


class ResultReason(IntEnum):
    """Represent result reason.

    Attributes:
        ITEM_NOT_FOUND: Symbolic value representing 1.
        INVALID_MESSAGE: Symbolic value representing 4.
        OPERATION_NOT_SUPPORTED: Symbolic value representing 5.
        MISSING_DATA: Symbolic value representing 6.
        INVALID_FIELD: Symbolic value representing 7.
        KEY_FORMAT_TYPE_NOT_SUPPORTED: Symbolic value representing 16.
        GENERAL_FAILURE: Symbolic value representing 256.
    """
    ITEM_NOT_FOUND = 1
    INVALID_MESSAGE = 4
    OPERATION_NOT_SUPPORTED = 5
    MISSING_DATA = 6
    INVALID_FIELD = 7
    KEY_FORMAT_TYPE_NOT_SUPPORTED = 16
    GENERAL_FAILURE = 256


class QueryFunction(IntEnum):
    """Represent query function.

    Attributes:
        OPERATIONS: Symbolic value representing 1.
        OBJECTS: Symbolic value representing 2.
        SERVER_INFORMATION: Symbolic value representing 3.
    """
    OPERATIONS = 1
    OBJECTS = 2
    SERVER_INFORMATION = 3


OBJECT_TYPE_SYMMETRIC_KEY = 2
CRYPTOGRAPHIC_ALGORITHM_AES = 3
KEY_FORMAT_TYPE_RAW = 1
NAME_TYPE_UNINTERPRETED_TEXT_STRING = 1
STATE_PRE_ACTIVE = 1
STATE_ACTIVE = 2
USAGE_ENCRYPT_DECRYPT = 0x0000000C
MAX_BATCH_ITEMS = 16
ATTRIBUTE_TAGS = {
    "Activation Date": Tag.ACTIVATION_DATE,
    "Cryptographic Algorithm": Tag.CRYPTOGRAPHIC_ALGORITHM,
    "Cryptographic Length": Tag.CRYPTOGRAPHIC_LENGTH,
    "Cryptographic Usage Mask": Tag.CRYPTOGRAPHIC_USAGE_MASK,
    "Name": Tag.NAME,
    "Object Type": Tag.OBJECT_TYPE,
    "State": Tag.STATE,
    "Unique Identifier": Tag.UNIQUE_IDENTIFIER,
}


@dataclass(frozen=True)
class ProtocolFailure(Exception):
    """Represent protocol failure.

    Attributes:
        reason: Reason maintained by this protocolfailure.
        message: Message maintained by this protocolfailure.
    """
    reason: ResultReason
    message: str


def _value(node: Ttlv, expected_type: TtlvType) -> int | bool | str | bytes:
    """Return value.

    Args:
        node: Node consumed by value.
        expected_type: Expected type used to verify the result.


    Raises:
        ProtocolFailure: If the operation encounters an invalid state.
    """
    if node.type is not expected_type:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "A KMIP field has the wrong TTLV type.")
    assert not isinstance(node.value, tuple)
    return node.value


def _integer_value(node: Ttlv, expected_type: TtlvType = TtlvType.INTEGER) -> int:
    """Return integer value.

    Args:
        node: Node consumed by integer value.
        expected_type: Expected type used to verify the result.


    Raises:
        ProtocolFailure: If the operation encounters an invalid state.
    """
    value = _value(node, expected_type)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "A KMIP numeric field is invalid.")
    return value


def _text_value(node: Ttlv) -> str:
    """Return text value.

    Args:
        node: Node consumed by text value.


    Raises:
        ProtocolFailure: If the operation encounters an invalid state.
    """
    value = _value(node, TtlvType.TEXT_STRING)
    if not isinstance(value, str):
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "A KMIP text field is invalid.")
    return value


def _required_child(node: Ttlv, tag: Tag) -> Ttlv:
    """Return required child.

    Args:
        node: Node consumed by required child.
        tag: Tag consumed by required child.


    Raises:
        ProtocolFailure: If the operation encounters an invalid state.
    """
    try:
        child = node.child(tag)
    except TtlvError as exc:
        raise ProtocolFailure(ResultReason.MISSING_DATA, "A required KMIP field is missing.") from exc
    assert child is not None
    return child


def _protocol_version(node: Ttlv) -> tuple[int, int]:
    """Return protocol version.

    Args:
        node: Node consumed by protocol version.


    Raises:
        ProtocolFailure: If the operation encounters an invalid state.
    """
    if node.type is not TtlvType.STRUCTURE:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "Protocol Version must be a structure.")
    try:
        assert_only_tags(node, {Tag.PROTOCOL_VERSION_MAJOR, Tag.PROTOCOL_VERSION_MINOR})
    except TtlvError as exc:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "Protocol Version contains unsupported fields.") from exc
    major = _integer_value(_required_child(node, Tag.PROTOCOL_VERSION_MAJOR))
    minor = _integer_value(_required_child(node, Tag.PROTOCOL_VERSION_MINOR))
    return major, minor


def _version_node() -> Ttlv:
    """Return version node."""
    return structure(
        Tag.PROTOCOL_VERSION,
        integer(Tag.PROTOCOL_VERSION_MAJOR, 1),
        integer(Tag.PROTOCOL_VERSION_MINOR, 4),
    )


def _attribute(name: str, value: Ttlv) -> Ttlv:
    """Return attribute.

    Args:
        name: Stable name identifying the resource or operation.
        value: Candidate value consumed by attribute.
    """
    return structure(
        Tag.ATTRIBUTE,
        text_string(Tag.ATTRIBUTE_NAME, name),
        Ttlv(Tag.ATTRIBUTE_VALUE, value.type, value.value),
    )


def _metadata_attribute(name: str, metadata: StoredKey) -> Ttlv:
    """Return metadata attribute.

    Args:
        name: Stable name identifying the resource or operation.
        metadata: Structured metadata associated with the artifact or operation.


    Raises:
        ProtocolFailure: If the operation encounters an invalid state.
    """
    if name == "Cryptographic Algorithm":
        value = enumeration(Tag.ATTRIBUTE_VALUE, CRYPTOGRAPHIC_ALGORITHM_AES)
    elif name == "Cryptographic Length":
        value = integer(Tag.ATTRIBUTE_VALUE, 256)
    elif name == "Cryptographic Usage Mask":
        value = integer(Tag.ATTRIBUTE_VALUE, USAGE_ENCRYPT_DECRYPT)
    elif name == "Object Type":
        value = enumeration(Tag.ATTRIBUTE_VALUE, OBJECT_TYPE_SYMMETRIC_KEY)
    elif name == "State":
        state = STATE_ACTIVE if metadata.state == "Active" else STATE_PRE_ACTIVE
        value = enumeration(Tag.ATTRIBUTE_VALUE, state)
    elif name == "Unique Identifier":
        value = text_string(Tag.ATTRIBUTE_VALUE, metadata.key_id)
    elif name == "Activation Date":
        if metadata.activated_at is None:
            raise ProtocolFailure(
                ResultReason.INVALID_FIELD,
                "Activation Date is unavailable for a pre-active key.",
            )
        value = date_time(
            Tag.ATTRIBUTE_VALUE,
            int(datetime.fromisoformat(metadata.activated_at).timestamp()),
        )
    elif name == "Name":
        if metadata.name is None:
            raise ProtocolFailure(
                ResultReason.INVALID_FIELD,
                "Name is unavailable for this key.",
            )
        value = structure(
            Tag.ATTRIBUTE_VALUE,
            text_string(Tag.NAME_VALUE, metadata.name),
            enumeration(Tag.NAME_TYPE, NAME_TYPE_UNINTERPRETED_TEXT_STRING),
        )
    else:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "Requested KMIP attribute is unsupported.")
    return _attribute(name, value)


def _parse_name(node: Ttlv) -> str:
    """Parse name.

    Args:
        node: Candidate node to parse.


    Returns:
        The parsed name.

    Raises:
        ProtocolFailure: If the operation encounters an invalid state.
    """
    if node.type is not TtlvType.STRUCTURE:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "Name must be a structure.")
    try:
        assert_only_tags(node, {Tag.NAME_VALUE, Tag.NAME_TYPE})
    except TtlvError as exc:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "Name contains unsupported fields.") from exc
    name = _text_value(_required_child(node, Tag.NAME_VALUE))
    name_type = _integer_value(
        _required_child(node, Tag.NAME_TYPE),
        TtlvType.ENUMERATION,
    )
    if name_type != NAME_TYPE_UNINTERPRETED_TEXT_STRING:
        raise ProtocolFailure(
            ResultReason.INVALID_FIELD,
            "Only Uninterpreted Text String names are supported.",
        )
    if not 1 <= len(name) <= 256:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "Name must contain 1 to 256 characters.")
    return name


def _parse_template_attributes(
    template: Ttlv,
    *,
    allowed_names: set[str],
) -> dict[str, int | str]:
    """Parse template attributes.

    Args:
        template: Candidate template to parse.
        allowed_names: Candidate allowed names to parse.


    Returns:
        The parsed template attributes.

    Raises:
        ProtocolFailure: If the operation encounters an invalid state.
    """
    if template.type is not TtlvType.STRUCTURE:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "Template Attribute must be a structure.")
    try:
        assert_only_tags(template, {Tag.ATTRIBUTE})
    except TtlvError as exc:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "Template Attribute contains unsupported fields.") from exc
    result: dict[str, int | str] = {}
    for attribute in template.children(Tag.ATTRIBUTE):
        if attribute.type is not TtlvType.STRUCTURE:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Attribute must be a structure.")
        try:
            assert_only_tags(attribute, {Tag.ATTRIBUTE_NAME, Tag.ATTRIBUTE_VALUE})
        except TtlvError as exc:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Attribute contains unsupported fields.") from exc
        name = _text_value(_required_child(attribute, Tag.ATTRIBUTE_NAME))
        if name in result:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Duplicate KMIP attributes are unsupported.")
        if name not in allowed_names:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Create attribute is outside the allowlist.")
        raw_value = _required_child(attribute, Tag.ATTRIBUTE_VALUE)
        if name == "Name":
            result[name] = _parse_name(raw_value)
            continue
        expected = (
            TtlvType.ENUMERATION
            if name in {"Cryptographic Algorithm", "Object Type", "State"}
            else TtlvType.INTEGER
        )
        result[name] = _integer_value(raw_value, expected)
    return result


def _unique_identifier(payload: Ttlv) -> str:
    """Return unique identifier.

    Args:
        payload: Validated request or task payload consumed by the operation.


    Raises:
        ProtocolFailure: If the operation encounters an invalid state.
    """
    value = _text_value(_required_child(payload, Tag.UNIQUE_IDENTIFIER))
    if not value:
        raise ProtocolFailure(ResultReason.INVALID_FIELD, "Unique Identifier must not be empty.")
    return value


class KmipDispatcher:
    """Dispatch the exact candidate operation set inside one provider namespace.

    Attributes:
        store: Store maintained by this kmipdispatcher.
    """

    def __init__(self, store: WrappedKeyStore) -> None:
        """Initialize the kmip dispatcher.

        Args:
            store: Store consumed by init.
        """
        self.store = store

    def _create(self, provider_id: str, payload: Ttlv) -> list[Ttlv]:
        """Create operation.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            payload: Validated request or task payload consumed by the operation.


        Returns:
            The create result.

        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        try:
            assert_only_tags(payload, {Tag.OBJECT_TYPE, Tag.TEMPLATE_ATTRIBUTE})
        except TtlvError as exc:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Create contains unsupported fields.") from exc
        object_type = _integer_value(
            _required_child(payload, Tag.OBJECT_TYPE),
            TtlvType.ENUMERATION,
        )
        if object_type != OBJECT_TYPE_SYMMETRIC_KEY:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Only Symmetric Key objects are supported.")
        attributes = _parse_template_attributes(
            _required_child(payload, Tag.TEMPLATE_ATTRIBUTE),
            allowed_names={
                "Cryptographic Algorithm",
                "Cryptographic Length",
                "Cryptographic Usage Mask",
                "Name",
            },
        )
        if attributes.get("Cryptographic Algorithm") != CRYPTOGRAPHIC_ALGORITHM_AES:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Only AES keys are supported.")
        if attributes.get("Cryptographic Length") != 256:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Only AES-256 keys are supported.")
        usage = attributes.get("Cryptographic Usage Mask", USAGE_ENCRYPT_DECRYPT)
        if usage != USAGE_ENCRYPT_DECRYPT:
            raise ProtocolFailure(
                ResultReason.INVALID_FIELD,
                "Only Encrypt and Decrypt key usage is supported.",
            )
        name = attributes.get("Name")
        assert name is None or isinstance(name, str)
        metadata = self.store.create_key(provider_id, name=name)
        return [
            enumeration(Tag.OBJECT_TYPE, OBJECT_TYPE_SYMMETRIC_KEY),
            text_string(Tag.UNIQUE_IDENTIFIER, metadata.key_id),
        ]

    def _activate(self, provider_id: str, payload: Ttlv) -> list[Ttlv]:
        """Return activate.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            payload: Validated request or task payload consumed by the operation.


        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        try:
            assert_only_tags(payload, {Tag.UNIQUE_IDENTIFIER})
        except TtlvError as exc:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Activate contains unsupported fields.") from exc
        key_id = _unique_identifier(payload)
        self.store.activate_key(provider_id, key_id)
        return [text_string(Tag.UNIQUE_IDENTIFIER, key_id)]

    def _get(self, provider_id: str, payload: Ttlv) -> list[Ttlv]:
        """Return operation.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            payload: Validated request or task payload consumed by the operation.


        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        try:
            assert_only_tags(payload, {Tag.UNIQUE_IDENTIFIER, Tag.KEY_FORMAT_TYPE})
        except TtlvError as exc:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Get contains unsupported fields.") from exc
        format_node = payload.child(Tag.KEY_FORMAT_TYPE, required=False)
        if format_node is not None and _integer_value(format_node, TtlvType.ENUMERATION) != KEY_FORMAT_TYPE_RAW:
            raise ProtocolFailure(
                ResultReason.KEY_FORMAT_TYPE_NOT_SUPPORTED,
                "Only Raw symmetric key format is supported.",
            )
        key_id = _unique_identifier(payload)
        metadata, plaintext = self.store.get_key(provider_id, key_id)
        try:
            if metadata.state != "Active":
                raise ProtocolFailure(
                    ResultReason.INVALID_FIELD,
                    "Only active KMIP keys may be retrieved.",
                )
            return [
                enumeration(Tag.OBJECT_TYPE, OBJECT_TYPE_SYMMETRIC_KEY),
                text_string(Tag.UNIQUE_IDENTIFIER, metadata.key_id),
                structure(
                    Tag.SYMMETRIC_KEY,
                    structure(
                        Tag.KEY_BLOCK,
                        enumeration(Tag.KEY_FORMAT_TYPE, KEY_FORMAT_TYPE_RAW),
                        structure(
                            Tag.KEY_VALUE,
                            byte_string(Tag.KEY_MATERIAL, plaintext),
                        ),
                        enumeration(Tag.CRYPTOGRAPHIC_ALGORITHM, CRYPTOGRAPHIC_ALGORITHM_AES),
                        integer(Tag.CRYPTOGRAPHIC_LENGTH, 256),
                    ),
                ),
            ]
        finally:
            mutable = bytearray(plaintext)
            mutable[:] = b"\0" * len(mutable)

    def _get_attribute_list(self, provider_id: str, payload: Ttlv) -> list[Ttlv]:
        """Return attribute list.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            payload: Validated request or task payload consumed by the operation.


        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        try:
            assert_only_tags(payload, {Tag.UNIQUE_IDENTIFIER})
        except TtlvError as exc:
            raise ProtocolFailure(
                ResultReason.INVALID_FIELD,
                "Get Attribute List contains unsupported fields.",
            ) from exc
        metadata = self.store.get_metadata(provider_id, _unique_identifier(payload))
        names = [
            "Cryptographic Algorithm",
            "Cryptographic Length",
            "Cryptographic Usage Mask",
            "Object Type",
            "State",
            "Unique Identifier",
        ]
        if metadata.name is not None:
            names.append("Name")
        if metadata.activated_at is not None:
            names.append("Activation Date")
        return [
            text_string(Tag.UNIQUE_IDENTIFIER, metadata.key_id),
            *(text_string(Tag.ATTRIBUTE_NAME, name) for name in names),
        ]

    def _get_attributes(self, provider_id: str, payload: Ttlv) -> list[Ttlv]:
        """Return attributes.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            payload: Validated request or task payload consumed by the operation.


        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        try:
            assert_only_tags(payload, {Tag.UNIQUE_IDENTIFIER, Tag.ATTRIBUTE_NAME})
        except TtlvError as exc:
            raise ProtocolFailure(
                ResultReason.INVALID_FIELD,
                "Get Attributes contains unsupported fields.",
            ) from exc
        metadata = self.store.get_metadata(provider_id, _unique_identifier(payload))
        names = [_text_value(node) for node in payload.children(Tag.ATTRIBUTE_NAME)]
        if not names:
            names = [
                "Cryptographic Algorithm",
                "Cryptographic Length",
                "Cryptographic Usage Mask",
                "Object Type",
                "State",
                "Unique Identifier",
            ]
            if metadata.name is not None:
                names.append("Name")
            if metadata.activated_at is not None:
                names.append("Activation Date")
        if len(names) != len(set(names)) or any(name not in ATTRIBUTE_TAGS for name in names):
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Requested attributes are invalid.")
        return [
            text_string(Tag.UNIQUE_IDENTIFIER, metadata.key_id),
            *(_metadata_attribute(name, metadata) for name in names),
        ]

    def _locate(self, provider_id: str, payload: Ttlv) -> list[Ttlv]:
        """Return locate.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            payload: Validated request or task payload consumed by the operation.


        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        try:
            assert_only_tags(payload, {Tag.MAXIMUM_RESPONSE_SIZE, Tag.ATTRIBUTE})
        except TtlvError as exc:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Locate contains unsupported fields.") from exc
        if payload.children(Tag.ATTRIBUTE):
            template = structure(Tag.TEMPLATE_ATTRIBUTE, *payload.children(Tag.ATTRIBUTE))
            filters = _parse_template_attributes(
                template,
                allowed_names={
                    "Cryptographic Algorithm",
                    "Cryptographic Length",
                    "Name",
                    "Object Type",
                    "State",
                },
            )
            if filters.get("Cryptographic Algorithm", CRYPTOGRAPHIC_ALGORITHM_AES) != CRYPTOGRAPHIC_ALGORITHM_AES:
                return []
            if filters.get("Cryptographic Length", 256) != 256:
                return []
            if filters.get("Object Type", OBJECT_TYPE_SYMMETRIC_KEY) != OBJECT_TYPE_SYMMETRIC_KEY:
                return []
            raw_state = filters.get("State")
            if raw_state not in {None, STATE_PRE_ACTIVE, STATE_ACTIVE}:
                return []
            state = (
                "Pre-Active"
                if raw_state == STATE_PRE_ACTIVE
                else "Active" if raw_state == STATE_ACTIVE else None
            )
            name = filters.get("Name")
            assert name is None or isinstance(name, str)
        else:
            state = None
            name = None
        return [
            text_string(Tag.UNIQUE_IDENTIFIER, key_id)
            for key_id in self.store.locate_keys(provider_id, state=state, name=name)
        ]

    @staticmethod
    def _query(payload: Ttlv) -> list[Ttlv]:
        """Return query.

        Args:
            payload: Validated request or task payload consumed by the operation.


        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        try:
            assert_only_tags(payload, {Tag.QUERY_FUNCTION})
        except TtlvError as exc:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Query contains unsupported fields.") from exc
        requested = [
            _integer_value(node, TtlvType.ENUMERATION)
            for node in payload.children(Tag.QUERY_FUNCTION)
        ]
        if not requested:
            raise ProtocolFailure(ResultReason.MISSING_DATA, "Query Function is required.")
        if len(requested) != len(set(requested)):
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Query Function must not be duplicated.")
        result: list[Ttlv] = []
        for function in requested:
            if function == QueryFunction.OPERATIONS:
                result.extend(enumeration(Tag.OPERATION, operation) for operation in Operation)
            elif function == QueryFunction.OBJECTS:
                result.append(enumeration(Tag.OBJECT_TYPE, OBJECT_TYPE_SYMMETRIC_KEY))
            elif function == QueryFunction.SERVER_INFORMATION:
                result.append(text_string(Tag.VENDOR_IDENTIFICATION, "Atlaso"))
            else:
                raise ProtocolFailure(
                    ResultReason.OPERATION_NOT_SUPPORTED,
                    "Query Function is outside the supported contract.",
                )
        return result

    @staticmethod
    def _discover_versions(payload: Ttlv) -> list[Ttlv]:
        """Return discover versions.

        Args:
            payload: Validated request or task payload consumed by the operation.


        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        try:
            assert_only_tags(payload, {Tag.PROTOCOL_VERSION})
        except TtlvError as exc:
            raise ProtocolFailure(
                ResultReason.INVALID_FIELD,
                "Discover Versions contains unsupported fields.",
            ) from exc
        versions = [_protocol_version(node) for node in payload.children(Tag.PROTOCOL_VERSION)]
        if versions and (1, 4) not in versions:
            raise ProtocolFailure(
                ResultReason.INVALID_FIELD,
                "No mutually supported KMIP protocol version was offered.",
            )
        return [_version_node()]

    def _dispatch_operation(
        self,
        provider_id: str,
        operation: Operation,
        payload: Ttlv,
    ) -> list[Ttlv]:
        """Return dispatch operation.

        Args:
            provider_id: Stable identifier of the associated provider resource.
            operation: Operation consumed by dispatch operation.
            payload: Validated request or task payload consumed by the operation.


        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        if payload.type is not TtlvType.STRUCTURE:
            raise ProtocolFailure(ResultReason.INVALID_FIELD, "Request Payload must be a structure.")
        handlers = {
            Operation.CREATE: self._create,
            Operation.ACTIVATE: self._activate,
            Operation.GET: self._get,
            Operation.GET_ATTRIBUTES: self._get_attributes,
            Operation.GET_ATTRIBUTE_LIST: self._get_attribute_list,
            Operation.LOCATE: self._locate,
        }
        if operation is Operation.QUERY:
            return self._query(payload)
        if operation is Operation.DISCOVER_VERSIONS:
            return self._discover_versions(payload)
        return handlers[operation](provider_id, payload)

    @staticmethod
    def _failed_batch(operation_value: int, failure: ProtocolFailure) -> Ttlv:
        """Return failed batch.

        Args:
            operation_value: Operation value consumed by failed batch.
            failure: Failure consumed by failed batch.
        """
        return structure(
            Tag.BATCH_ITEM,
            enumeration(Tag.OPERATION, operation_value),
            enumeration(Tag.RESULT_STATUS, ResultStatus.OPERATION_FAILED),
            enumeration(Tag.RESULT_REASON, failure.reason),
            text_string(Tag.RESULT_MESSAGE, failure.message),
        )

    def dispatch(self, provider_id: str, request: Ttlv) -> Ttlv:
        """Return dispatch.

        Args:
            provider_id: Identifier of the provider.
            request: Incoming HTTP request.

        Raises:
            ProtocolFailure: If the operation encounters an invalid state.
        """
        if request.tag != Tag.REQUEST_MESSAGE or request.type is not TtlvType.STRUCTURE:
            raise ProtocolFailure(ResultReason.INVALID_MESSAGE, "Root TTLV must be Request Message.")
        try:
            assert_only_tags(request, {Tag.REQUEST_HEADER, Tag.BATCH_ITEM})
        except TtlvError as exc:
            raise ProtocolFailure(ResultReason.INVALID_MESSAGE, "Request Message contains unsupported fields.") from exc
        header = _required_child(request, Tag.REQUEST_HEADER)
        if header.type is not TtlvType.STRUCTURE:
            raise ProtocolFailure(ResultReason.INVALID_MESSAGE, "Request Header must be a structure.")
        try:
            assert_only_tags(
                header,
                {Tag.PROTOCOL_VERSION, Tag.MAXIMUM_RESPONSE_SIZE, Tag.BATCH_COUNT},
            )
        except TtlvError as exc:
            raise ProtocolFailure(ResultReason.INVALID_MESSAGE, "Request Header contains unsupported fields.") from exc
        if _protocol_version(_required_child(header, Tag.PROTOCOL_VERSION)) != (1, 4):
            raise ProtocolFailure(ResultReason.INVALID_MESSAGE, "Only KMIP 1.4 is supported.")
        batch_items = request.children(Tag.BATCH_ITEM)
        batch_count = _integer_value(_required_child(header, Tag.BATCH_COUNT))
        if batch_count != len(batch_items) or not 1 <= batch_count <= MAX_BATCH_ITEMS:
            raise ProtocolFailure(ResultReason.INVALID_MESSAGE, "KMIP Batch Count is invalid.")

        responses: list[Ttlv] = []
        for item in batch_items:
            operation_value = 0
            try:
                if item.type is not TtlvType.STRUCTURE:
                    raise ProtocolFailure(ResultReason.INVALID_MESSAGE, "Batch Item must be a structure.")
                assert_only_tags(item, {Tag.OPERATION, Tag.REQUEST_PAYLOAD})
                operation_value = _integer_value(
                    _required_child(item, Tag.OPERATION),
                    TtlvType.ENUMERATION,
                )
                try:
                    operation = Operation(operation_value)
                except ValueError as exc:
                    raise ProtocolFailure(
                        ResultReason.OPERATION_NOT_SUPPORTED,
                        "Operation is outside the supported contract.",
                    ) from exc
                payload = _required_child(item, Tag.REQUEST_PAYLOAD)
                result = self._dispatch_operation(provider_id, operation, payload)
                responses.append(
                    structure(
                        Tag.BATCH_ITEM,
                        enumeration(Tag.OPERATION, operation),
                        enumeration(Tag.RESULT_STATUS, ResultStatus.SUCCESS),
                        structure(Tag.RESPONSE_PAYLOAD, *result),
                    )
                )
            except TtlvError:
                failure = ProtocolFailure(
                    ResultReason.INVALID_MESSAGE,
                    "Batch Item contains invalid TTLV.",
                )
                responses.append(self._failed_batch(operation_value, failure))
            except KeyNotFoundError:
                failure = ProtocolFailure(
                    ResultReason.ITEM_NOT_FOUND,
                    "KMIP key was not found in the authenticated provider.",
                )
                responses.append(self._failed_batch(operation_value, failure))
            except KeyStateError:
                failure = ProtocolFailure(ResultReason.INVALID_FIELD, "KMIP key state is invalid.")
                responses.append(self._failed_batch(operation_value, failure))
            except KeyStoreError:
                failure = ProtocolFailure(
                    ResultReason.GENERAL_FAILURE,
                    "KMIP operational store request failed.",
                )
                responses.append(self._failed_batch(operation_value, failure))
            except ProtocolFailure as failure:
                responses.append(self._failed_batch(operation_value, failure))

        return structure(
            Tag.RESPONSE_MESSAGE,
            structure(
                Tag.RESPONSE_HEADER,
                _version_node(),
                date_time(Tag.TIME_STAMP, int(time.time())),
                integer(Tag.BATCH_COUNT, len(responses)),
            ),
            *responses,
        )
