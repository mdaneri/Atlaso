"""Read-only baseline data for a separately admitted normal-UI restoration journal."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import re
from collections import Counter
from collections.abc import Callable
from html import unescape
from html.parser import HTMLParser
from typing import Any

from scripts.interop.certificate_dual_stack_guest import GuestRefusal, public_bytes
from scripts.interop.certificate_dual_stack_ui import (
    FIELDS,
    REVIEW_KEYS,
    UIClient,
    assert_public_review,
    interface_fields,
    selected_interface,
)

_REVIEW_PATH = "/ui/management/appliance-apply/review"
_DNS_PATH = "/ui/management/dns"
_DNS_ACTION = f"{_DNS_PATH}/settings"
_INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
_NULLABLE = {"ip_cidr": (4, True), "gateway": (4, False), "ipv6_cidr": (6, True), "ipv6_gateway": (6, False)}
_ROW_KEYS = (set(FIELDS) - {"admin_state"}) | {"id", "name", "mac_address", "admin_up"}
_CHECKBOXES = {"enabled", "expand_hosts", "authoritative", "dnssec_enabled", "rebind_protection_enabled"}
_NUMBERS = {"cache_size", "authoritative_ttl", "authoritative_refresh", "authoritative_retry", "authoritative_expire"}
_TEXT = {"authoritative_server", "authoritative_contact"}
_TEXTAREAS = {"upstream_servers", "conditional_forwarders", "rebind_domain_exemptions"}
_QUERY_MODE = "query_logging_mode"
_QUERY_OPTIONS = {"off", "queries-extra"}
_REQUIRED_DNS = _CHECKBOXES | _NUMBERS | _TEXT | _TEXTAREAS | {"listen_interfaces_present", _QUERY_MODE}
_FORM_CONTROLS = {"input", "textarea", "select", "button", "object", "output", "fieldset"}
_RAW_TEXT = {"noscript", "title", "iframe", "xmp", "noembed", "noframes", "script", "style"}


class _DNSSettingsForm(HTMLParser):
    """Read the current DNS settings controls and refuse unsupported ownership or markup."""

    CDATA_CONTENT_ELEMENTS = (  # type: ignore[misc]  # HTMLParser dispatches through the subclass's raw-text table.
        *HTMLParser.CDATA_CONTENT_ELEMENTS, *_RAW_TEXT, "textarea",
    )

    def __init__(self) -> None:
        super().__init__()
        self.form_open = False
        self.target = False
        self.matches = 0
        self.target_id = ""
        self.ids: Counter[str] = Counter()
        self.external_owners: set[str] = set()
        self.fieldsets: list[bool] = []
        self.inert: list[str] = []
        self.datalist_depth = 0
        self.values: dict[str, Any] = {}
        self.interfaces: list[str] = []
        self.csrf = ""
        self.textarea: str | None = None
        self.text_parts: list[str] = []
        self.select_open = False
        self.options: set[str] = set()
        self.selected: list[str] = []
        self.option_open = False

    def _put(self, name: str, value: object) -> None:
        """Record one uniquely named public control.

        Args:
            name: Supported control name.
            value: Parsed desired value.
        """
        if name in self.values:
            raise GuestRefusal("restoration_dns_form_invalid")
        self.values[name] = value

    def _input(self, name: str, attrs: dict[str, str | None]) -> None:
        """Interpret the current template's input types.

        Args:
            name: Input name or empty string for a display control.
            attrs: Parsed attributes after ownership checks.
        """
        kind = attrs.get("type", "text")
        value = attrs.get("value")
        if not name:
            if kind == "text" or (kind == "number" and "readonly" in attrs):
                return
        elif name in _CHECKBOXES and kind == "checkbox" and ("value" not in attrs or value == "on"):
            self._put(name, "checked" in attrs)
            return
        elif name in _NUMBERS and kind == "number" and isinstance(value, str):
            if re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", value):
                number = int(value)
                if (0 if name == "cache_size" else 1) <= number <= 2_147_483_647:
                    self._put(name, number)
                    return
        elif name in _TEXT and kind == "text" and isinstance(value, str) and len(value) <= 253:
            self._put(name, value)
            return
        elif kind == "hidden" and isinstance(value, str):
            if name == "csrf" and not self.csrf and 0 < len(value) <= 4096:
                self.csrf = value
                return
            if name == "listen_interfaces_present" and value == "1":
                self._put(name, value)
                return
            if name == "listen_interfaces" and _INTERFACE.fullmatch(value):
                if len(self.interfaces) < 256 and value not in self.interfaces:
                    self.interfaces.append(value)
                    return
        raise GuestRefusal("restoration_dns_form_invalid")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect controls from the single supported form.

        Args:
            tag: Parsed HTML start tag.
            attrs: Original ordered attributes.
        """
        opaque = _RAW_TEXT | {"template"}
        if self.inert:
            if self.inert[-1] == "template" and tag in opaque:
                self.inert.append(tag)
            return
        if tag in opaque:
            if self.target:
                raise GuestRefusal("restoration_dns_form_invalid")
            self.inert.append(tag)
            return
        if tag == "plaintext":
            raise GuestRefusal("restoration_dns_form_invalid")
        values = dict(attrs)
        relevant = self.target or tag == "form" or (tag in _FORM_CONTROLS and "form" in values)
        if relevant and len(values) != len(attrs):
            raise GuestRefusal("restoration_dns_form_invalid")
        for attr, identifier in attrs:
            if attr == "id" and identifier:
                self.ids[identifier] += 1
        if tag == "fieldset":
            self.fieldsets.append("disabled" in values)
        if tag == "datalist":
            self.datalist_depth += 1
        if tag in _FORM_CONTROLS and (owner := values.get("form")):
            self.external_owners.add(owner)
        if tag == "form":
            target = values.get("action") == _DNS_ACTION
            if self.form_open or (target and (self.datalist_depth or any(self.fieldsets))):
                raise GuestRefusal("restoration_dns_form_invalid")
            self.form_open = True
            if target:
                if self.matches or (values.get("method") or "").lower() != "post":
                    raise GuestRefusal("restoration_dns_form_invalid")
                self.matches += 1
                self.target = True
                self.target_id = values.get("id") or ""
            return
        if not self.target:
            return
        if self.textarea is not None or (self.select_open and tag != "option"):
            raise GuestRefusal("restoration_dns_form_invalid")
        if tag == "option" and self.select_open:
            value = values.get("value") or ""
            if self.option_open or value not in _QUERY_OPTIONS or value in self.options or "disabled" in values:
                raise GuestRefusal("restoration_dns_form_invalid")
            self.options.add(value)
            self.option_open = True
            if "selected" in values:
                self.selected.append(value)
        if tag not in _FORM_CONTROLS:
            return
        name = values.get("name") or ""
        if ({"form", "disabled", "dirname"} & values.keys()
                or any(self.fieldsets) or self.datalist_depth):
            raise GuestRefusal("restoration_dns_form_invalid")
        if tag == "input":
            self._input(name, values)
        elif tag == "textarea" and name in _TEXTAREAS:
            self.textarea = name
            self.text_parts = []
        elif tag == "select" and name == _QUERY_MODE and "multiple" not in values and name not in self.values:
            self.select_open = True
        elif not ((tag == "button" and not name and values.get("type") == "button") or (tag == "fieldset" and not name)):
            raise GuestRefusal("restoration_dns_form_invalid")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Treat void inputs normally and refuse ambiguous form syntax.

        Args:
            tag: Parsed self-closing tag.
            attrs: Original ordered attributes.
        """
        if (self.target or tag == "form") and tag not in {"input", "br", "hr", "img", "wbr"}:
            raise GuestRefusal("restoration_dns_form_invalid")
        self.handle_starttag(tag, attrs)

    def handle_data(self, data: str) -> None:
        """Collect textarea text.

        Args:
            data: Decoded text from the page.
        """
        if self.textarea is not None:
            self.text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        """Close supported controls and the enclosing form.

        Args:
            tag: Parsed HTML end tag.
        """
        if self.inert:
            if tag == self.inert[-1]:
                self.inert.pop()
            return
        if self.textarea is not None:
            if tag != "textarea":
                raise GuestRefusal("restoration_dns_form_invalid")
            raw = "".join(self.text_parts).replace("\r\n", "\n").replace("\r", "\n")
            value = unescape(raw).removeprefix("\n")
            if len(value) > 16_384:
                raise GuestRefusal("restoration_dns_form_invalid")
            self._put(self.textarea, value)
            self.textarea = None
        elif self.select_open:
            if tag == "option" and self.option_open:
                self.option_open = False
            elif tag == "select" and not self.option_open and self.options == _QUERY_OPTIONS and len(self.selected) == 1:
                self._put(_QUERY_MODE, self.selected[0])
                self.select_open = False
            else:
                raise GuestRefusal("restoration_dns_form_invalid")
        elif tag == "form":
            if self.target and (self.datalist_depth or self.fieldsets):
                raise GuestRefusal("restoration_dns_form_invalid")
            self.target = False
            self.form_open = False
        elif tag == "fieldset" and self.fieldsets:
            self.fieldsets.pop()
        elif tag == "datalist" and self.datalist_depth:
            self.datalist_depth -= 1

    def projection(self) -> dict[str, Any]:
        """Return the supported desired settings with private controls omitted."""
        if (self.matches != 1 or self.target or not self.csrf or self.values.keys() != _REQUIRED_DNS
                or (self.target_id and (self.ids[self.target_id] != 1 or self.target_id in self.external_owners))):
            raise GuestRefusal("restoration_dns_form_invalid")
        return {**self.values, "listen_interfaces": self.interfaces}


def _review(client: UIClient) -> dict[str, Any]:
    """Project the exact clean default review without its private token.

    Args:
        client: Admitted normal-UI client.
    """
    value = client.read_json(_REVIEW_PATH)
    if (value.keys() != REVIEW_KEYS
            or value["active_task"] is not None or value["initial_apply_required"] is not False
            or value["plan_error"] != "" or value["units"] != [] or value["requested_units"] != []
            or any(type(value[key]) is not int or value[key] != 0 for key in ("pending_count", "execution_count"))
            or not isinstance(value["plan_token"], str)):
        raise GuestRefusal("restoration_review_not_clean")
    client.private_markers.add(value["plan_token"])
    return {key: item for key, item in value.items() if key != "plan_token"}


def _interface(client: UIClient, interface: str, mac: str) -> dict[str, Any]:
    """Capture original desired fields and their browser projection separately.

    Args:
        client: Admitted normal-UI client.
        interface: Original physical interface name.
        mac: Original canonical MAC.
    """
    row, _ = selected_interface(client, interface, mac)
    if (not _ROW_KEYS <= row.keys() or type(row["id"]) is not int or not 0 < row["id"] <= 2**63 - 1
            or type(row["mtu"]) is not int or not 576 <= row["mtu"] <= 9000
            or row["role"] not in ("management", "access", "route", "unused")
            or row["mode"] not in ("access", "trunk", "unused") or row["ipv4_method"] not in ("static", "dhcp")
            or any(type(row[key]) is not bool for key in (
                "admin_up", "ipv6_enabled", "check_duplicate_ip_addresses", "access_management_ui_enabled",
            ))):
        raise GuestRefusal("restoration_interface_invalid")
    for key, (version, cidr) in _NULLABLE.items():
        value = row[key]
        if value is None or value == "":
            continue
        if not isinstance(value, str) or len(value) > 80 or "%" in value:
            raise GuestRefusal("restoration_interface_invalid")
        address = ipaddress.ip_interface(value) if cidr else ipaddress.ip_address(value)
        if address.version != version:
            raise GuestRefusal("restoration_interface_invalid")
    return {"original_row": {key: row[key] for key in _ROW_KEYS}, "browser_fields": interface_fields(row)}


def _observe(client: UIClient, interface: str, mac: str) -> dict[str, Any]:
    """Read the default review, selected interface and current DNS settings once.

    Args:
        client: Admitted normal-UI client.
        interface: Original physical interface name.
        mac: Original canonical MAC.
    """
    review = _review(client)
    physical = _interface(client, interface, mac)
    status, _, body = client.request(_DNS_PATH)
    if status != 200:
        raise GuestRefusal("restoration_dns_unavailable")
    parser = _DNSSettingsForm()
    parser.feed(body.decode("utf-8", "strict"))
    parser.close()
    dns = parser.projection()
    client.private_markers.add(parser.csrf)
    result = {"review": review, **physical, "dns_settings": dns}
    assert_public_review(result, client.private_markers)
    return result


def capture_restoration_baseline(
    client: UIClient,
    interface: str,
    mac: str,
    checkpoint: Callable[[dict[str, Any]], object],
) -> dict[str, Any]:
    """Capture a stable desired-state projection for the original controller.

    The digest binds canonical parsed values. Repeated reads detect observed
    drift. The caller owns checkpoint durability, resource admission and any
    subsequent restoration decision.

    Args:
        client: Separately admitted pinned-origin normal-UI client.
        interface: Independently observed physical interface name.
        mac: Independently observed original MAC in canonical notation.
        checkpoint: Synchronous publisher receiving an independent copy and returning None.
    """
    if (not isinstance(interface, str) or not _INTERFACE.fullmatch(interface)
            or not isinstance(mac, str) or not _MAC.fullmatch(mac)):
        raise GuestRefusal("restoration_interface_invalid")
    try:
        original = _observe(client, interface, mac)
        if _observe(client, interface, mac) != original:
            raise GuestRefusal("restoration_baseline_drift")
        data = {
            **original, "test_only": True, "consistency_only": True,
            "native_acceptance": False, "formal_acceptance": False,
            "projection_sha256": {
                key: hashlib.sha256(public_bytes(value)).hexdigest() for key, value in original.items()
            },
        }
        assert_public_review(data, client.private_markers)
        public_bytes(data)
    except Exception:  # noqa: BLE001 - transport and parser diagnostics may contain private UI data.
        raise GuestRefusal("restoration_baseline_unavailable") from None
    try:
        if checkpoint(copy.deepcopy(data)) is not None:
            raise GuestRefusal("restoration_checkpoint_invalid")
        if _observe(client, interface, mac) != original:
            raise GuestRefusal("restoration_baseline_drift")
        assert_public_review(data, client.private_markers)
    except Exception:  # noqa: BLE001 - a publisher exception may follow a partial or complete write.
        raise GuestRefusal("restoration_checkpoint_uncertain") from None
    return copy.deepcopy(data)
