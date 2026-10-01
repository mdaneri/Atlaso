"""Bounded clock-source acceptance actions executed only in an owned lifecycle guest."""

import hashlib
import http.cookiejar
import importlib.metadata
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

BASE = ""
HOST = ""
USERNAME = "admin"
TLS_CONTEXT = None
PYTHON = "/opt/atlaso/.venv/bin/python"
MODES = {"ntp_client", "ntp_server", "vmware_tools"}
WEB_ACTIONS = {
    "prepare_server_interface",
    "apply",
    "status",
    "wait_status",
    "conflict_enable",
    "server_probe",
}
WAIT_STATUS_TLS_TIMEOUT_SECONDS = 120
WAIT_STATUS_LOGIN_READY_TIMEOUT_SECONDS = 60


class SafeFailure(Exception):
    def __init__(self, stage, reason):
        self.stage, self.reason = stage, reason


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.fields, self.interfaces = [], []
        self.in_form, self.form_action = False, "/ntp/settings"
        self.text_name, self.text_parts = None, []
        self.select = None
        self.option = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "form" and a.get("id") == "ntp-settings-form":
            self.in_form, self.form_action = True, a.get("action") or self.form_action
        if tag == "button" and a.get("data-tag-option"):
            self.interfaces.append(a["data-tag-option"])
        if tag == "textarea" and self.in_form:
            self.text_name, self.text_parts = a.get("name"), []
        if tag == "select":
            form_owned = self.in_form or a.get("form") == "ntp-settings-form"
            self.select = {
                "name": a.get("name", ""),
                "successful": form_owned and bool(a.get("name")) and "disabled" not in a,
                "multiple": "multiple" in a,
                "options": [],
            }
            return
        if tag == "option" and self.select is not None:
            self.option = {
                "value": a.get("value"),
                "selected": "selected" in a,
                "disabled": "disabled" in a,
                "text": [],
            }
            return
        if tag != "input" or not a.get("name") or "disabled" in a:
            return
        if not self.in_form and a.get("form") != "ntp-settings-form":
            return
        if (
            a.get("type", "text").lower() in {"checkbox", "radio"}
            and "checked" not in a
        ):
            return
        self.fields.append((a["name"], a.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "option" and self.option is not None and self.select is not None:
            option = self.option
            value = option["value"]
            if value is None:
                value = " ".join("".join(option["text"]).split())
            self.select["options"].append(
                {"value": value, "selected": option["selected"], "disabled": option["disabled"]}
            )
            self.option = None
        if tag == "select" and self.select is not None:
            select = self.select
            self.select = None
            if not select["successful"]:
                return
            options = select["options"]
            selected = [option for option in options if option["selected"]]
            if not select["multiple"] and not selected:
                selected = next((option for option in options if not option["disabled"]), None)
                selected = [] if selected is None else [selected]
            self.fields.extend(
                (select["name"], option["value"])
                for option in selected
                if not option["disabled"]
            )
        if tag == "textarea" and self.text_name:
            self.fields.append((self.text_name, "".join(self.text_parts)))
            self.text_name, self.text_parts = None, []
        if tag == "form" and self.in_form:
            self.in_form = False

    def handle_data(self, data):
        if self.text_name:
            self.text_parts.append(data)
        if self.option is not None:
            self.option["text"].append(data)


class TokenParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.token = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "input" and a.get("name") == "csrf":
            self.token = a.get("value") or ""


class InterfaceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = []

    def handle_starttag(self, tag, attrs):
        if tag != "div":
            return
        a = dict(attrs)
        if a.get("id") != "physical-interfaces-table" or not a.get("data-interfaces"):
            return
        try:
            self.rows = json.loads(a["data-interfaces"])
        except ValueError, TypeError:
            self.rows = []


def reply(ok, **kwargs):
    print(json.dumps({"ok": ok, **kwargs}, separators=(",", ":")), flush=True)


def request(opener, path, *, data=None, headers=None, timeout=20, follow=True):
    origin = BASE.split("/ui/management", 1)[0]
    target = (
        origin + path
        if path.startswith("/ui/management/")
        else BASE.rstrip("/") + "/" + path.lstrip("/")
    )
    req = Request(target, data=data, headers=headers or {})
    # Network Apply may briefly reload the management listener. Retry only
    # read-only observations; a submitted mutation is never blindly repeated.
    for attempt in range(3 if data is None else 1):
        try:
            response = opener.open(req, timeout=timeout)
            break
        except HTTPError as exc:
            if data is None and exc.code in {502, 503, 504} and attempt < 2:
                time.sleep(2)
                continue
            raise SafeFailure(
                "http", "HTTP request rejected (status %d)." % exc.code
            ) from None
        except URLError, TimeoutError, OSError:
            if data is None and attempt < 2:
                time.sleep(2)
                continue
            raise SafeFailure(
                "http", "Appliance UI request failed or timed out."
            ) from None
    with response:
        body = response.read(2_000_000)
        return response.status, response.url, response.headers, body


def initialize_tls_context(host, *, timeout_seconds=15):
    """Trust the guest's served public leaf after bounded listener recovery."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeFailure(
                "https-listener", "The appliance HTTPS listener did not recover before the bounded deadline."
            )
        try:
            leaf = ssl.get_server_certificate((host, 443), timeout=min(5, remaining))
            context = ssl.create_default_context(cadata=leaf)
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            context.check_hostname = False
            return context
        except (OSError, ssl.SSLError, ValueError):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SafeFailure(
                    "https-listener", "The appliance HTTPS listener did not recover before the bounded deadline."
                ) from None
            time.sleep(min(1, remaining))


def wait_for_login_form(opener, *, timeout):
    """Wait for a readable login form using safe, repeatable GET requests only."""
    deadline = time.monotonic() + timeout
    target = BASE.rstrip("/") + "/login"
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeFailure(
                "login-readiness", "The login page did not become ready before the bounded deadline."
            )
        req = Request(target)
        try:
            with opener.open(req, timeout=min(5, remaining)) as response:
                if response.status != 200:
                    raise SafeFailure(
                        "login-readiness", "The login page returned an unexpected response."
                    )
                body = response.read(2_000_000)
        except HTTPError as exc:
            if exc.code not in {502, 503, 504}:
                raise SafeFailure(
                    "login-readiness", "The login page returned a non-retryable HTTP response."
                ) from None
            body = None
        except (URLError, TimeoutError, OSError):
            body = None
        if body is not None:
            parser = TokenParser()
            parser.feed(body.decode("utf-8", "replace"))
            if not parser.token:
                raise SafeFailure(
                    "login-readiness", "The login page did not expose its CSRF field."
                )
            return parser.token
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeFailure(
                "login-readiness", "The login page did not become ready before the bounded deadline."
            )
        time.sleep(min(1, remaining))


def login(password, *, readiness_timeout=0):
    opener = build_opener(
        HTTPCookieProcessor(http.cookiejar.CookieJar()),
        __import__("urllib.request", fromlist=["HTTPSHandler"]).HTTPSHandler(
            context=TLS_CONTEXT
        ),
    )
    if readiness_timeout:
        token = wait_for_login_form(opener, timeout=readiness_timeout)
    else:
        _, _, _, body = request(opener, "/login")
        parser = TokenParser()
        parser.feed(body.decode("utf-8", "replace"))
        token = parser.token
        if not token:
            raise SafeFailure("login", "Login form did not expose its CSRF field.")
    fields = urlencode(
        {"username": USERNAME, "password": password, "csrf": token}
    ).encode()
    status, _, _, _ = request(
        opener,
        "/login",
        data=fields,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status not in (200, 303):
        raise SafeFailure("login", "Administrator login did not complete.")
    return opener


def ntp_page(opener):
    _, _, _, body = request(opener, "/ntp")
    parser = FormParser()
    parser.feed(body.decode("utf-8", "replace"))
    values = {}
    for key, value in parser.fields:
        values.setdefault(key, []).append(value)
    token = values.get("csrf", [""])[0]
    if not token:
        raise SafeFailure(
            "settings", "NTP settings form did not expose its CSRF field."
        )
    return parser, values, token


def post_form(opener, path, fields, *, accept_json=False):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if accept_json:
        headers.update({"Accept": "application/json", "X-Atlaso-Autosave": "1"})
    return request(
        opener, path, data=urlencode(fields, doseq=True).encode(), headers=headers
    )


def status(opener):
    _, _, _, body = request(opener, "/ntp/source-health")
    payload = json.loads(body)
    raw = payload.get("status") if isinstance(payload, dict) else {}
    if not isinstance(raw, dict):
        raw = {}
    sync = (
        raw.get("synchronization")
        if isinstance(raw.get("synchronization"), dict)
        else {}
    )
    controller = (
        raw.get("selected_controller")
        if isinstance(raw.get("selected_controller"), dict)
        else {}
    )
    conflicts = (
        raw.get("daemon_conflicts")
        if isinstance(raw.get("daemon_conflicts"), dict)
        else {}
    )
    guard = (
        raw.get("client_packet_guard")
        if isinstance(raw.get("client_packet_guard"), dict)
        else {}
    )
    compact_conflicts = {
        str(name): {
            key: value.get(key) for key in ("active", "enabled") if key in value
        }
        for name, value in conflicts.items()
        if isinstance(value, dict)
    }
    return {
        "mode": raw.get("mode"),
        "healthy": sync.get("healthy"),
        "sync_state": sync.get("state"),
        "controller": {
            key: controller.get(key) for key in ("name", "active", "enabled")
        },
        "conflicts": compact_conflicts,
        "client_packet_guard": guard.get("active"),
    }


def assert_clock(clock, expected_mode=None, expected_health="any"):
    if expected_mode and clock.get("mode") != expected_mode:
        raise SafeFailure(
            "clock-assertion", "Observed clock mode did not match the requested mode."
        )
    selected = "vmware_tools" if expected_mode == "vmware_tools" else "ntpd"
    controller = clock.get("controller") or {}
    if expected_mode and (
        controller.get("name") != selected
        or controller.get("active") is not True
        or controller.get("enabled") is not True
    ):
        raise SafeFailure(
            "clock-assertion",
            "The selected clock controller is not active and enabled.",
        )
    for name, state in (clock.get("conflicts") or {}).items():
        if name != selected and (
            state.get("active") is True or state.get("enabled") is True
        ):
            raise SafeFailure(
                "clock-assertion",
                "A competing clock controller remains active or enabled.",
            )
    if expected_mode == "ntp_client" and clock.get("client_packet_guard") is not True:
        raise SafeFailure(
            "clock-assertion", "Client-only NTP ingress guard is not verified active."
        )
    health = clock.get("healthy")
    expected_value = {"healthy": True, "unhealthy": False, "unknown": None}.get(
        expected_health, "any"
    )
    if expected_value != "any" and health is not expected_value:
        raise SafeFailure(
            "clock-assertion", "Clock health did not match the requested expectation."
        )


def wait_status(opener, mode, health="healthy", timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = status(opener)
        try:
            assert_clock(observed, mode, health)
        except SafeFailure:
            time.sleep(2)
        else:
            return observed
    raise SafeFailure(
        "clock-assertion", "Clock health did not recover before the bounded deadline."
    )


def apply_unit(opener, unit_id, csrf):
    _, _, _, review_body = request(opener, "/appliance-apply/review")
    review = json.loads(review_body)
    unit = next(
        (item for item in review.get("units", []) if item.get("id") == unit_id), None
    )
    # Review omits unchanged units. The normal submit endpoint validates all
    # explicitly selected units and supports reapplying ntpd after runtime drift.
    if not unit and unit_id != "ntpd":
        raise SafeFailure(
            "apply-review", "Global Appliance Apply did not expose the selected unit."
        )
    if unit and not unit.get("valid"):
        raise SafeFailure(
            "apply-review",
            "Global Appliance Apply reports invalid desired state for the selected unit.",
        )
    if review.get("active_task"):
        raise SafeFailure(
            "apply-review", "Another global Appliance Apply task is already active."
        )
    selected = [unit_id]
    if unit_id in {"network", "ntpd"}:
        firewall = next(
            (item for item in review.get("units", []) if item.get("id") == "firewall"),
            None,
        )
        if firewall and firewall.get("valid"):
            selected.append("firewall")
    apply_fields = urlencode(
        [("csrf", csrf), *[("selected_units", item) for item in selected]]
    ).encode()
    _, location, _, _ = request(
        opener,
        "/appliance-apply",
        data=apply_fields,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    match = re.search(r"job_id=([A-Za-z0-9_-]+)", location)
    if not match:
        raise SafeFailure(
            "apply-submit", "Global Appliance Apply did not return a task identifier."
        )
    job_id = match.group(1)
    deadline = time.monotonic() + 240
    task_status = "unknown"
    while time.monotonic() < deadline:
        _, _, _, task_body = request(opener, "/tasks/%s/status" % job_id)
        task = json.loads(task_body).get("task", {})
        task_status = task.get("status", "unknown")
        if task_status in {"succeeded", "failed", "cancelled", "interrupted"}:
            break
        time.sleep(2)
    if task_status != "succeeded":
        raise SafeFailure(
            "apply", "Global Appliance Apply ended in state %s." % task_status
        )
    return job_id


def apply_mode(opener, mode, server_interface=None, expected_health="any"):
    if mode not in MODES:
        raise SafeFailure("arguments", "Unsupported mode.")
    parser, values, csrf = ntp_page(opener)
    fields = [(key, value) for key, vals in values.items() for value in vals]
    fields = [
        (key, value)
        for key, value in fields
        if key not in {"enabled", "time_source", "nts_server_enabled", "csrf"}
    ]
    fields.extend(
        [
            ("csrf", csrf),
            (
                "time_source",
                values.get("time_source", ["ntp_client"])[0]
                if mode == "ntp_server"
                else mode,
            ),
        ]
    )
    if mode == "ntp_server":
        fields.append(("enabled", "on"))
        if server_interface and server_interface not in parser.interfaces:
            raise SafeFailure(
                "settings", "The requested NTP interface is not currently eligible."
            )
        if server_interface:
            fields = [
                (key, value) for key, value in fields if key != "listen_interfaces"
            ]
            fields.append(("listen_interfaces", server_interface))
        if not values.get("listen_interfaces"):
            if not parser.interfaces:
                raise SafeFailure(
                    "settings",
                    "No eligible non-management interface is available for server mode.",
                )
            if not server_interface:
                fields.append(("listen_interfaces", parser.interfaces[0]))
    # Keep at least one safe upstream when an appliance was restored without any.
    sources = []
    try:
        candidate = json.loads(values.get("upstream_sources_json", [""])[0])
        if isinstance(candidate, list):
            sources = candidate
    except ValueError, TypeError:
        sources = []
    if not any(
        isinstance(row, dict) and row.get("enabled") and row.get("source")
        for row in sources
    ):
        sources = [
            {
                "id": "acceptance-upstream",
                "source": "time.cloudflare.com",
                "enabled": True,
                "use_nts": False,
                "description": "Acceptance upstream",
            }
        ]
        fields = [
            (key, value)
            for key, value in fields
            if key not in {"upstream_servers", "upstream_sources_json"}
        ]
        fields.extend(
            [
                ("upstream_servers", "time.cloudflare.com"),
                ("upstream_sources_json", json.dumps(sources, separators=(",", ":"))),
            ]
        )
    # Keep the managed NTS server off in all acceptance modes.
    fields.append(("listen_interfaces_present", "1"))
    fields.append(("nts_server_enabled", ""))
    _, _, _, saved_body = post_form(
        opener, parser.form_action, fields, accept_json=True
    )
    try:
        saved = json.loads(saved_body)
    except ValueError:
        raise SafeFailure(
            "settings",
            "Desired NTP settings did not return the expected autosave status.",
        ) from None
    if saved.get("valid") is False:
        errors = saved.get("validation_errors") or []
        # Validation details are bounded and never include page content or credentials.
        raise SafeFailure(
            "validation",
            "Desired NTP settings are invalid (%d validation issue(s))." % len(errors),
        )
    apply_unit(opener, "ntpd", csrf)
    observed = wait_status(opener, mode, expected_health)
    _, after_values, _ = ntp_page(opener)
    remembered = after_values.get("time_source", [None])[0]
    if (
        mode == "ntp_server"
        and remembered != values.get("time_source", ["ntp_client"])[0]
    ):
        raise SafeFailure(
            "settings", "Server mode changed the remembered client clock source."
        )
    return {
        "applied_mode": mode,
        "task_status": "succeeded",
        "clock": observed,
        "remembered_time_source": remembered,
    }


def prepare_server_interface(opener, interface_name, fixture_cidr):
    if not interface_name:
        raise SafeFailure(
            "network-fixture", "An explicit test interface name is required."
        )
    try:
        network = ipaddress.ip_interface(fixture_cidr)
    except ValueError:
        raise SafeFailure(
            "network-fixture", "The fixture address must be a valid IPv4 CIDR."
        ) from None
    if (
        network.version != 4
        or not network.ip.is_private
        or network.ip.is_loopback
        or network.ip.is_link_local
    ):
        raise SafeFailure(
            "network-fixture", "The fixture must use a private, routable IPv4 CIDR."
        )
    _, _, _, body = request(opener, "/physical-interfaces")
    inventory = InterfaceParser()
    inventory.feed(body.decode("utf-8", "replace"))
    rows = inventory.rows
    target = next((row for row in rows if row.get("name") == interface_name), None)
    if not target:
        raise SafeFailure(
            "network-fixture",
            "The selected physical interface is not in current appliance inventory.",
        )
    if target.get("role") == "management" or target.get("access_management_ui_enabled"):
        raise SafeFailure(
            "network-fixture",
            "The selected physical interface carries management access.",
        )
    if target.get("role") != "unused" or any(
        target.get(key) for key in ("ip_cidr", "gateway", "ipv6_cidr", "ipv6_gateway")
    ):
        raise SafeFailure(
            "network-fixture",
            "Fixture setup only accepts a currently unused, unaddressed physical interface.",
        )
    try:
        management_host_ip = ipaddress.ip_address(HOST)
        target_addresses = [target.get("ip_cidr"), target.get("host_ip_cidr")]
        if any(
            ipaddress.ip_interface(value).ip == management_host_ip
            for value in target_addresses
            if value
        ):
            raise SafeFailure(
                "network-fixture",
                "The selected physical interface owns the current management address.",
            )
    except ValueError:
        pass
    management_rows = [row for row in rows if row.get("role") == "management"]
    for row in management_rows:
        for value in (
            row.get("ip_cidr"),
            row.get("host_ip_cidr"),
            row.get("ipv6_cidr"),
        ):
            if not value:
                continue
            try:
                current = ipaddress.ip_interface(value)
            except ValueError:
                continue
            if current.version == 4 and current.network.overlaps(network.network):
                raise SafeFailure(
                    "network-fixture",
                    "The fixture subnet overlaps a management address range.",
                )
    for row in rows:
        if row.get("id") == target.get("id"):
            continue
        for value in (row.get("ip_cidr"), row.get("host_ip_cidr")):
            if not value:
                continue
            try:
                current = ipaddress.ip_interface(value)
            except ValueError:
                continue
            if current.version == 4 and current.network.overlaps(network.network):
                raise SafeFailure(
                    "network-fixture",
                    "The fixture subnet overlaps an existing physical-interface subnet.",
                )
    token_parser = TokenParser()
    token_parser.feed(body.decode("utf-8", "replace"))
    if not token_parser.token:
        raise SafeFailure(
            "network-fixture", "Physical-interface page did not expose its CSRF field."
        )
    form = [
        ("csrf", token_parser.token),
        ("role", "access"),
        ("mode", "access"),
        ("ipv4_method", "static"),
        ("ip_cidr", str(network)),
        ("gateway", ""),
        ("ipv6_enabled", ""),
        ("ipv6_cidr", ""),
        ("ipv6_gateway", ""),
        ("mtu", str(target.get("mtu") or 1500)),
        ("admin_state", "up"),
        ("access_management_ui_enabled", ""),
    ]
    request(
        opener,
        "/physical-interfaces/%s/edit" % target["id"],
        data=urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    apply_unit(opener, "network", token_parser.token)
    _, _, _, refreshed = request(opener, "/physical-interfaces")
    after = InterfaceParser()
    after.feed(refreshed.decode("utf-8", "replace"))
    resulting = next(
        (row for row in after.rows if row.get("id") == target.get("id")), None
    )
    if (
        not resulting
        or resulting.get("role") != "access"
        or resulting.get("mode") != "access"
        or resulting.get("admin_state") != "up"
        or resulting.get("ip_cidr") != str(network)
    ):
        raise SafeFailure(
            "network-fixture",
            "Network Apply did not persist the requested non-management interface fixture.",
        )
    protected_fields = (
        "role",
        "mode",
        "admin_state",
        "ipv4_method",
        "ip_cidr",
        "gateway",
        "ipv6_enabled",
        "ipv6_cidr",
        "ipv6_gateway",
    )
    if any(
        row.get(key) != old.get(key)
        for old in management_rows
        for row in after.rows
        if row.get("id") == old.get("id")
        for key in protected_fields
    ):
        raise SafeFailure(
            "network-fixture",
            "Management-interface desired addressing changed during fixture setup.",
        )
    return {
        "network_fixture": "applied",
        "interface": interface_name,
        "cidr": str(network),
        "management_preserved": True,
    }


def server_udp_probe(opener, address_text):
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError, TypeError:
        raise SafeFailure(
            "server-probe", "The server address must be an IPv4 literal."
        ) from None
    if address.version != 4:
        raise SafeFailure("server-probe", "Only IPv4 NTP server probes are supported.")
    inventory = subprocess.run(
        ["ip", "-json", "address", "show"], capture_output=True, timeout=5, check=False
    )
    if inventory.returncode:
        raise SafeFailure(
            "server-probe", "Guest interface addresses could not be verified."
        )
    try:
        rows = json.loads(inventory.stdout)
        assigned = any(
            info.get("family") == "inet" and info.get("local") == str(address)
            for row in rows
            if isinstance(row, dict)
            for info in row.get("addr_info", [])
            if isinstance(info, dict)
        )
    except ValueError, TypeError, AttributeError:
        assigned = False
    if not assigned:
        raise SafeFailure(
            "server-probe",
            "The requested NTP server address is not assigned to a guest interface.",
        )
    request = bytearray(48)
    request[0] = 0x23  # NTPv4 client request.
    ntp_now = time.time()
    ntp_seconds = int(ntp_now) + 2208988800
    ntp_fraction = int((ntp_now % 1) * (1 << 32))
    struct.pack_into("!II", request, 40, ntp_seconds, ntp_fraction)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(4)
            client.bind((str(address), 0))
            client.sendto(request, (str(address), 123))
            reply, peer = client.recvfrom(512)
    except OSError, TimeoutError:
        raise SafeFailure(
            "server-probe", "No NTP server response arrived before the bounded timeout."
        ) from None
    if len(reply) < 48 or peer != (str(address), 123):
        raise SafeFailure(
            "server-probe",
            "The NTP response was incomplete or came from an unexpected endpoint.",
        )
    leap, version, mode = reply[0] >> 6, (reply[0] >> 3) & 7, reply[0] & 7
    stratum = reply[1]
    if mode != 4 or version not in {3, 4} or not 1 <= stratum <= 15 or leap == 3:
        raise SafeFailure(
            "server-probe",
            "The NTP response does not report a synchronized server at a valid stratum.",
        )
    if reply[24:32] != request[40:48] or not any(reply[40:48]):
        raise SafeFailure(
            "server-probe",
            "The NTP response timestamps do not match the probe request.",
        )
    clock = status(opener)
    assert_clock(clock, "ntp_server", "healthy")
    return {
        "probe_received": True,
        "response_mode": mode,
        "response_version": version,
        "stratum": stratum,
        "leap_alarm": leap == 3,
        "clock_healthy": clock.get("healthy"),
        "sync_state": clock.get("sync_state"),
    }


def run_action(payload):
    action = payload.get("action")
    if action == "deployment_identity":
        with open("/opt/atlaso/bin/atlaso-helper", "rb") as stream:
            helper_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        return {"helper_sha256": helper_hash, "installed_version": importlib.metadata.version("atlaso")}
    if action == "fixture_identity":
        interface_name = payload.get("interface_name")
        expected = ipaddress.IPv4Interface(payload["fixture_cidr"])
        rows = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr", "show"], timeout=5))
        link = next((row for row in rows if row.get("ifname") == interface_name), {})
        if not any(info.get("local") == str(expected.ip) and info.get("prefixlen") == expected.network.prefixlen for info in link.get("addr_info", [])):
            raise SafeFailure("identity", "The owned fixture address is not assigned to its selected guest interface.")
        mac = link.get("address", "")
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            raise SafeFailure("identity", "The owned fixture hardware identity is unavailable.")
        return {"fixture_address": str(expected.ip), "fixture_interface": interface_name, "fixture_mac": mac}
    if action == "install_probe_tools":
        result = subprocess.run(
            ["tdnf", "install", "-y", "tcpdump"],
            capture_output=True,
            timeout=90,
            check=False,
        )
        if result.returncode:
            raise SafeFailure(
                "client-probe", "Photon packet-capture test tool installation failed."
            )
        return {"packet_capture_tool": "ready"}
    if action == "boot_id":
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as stream:
            return {"boot_id": stream.read().strip()}
    if action == "client_capture":
        peer = str(ipaddress.IPv4Address(payload["peer_ip"]))
        peer_port = int(payload["peer_port"])
        if not 1 <= peer_port <= 65535:
            raise SafeFailure("client-probe", "Invalid probe source port.")
        packet_filter = (
            "dst host %s and udp dst port 123 and src host %s and udp src port %d and udp[8] & 7 = 3"
            % (HOST, peer, peer_port)
        )
        capture = subprocess.Popen(
            [
                "timeout",
                "8",
                "tcpdump",
                "-nn",
                "-l",
                "-Q",
                "in",
                "-i",
                "any",
                "-c",
                "1",
                packet_filter,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.5)
            if capture.poll() is not None:
                raise SafeFailure("client-probe", "Packet capture did not start.")
            reply(True, capture_ready=True)
            output, _ = capture.communicate(timeout=12)
            if capture.returncode != 0 or b"IP " not in output:
                raise SafeFailure(
                    "client-probe",
                    "The exact host probe was not observed at guest ingress.",
                )
            return {"probe_delivered_to_guest": True}
        finally:
            if capture.poll() is None:
                capture.kill()
                capture.wait(timeout=5)
    if action == "reboot":
        try:
            with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as stream:
                old_boot_id = stream.read().strip()
        except OSError:
            raise SafeFailure(
                "reboot", "The guest boot identity could not be read before reboot."
            ) from None
        result = subprocess.run(
            ["systemd-run", "--on-active=2s", "/usr/bin/systemctl", "reboot"],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if result.returncode:
            raise SafeFailure(
                "reboot", "The bounded system reboot request was rejected."
            )
        return {"reboot_scheduled": True, "boot_id": old_boot_id}
    if action == "tools_restart":
        result = subprocess.run(
            ["systemctl", "restart", "vmtoolsd.service"],
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode:
            raise SafeFailure("vmtools", "The VMware Tools service restart failed.")
        return {"vmtools_restart": "succeeded"}
    if action == "conflict_enable":
        result = subprocess.run(
            ["vmware-toolbox-cmd", "timesync", "enable"],
            capture_output=True,
            timeout=20,
            check=False,
        )
        if result.returncode:
            raise SafeFailure(
                "conflict",
                "VMware Tools periodic time synchronization could not be enabled.",
            )
        opener = login(payload["password"])
        clock = status(opener)
        mode = clock.get("mode")
        vmtools = (clock.get("conflicts") or {}).get("vmware_tools", {})
        if (
            mode not in {"ntp_client", "ntp_server"}
            or vmtools.get("active") is not True
            or vmtools.get("enabled") is not True
            or clock.get("healthy") is not False
        ):
            raise SafeFailure(
                "conflict",
                "The competing-controller diagnostic was not observed as unhealthy.",
            )
        return {"conflict_enabled": True, "clock": clock}
    if action == "ntpwait":
        binary = next(
            (
                path
                for path in ("/usr/sbin/ntpwait", "/usr/bin/ntpwait", "/sbin/ntpwait")
                if os.path.isfile(path)
            ),
            None,
        )
        if not binary:
            return {"ntpwait": "unavailable"}
        result = subprocess.run(
            [binary, "-v", "-n", "12", "-s", "2"],
            capture_output=True,
            timeout=32,
            check=False,
        )
        return {
            "ntpwait": "synchronized"
            if result.returncode == 0
            else "bounded_timeout_or_failure",
            "returncode": result.returncode,
        }
    if action == "wait_status":
        opener = login(
            payload["password"],
            readiness_timeout=WAIT_STATUS_LOGIN_READY_TIMEOUT_SECONDS,
        )
        return {
            "clock": wait_status(
                opener,
                payload["assert_mode"],
                payload.get("expected_health", "healthy"),
            )
        }
    if action == "status":
        opener = login(payload["password"])
        clock = status(opener)
        assert_clock(
            clock, payload.get("assert_mode"), payload.get("expected_health", "any")
        )
        return {"clock": clock}
    if action == "prepare_server_interface":
        opener = login(payload["password"])
        return prepare_server_interface(
            opener, payload.get("interface_name"), payload.get("fixture_cidr")
        )
    if action == "server_probe":
        opener = login(payload["password"])
        return server_udp_probe(opener, payload.get("server_address"))
    if action == "apply":
        opener = login(payload["password"])
        return apply_mode(
            opener,
            payload.get("mode"),
            payload.get("server_interface"),
            payload.get("expected_health", "any"),
        )
    raise SafeFailure("arguments", "Unsupported acceptance step.")


def main():
    global BASE, HOST, TLS_CONTEXT, USERNAME
    TLS_CONTEXT = None
    try:
        request_data = json.loads(sys.stdin.readline(65537))
        USERNAME = request_data.get("username", "admin")
        host_ip = ipaddress.IPv4Address(request_data["host"])
        HOST = str(host_ip)
        addresses = json.loads(
            subprocess.check_output(["ip", "-j", "-4", "addr", "show"], timeout=5)
        )
        if not any(
            address.get("local") == HOST
            for link in addresses
            for address in link.get("addr_info", [])
        ):
            raise SafeFailure(
                "identity",
                "The pinned management address is not assigned to this guest.",
            )
        BASE = "https://%s/ui/management" % HOST
        if request_data.get("action") in WEB_ACTIONS:
            # The certificate pin is obtained inside the independently pinned
            # SSH guest. Read-only boot and host actions do not depend on nginx.
            tls_timeout = (
                WAIT_STATUS_TLS_TIMEOUT_SECONDS
                if request_data.get("action") == "wait_status"
                else 15
            )
            TLS_CONTEXT = initialize_tls_context(
                HOST, timeout_seconds=tls_timeout
            )
        result = run_action(request_data)
        reply(True, **result)
    except SafeFailure as exc:
        reply(False, stage=exc.stage, reason=exc.reason)
    except Exception:  # noqa: BLE001 - the credential-bearing guest boundary emits only fixed safe errors.
        reply(
            False,
            stage="unexpected",
            reason="Guest acceptance action failed; exception details were suppressed.",
        )


if __name__ == "__main__":
    main()
