import importlib.machinery
import importlib.util
import json
import sqlite3
import subprocess
from types import SimpleNamespace
from pathlib import Path

import pytest
from sqlalchemy.exc import OperationalError as SQLAlchemyOperationalError

import labfoundry.app.appliance_console as appliance_console
from labfoundry.app.appliance_console import (
    CursesConsole,
    ConsoleOperationError,
    ServiceStatus,
    configure_firewall,
    management_urls,
    schedule_power,
    validate_dns_servers,
    validate_ipv6_management_values,
    validate_management_values,
)


HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "labfoundry-helper"


def load_helper_module():
    loader = importlib.machinery.SourceFileLoader("labfoundry_helper_console", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("labfoundry_helper_console", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_console_management_validation_limits_dhcp_and_static_values():
    assert validate_management_values("dhcp", "", "") == ("dhcp", "", "")
    assert validate_management_values("static", "192.168.49.1/24", "192.168.49.254") == (
        "static",
        "192.168.49.1/24",
        "192.168.49.254",
    )
    with pytest.raises(ConsoleOperationError, match="on-link"):
        validate_management_values("static", "192.168.49.1/24", "192.168.50.1")
    with pytest.raises(ConsoleOperationError, match="cannot include"):
        validate_management_values("dhcp", "192.168.49.1/24", "")


@pytest.mark.parametrize(
    ("reported", "expected"),
    [("x86_64", "amd64"), ("AMD64", "amd64"), ("aarch64", "arm64"), ("armv7l", "armv7"), ("riscv64", "riscv64"), ("", "unknown")],
)
def test_console_architecture_label_normalizes_common_platform_names(reported, expected):
    assert appliance_console._architecture_label(reported) == expected


def test_console_dns_validation_accepts_compact_lists():
    assert validate_dns_servers("1.1.1.1, 9.9.9.9") == ["1.1.1.1", "9.9.9.9"]
    with pytest.raises(ConsoleOperationError, match="DNS server"):
        validate_dns_servers("resolver.example.com")


def test_console_ipv6_management_validation_supports_independent_modes_and_gateways():
    assert validate_ipv6_management_values("disabled", "", "") == ("disabled", "", "")
    assert validate_ipv6_management_values("automatic", "", "") == ("automatic", "", "")
    assert validate_ipv6_management_values("static", "2001:db8:49::10/64", "2001:db8:49::1") == (
        "static",
        "2001:db8:49::10/64",
        "2001:db8:49::1",
    )
    assert validate_ipv6_management_values("static", "2001:db8:49::10/64", "fe80::1") == (
        "static",
        "2001:db8:49::10/64",
        "fe80::1",
    )
    with pytest.raises(ConsoleOperationError, match="cannot include"):
        validate_ipv6_management_values("automatic", "2001:db8:49::10/64", "")
    with pytest.raises(ConsoleOperationError, match="must use IPv6"):
        validate_ipv6_management_values("static", "192.168.49.10/24", "")
    with pytest.raises(ConsoleOperationError, match="must use IPv6"):
        validate_ipv6_management_values("static", "2001:db8:49::10/64", "192.168.49.1")
    with pytest.raises(ConsoleOperationError, match="link-local or on-link"):
        validate_ipv6_management_values("static", "2001:db8:49::10/64", "2001:db8:50::1")
    with pytest.raises(ConsoleOperationError, match="cannot equal"):
        validate_ipv6_management_values("static", "2001:db8:49::10/64", "2001:db8:49::10")


def test_console_management_urls_bracket_ipv6_and_ignore_link_local_addresses():
    assert management_urls("appliance.labfoundry.internal", "192.168.49.10/24", "2001:db8:49::10/64") == (
        "https://appliance.labfoundry.internal/",
        "https://192.168.49.10/",
        "https://[2001:db8:49::10]/",
    )
    assert management_urls("", "", "fe80::10/64") == ()
    assert management_urls(
        "appliance.labfoundry.internal",
        "192.168.49.10/24",
        "2001:db8:49::10/64",
        https_enabled=False,
    ) == (
        "http://appliance.labfoundry.internal/",
        "http://192.168.49.10/",
        "http://[2001:db8:49::10]/",
    )


def test_console_load_summary_uses_one_five_and_fifteen_minute_averages(monkeypatch):
    monkeypatch.setattr(appliance_console.os, "getloadavg", lambda: (0.125, 1.5, 12.345), raising=False)

    assert appliance_console._load_summary() == "1 min 0.12 | 5 min 1.50 | 15 min 12.35"


@pytest.mark.parametrize(
    ("values", "cpu_count", "expected"),
    [
        ((2.99, 0.0, 0.0), 4, "normal"),
        ((3.0, 0.0, 0.0), 4, "warning"),
        ((0.0, 3.99, 0.0), 4, "warning"),
        ((0.0, 0.0, 4.0), 4, "critical"),
        ((8.0, 0.0, 0.0), 8, "critical"),
    ],
)
def test_console_load_status_scales_warning_and_critical_thresholds_by_cpu_count(values, cpu_count, expected):
    summary, severity = appliance_console._load_status(values, cpu_count)

    assert summary.startswith("1 min ")
    assert severity == expected


def test_console_load_colors_use_header_safe_warning_and_critical_pairs():
    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(A_BOLD=0x100, color_pair=lambda value: value)

    assert console._load_attr("normal") == 1
    assert console._load_attr("warning") == 6 | 0x100
    assert console._load_attr("critical") == 7 | 0x100


def test_console_release_summary_drops_embedded_photon_metadata_lines():
    release = "VMware Photon OS 5.0\nPHOTON_BUILD_NUMBER=12345\n"

    assert appliance_console._first_display_line(release, "Linux") == "VMware Photon OS 5.0"


def test_console_uses_bounded_recovery_redraws_after_service_activity():
    assert CursesConsole._recovery_redraws(10.0) == [11.0, 13.0, 18.0]


def test_console_refresh_interval_defaults_to_five_seconds_and_is_bounded(monkeypatch):
    monkeypatch.delenv(appliance_console.CONSOLE_REFRESH_ENV, raising=False)
    assert appliance_console._console_refresh_seconds() == 5
    monkeypatch.setenv(appliance_console.CONSOLE_REFRESH_ENV, "15")
    assert appliance_console._console_refresh_seconds() == 15
    monkeypatch.setenv(appliance_console.CONSOLE_REFRESH_ENV, "0")
    assert appliance_console._console_refresh_seconds() == 1
    monkeypatch.setenv(appliance_console.CONSOLE_REFRESH_ENV, "999")
    assert appliance_console._console_refresh_seconds() == 300
    monkeypatch.setenv(appliance_console.CONSOLE_REFRESH_ENV, "invalid")
    assert appliance_console._console_refresh_seconds() == 5


def test_console_missing_network_inventory_is_initializing_only_during_startup_grace():
    error = appliance_console.ConsoleNetworkInventoryUnavailable("No management interface is available.")

    assert appliance_console._console_status_failure(error, started_at=100.0, now=100.0) == (
        "Initializing appliance networking...",
        False,
    )
    assert appliance_console._console_status_failure(error, started_at=100.0, now=129.99) == (
        "Initializing appliance networking...",
        False,
    )
    assert appliance_console._console_status_failure(error, started_at=100.0, now=130.0) == (
        "Status unavailable: No management interface is available.",
        True,
    )


def test_console_uninitialized_physical_interface_table_is_network_initialization(monkeypatch):
    class UninitializedDatabase:
        def __enter__(self):
            raise SQLAlchemyOperationalError(
                "SELECT * FROM physical_interfaces",
                {},
                sqlite3.OperationalError("no such table: physical_interfaces"),
            )

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(appliance_console, "SessionLocal", UninitializedDatabase)

    with pytest.raises(
        appliance_console.ConsoleNetworkInventoryUnavailable,
        match="Management interface inventory is initializing",
    ):
        appliance_console.load_console_status()


def test_console_does_not_hide_unrelated_database_errors(monkeypatch):
    error = SQLAlchemyOperationalError(
        "SELECT * FROM settings",
        {},
        sqlite3.OperationalError("database disk image is malformed"),
    )

    class BrokenDatabase:
        def __enter__(self):
            raise error

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(appliance_console, "SessionLocal", BrokenDatabase)

    with pytest.raises(SQLAlchemyOperationalError) as raised:
        appliance_console.load_console_status()

    assert raised.value is error


def test_console_unrelated_status_failures_are_not_hidden_during_startup():
    error = RuntimeError("database unavailable")

    assert appliance_console._console_status_failure(error, started_at=100.0, now=100.0) == (
        "Status unavailable: database unavailable",
        True,
    )


def test_console_draws_initializing_network_message_during_startup(monkeypatch):
    class FakeCurses:
        A_BOLD = 0x100

        @staticmethod
        def color_pair(value):
            return value

    class FakeScreen:
        @staticmethod
        def getmaxyx():
            return (30, 80)

        @staticmethod
        def clear():
            return None

        @staticmethod
        def erase():
            return None

    def fail_status_load():
        raise appliance_console.ConsoleNetworkInventoryUnavailable("No management interface is available.")

    rendered: list[tuple[int, int, str, int]] = []
    console = CursesConsole.__new__(CursesConsole)
    console.curses = FakeCurses
    console.stdscr = FakeScreen()
    console._force_clear = True
    console._started_at = 100.0
    console._safe_add = lambda row, column, value, attr=0, **_kwargs: rendered.append((row, column, value, attr))
    console._fill_line = lambda *_args: None
    console._draw_footer = lambda *_args: None
    console._refresh_screen = lambda: None
    monkeypatch.setattr(appliance_console, "load_console_status", fail_status_load)
    monkeypatch.setattr(appliance_console.time, "monotonic", lambda: 105.0)

    console.draw_main()

    assert (5, 4, "Initializing appliance networking...", 1 | FakeCurses.A_BOLD) in rendered


def test_console_text_editor_supports_cursor_navigation_insertion_and_deletion():
    class FakeCurses:
        KEY_LEFT = 1
        KEY_RIGHT = 2
        KEY_HOME = 3
        KEY_END = 4
        KEY_BACKSPACE = 5
        KEY_DC = 6

    console = CursesConsole.__new__(CursesConsole)
    console.curses = FakeCurses

    value, cursor = console._edit_text("192.168.1.1", 11, FakeCurses.KEY_LEFT)
    value, cursor = console._edit_text(value, cursor, ord("0"))
    assert (value, cursor) == ("192.168.1.01", 11)
    value, cursor = console._edit_text(value, cursor, FakeCurses.KEY_BACKSPACE)
    assert (value, cursor) == ("192.168.1.1", 10)
    value, cursor = console._edit_text(value, cursor, FakeCurses.KEY_DC)
    assert (value, cursor) == ("192.168.1.", 10)
    assert console._edit_text(value, cursor, FakeCurses.KEY_HOME)[1] == 0
    assert console._edit_text(value, 0, FakeCurses.KEY_END)[1] == len(value)


def test_console_management_form_uses_field_navigation_and_cursor_editing():
    keys = [2, 1, ord("9"), 9, 9, 9, 9, 9, 9, 10]

    class FakeWindow:
        def keypad(self, _enabled):
            return None

        def erase(self):
            return None

        def bkgd(self, *_args):
            return None

        def box(self):
            return None

        def addnstr(self, *_args):
            return None

        def move(self, *_args):
            return None

        def refresh(self):
            return None

        def getch(self):
            return keys.pop(0)

    class FakeCurses:
        A_BOLD = 1
        A_REVERSE = 2
        KEY_LEFT = 1
        KEY_DOWN = 2
        KEY_RIGHT = 3
        KEY_HOME = 4
        KEY_END = 5
        KEY_BACKSPACE = 6
        KEY_DC = 7
        KEY_UP = 8
        KEY_BTAB = 353
        KEY_ENTER = 343

        @staticmethod
        def color_pair(value):
            return value

        @staticmethod
        def curs_set(_value):
            return None

        @staticmethod
        def newwin(*_args):
            return FakeWindow()

    console = CursesConsole.__new__(CursesConsole)
    console.curses = FakeCurses
    console.stdscr = SimpleNamespace(getmaxyx=lambda: (24, 80))
    status = SimpleNamespace(
        ipv4_method="static",
        ipv4_cidr="192.168.1.10/24",
        gateway="192.168.1.1",
        ipv6_mode="static",
        ipv6_cidr="2001:db8::10/64",
        ipv6_gateway="fe80::1",
        dns_servers=("192.168.1.2", "2001:db8::53"),
    )

    result = console._management_form(status)

    assert result == (
        "static",
        "192.168.1.10/294",
        "192.168.1.1",
        "static",
        "2001:db8::10/64",
        "fe80::1",
        "192.168.1.2, 2001:db8::53",
    )


def test_console_top_temporarily_leaves_and_restores_curses(monkeypatch):
    events: list[str] = []

    class FakeCurses:
        class error(Exception):
            pass

        @staticmethod
        def def_prog_mode():
            events.append("save")

        @staticmethod
        def endwin():
            events.append("end")

        @staticmethod
        def reset_prog_mode():
            events.append("restore")

    console = CursesConsole.__new__(CursesConsole)
    console.curses = FakeCurses
    console.message = ""
    console.message_error = False
    console._force_clear = False
    console._initialize_screen = lambda: events.append("initialize")
    console._clear_terminal = lambda: events.append("clear")
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(
        appliance_console.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs)) or subprocess.CompletedProcess(command, 0),
    )

    console.show_top()

    assert [command for command, _kwargs in calls] == [["top"]]
    assert calls[0][1]["stdin"] is appliance_console.sys.stdin
    assert calls[0][1]["stdout"] is appliance_console.sys.stdout
    assert calls[0][1]["stderr"] is appliance_console.sys.stdout
    assert events == ["save", "end", "clear", "clear", "restore", "initialize"]
    assert console._force_clear is True


@pytest.mark.parametrize(("authenticated", "expected_calls"), [(True, 1), (False, 0)])
def test_console_top_requires_fresh_root_authentication(authenticated, expected_calls):
    console = CursesConsole.__new__(CursesConsole)
    calls: list[str] = []
    console._require_authentication = lambda: authenticated
    console.show_top = lambda: calls.append("top")

    console.show_authenticated_top()

    assert len(calls) == expected_calls


def test_console_top_authentication_cancel_does_not_check_password(monkeypatch):
    console = CursesConsole.__new__(CursesConsole)
    console._prompt = lambda *args, **kwargs: None
    console.message = ""
    console.message_error = False
    calls: list[str] = []
    monkeypatch.setattr(appliance_console, "authenticate_root", lambda password: calls.append(password) or True)

    assert console._require_authentication() is False
    assert calls == []


def test_console_password_prompt_uses_light_network_field_style():
    field_attributes: list[int] = []
    rendered_text: list[str] = []
    rendered_rows: list[tuple[int, str]] = []

    class FakeWindow:
        def keypad(self, _enabled):
            return None

        def bkgd(self, *_args):
            return None

        def box(self):
            return None

        def addnstr(self, row, _column, value, _length, attribute):
            rendered_text.append(value)
            rendered_rows.append((row, value))
            if row == 3:
                field_attributes.append(attribute)

        def move(self, *_args):
            return None

        def refresh(self):
            return None

        def get_wch(self):
            return "\x1b"

    class FakeCurses:
        A_BOLD = 1
        KEY_LEFT = 1
        KEY_RIGHT = 2
        KEY_UP = 3
        KEY_DOWN = 4
        KEY_BTAB = 353
        KEY_ENTER = 343

        @staticmethod
        def color_pair(value):
            return value

        @staticmethod
        def curs_set(_value):
            return None

        @staticmethod
        def newwin(*_args):
            return FakeWindow()

    console = CursesConsole.__new__(CursesConsole)
    console.curses = FakeCurses
    console.stdscr = SimpleNamespace(getmaxyx=lambda: (30, 80))

    assert console._prompt("Photon OS root authentication", "Root password:", secret=True) is None
    assert field_attributes == [9, 9]
    assert (0, " Photon OS root authentication ") in rendered_rows
    assert " < Apply > " in rendered_text
    assert " < Cancel > " in rendered_text


def test_console_password_prompt_preserves_literal_root_password_characters():
    keys = iter([*"VMware01!", "\n"])

    class FakeWindow:
        def keypad(self, _enabled):
            return None

        def bkgd(self, *_args):
            return None

        def box(self):
            return None

        def addnstr(self, *_args):
            return None

        def move(self, *_args):
            return None

        def refresh(self):
            return None

        def get_wch(self):
            return next(keys)

    class FakeCurses:
        A_BOLD = 1
        KEY_LEFT = 1
        KEY_RIGHT = 2
        KEY_UP = 3
        KEY_DOWN = 4
        KEY_BTAB = 353
        KEY_ENTER = 343

        @staticmethod
        def color_pair(value):
            return value

        @staticmethod
        def curs_set(_value):
            return None

        @staticmethod
        def newwin(*_args):
            return FakeWindow()

    console = CursesConsole.__new__(CursesConsole)
    console.curses = FakeCurses
    console.stdscr = SimpleNamespace(getmaxyx=lambda: (30, 80))

    assert console._prompt("Photon OS root authentication", "Root password:", secret=True) == "VMware01!"


def test_console_top_authentication_failure_is_visible(monkeypatch):
    console = CursesConsole.__new__(CursesConsole)
    console._prompt = lambda *args, **kwargs: "incorrect"
    console.message = "Previous message"
    console.message_error = True
    dialogs: list[tuple[str, list[str], list[str]]] = []
    console._dialog = lambda title, lines, options: dialogs.append((title, lines, options)) or 0
    monkeypatch.setattr(appliance_console, "authenticate_root", lambda _password: False)

    assert console._require_authentication() is False
    assert dialogs == [("Root authentication failed", ["The Photon OS root password was incorrect."], ["OK"])]
    assert console.message == ""
    assert console.message_error is False


def test_console_shell_is_audited_and_returns_to_curses(monkeypatch):
    console = CursesConsole.__new__(CursesConsole)
    events: list[object] = []
    console.message = ""
    console.message_error = False
    console._run_interactive = lambda command, label: events.append((command, label)) or 0
    monkeypatch.setattr(appliance_console, "record_console_shell", lambda action: events.append(action))

    console.show_shell()

    assert events == ["open", (["/usr/bin/bash", "--login"], "Bash console"), "close"]


def test_console_management_rows_use_stable_table_columns():
    ipv4 = CursesConsole._network_table_row(
        "IPv4", "192.168.167.219/24", 128, gateway="192.168.167.2", mode="dhcp"
    )
    ipv6 = CursesConsole._network_table_row(
        "IPv6", "Awaiting RA/SLAAC", 128, gateway="none", mode="automatic"
    )

    assert ipv4.index("GW ") == ipv6.index("GW ")
    assert ipv4.index("Mode ") == ipv6.index("Mode ")
    assert ipv4.startswith("IPv4      192.168.167.219/24")
    assert ipv6.startswith("IPv6      Awaiting RA/SLAAC")


def test_console_help_pages_cover_status_keys_navigation_and_safety():
    titles = [title for title, _lines in appliance_console.HELP_PAGES]
    help_text = "\n".join(line for _title, lines in appliance_console.HELP_PAGES for line in lines)

    assert titles == ["Screen overview", "Service states", "Function keys", "Dialogs and navigation", "Recovery and safety"]
    for expected in ("▶ on", "▶ off", "■ on", "■ off", "! crashed", "? on"):
        assert expected in help_text
    for expected in ("F1 Help", "F2 Customize", "F3 Top", "F4 Console", "F12 Shut down / Restart"):
        assert expected in help_text
    assert "Ctrl+Alt+Del is blocked" in help_text
    assert max(len(line) for _title, lines in appliance_console.HELP_PAGES for line in lines) <= 68


def test_console_help_modal_pages_forward_and_closes():
    keys = iter([343, 343, 343, 343, 343])
    framed_titles: list[str] = []

    class FakeWindow:
        def keypad(self, _enabled):
            return None

        def erase(self):
            return None

        def bkgd(self, *_args):
            return None

        def box(self):
            return None

        def addnstr(self, row, _column, value, *_args):
            if row == 0:
                framed_titles.append(value)

        def refresh(self):
            return None

        def getch(self):
            return next(keys)

    class FakeCurses:
        A_BOLD = 1
        KEY_F1 = 265
        KEY_RESIZE = 410
        KEY_LEFT = 260
        KEY_RIGHT = 261
        KEY_UP = 259
        KEY_DOWN = 258
        KEY_PPAGE = 339
        KEY_NPAGE = 338
        KEY_BTAB = 353
        KEY_ENTER = 343

        @staticmethod
        def color_pair(value):
            return value

        @staticmethod
        def newwin(*_args):
            return FakeWindow()

    console = CursesConsole.__new__(CursesConsole)
    console.curses = FakeCurses
    console.stdscr = SimpleNamespace(getmaxyx=lambda: (30, 80))

    console.show_help()

    assert len(framed_titles) == len(appliance_console.HELP_PAGES)
    assert "Console help 1/5 - Screen overview" in framed_titles[0]
    assert "Console help 5/5 - Recovery and safety" in framed_titles[-1]


def test_console_footer_includes_help_and_compact_power_label():
    rendered: list[tuple[int, str]] = []
    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(A_BOLD=1, color_pair=lambda value: value)
    console._fill_line = lambda *_args: None
    console._safe_add = lambda _row, column, value, *_args: rendered.append((column, value))

    console._draw_footer(30, 80)

    assert rendered == [
        (1, "<F1> Help"),
        (12, "<F2> Customize"),
        (29, "<F3> Top"),
        (40, "<F4> Console"),
        (67, "<F12> Power"),
    ]


def test_console_appliance_services_use_full_catalog_and_optional_units(monkeypatch):
    from labfoundry.app import ui

    rows = [
        {"service": service_id, "enabled": True, "running": True}
        for _label, service_id, _unit in appliance_console.SERVICE_CATALOG
    ]
    next(row for row in rows if row["service"] == "firewall")["enabled"] = False
    next(row for row in rows if row["service"] == "kms").update(enabled=False, running=False)
    monkeypatch.setattr(ui, "services_template_context", lambda db: {"service_rows": rows})
    monkeypatch.setattr(
        appliance_console,
        "_systemd_unit_states",
        lambda units: {
            unit: {
                "LoadState": "not-found" if unit == "labfoundry-kms.service" else "loaded",
                "UnitFileState": "enabled",
                "ActiveState": "failed" if unit == "slapd.service" else "active",
            }
            for unit in units
        },
    )

    statuses = appliance_console._appliance_service_statuses(SimpleNamespace(), firewall_enabled=False)

    assert [status.label for status in statuses] == [row[0] for row in appliance_console.SERVICE_CATALOG]
    assert len(statuses) == 14
    assert next(status for status in statuses if status.label == "Managed LDAP").display_label == "! crashed"
    assert next(status for status in statuses if status.label == "KMS / KMIP").display_label == "■ off"
    firewall = next(status for status in statuses if status.label == "Firewall")
    assert firewall.display_label == "▶ off"


def test_console_enabled_optional_service_without_unit_is_unavailable(monkeypatch):
    from labfoundry.app import ui

    rows = [
        {"service": service_id, "enabled": service_id == "kms", "running": False}
        for _label, service_id, _unit in appliance_console.SERVICE_CATALOG
    ]
    monkeypatch.setattr(ui, "services_template_context", lambda db: {"service_rows": rows})
    monkeypatch.setattr(appliance_console, "_systemd_unit_states", lambda units: {})

    statuses = appliance_console._appliance_service_statuses(SimpleNamespace(), firewall_enabled=False)

    assert next(status for status in statuses if status.label == "KMS / KMIP").display_label == "? on"


def test_console_service_rows_fit_normal_tty_and_compact_summary_reports_exceptions():
    services = (
        ServiceStatus("LabFoundry", "labfoundry.service", "loaded", "enabled", "active"),
        ServiceStatus("LDAP", "slapd.service", "loaded", "enabled", "failed"),
        ServiceStatus("KMS", "labfoundry-kms.service", "not-found", "", "inactive"),
        ServiceStatus("Firewall", "labfoundry-firewall.service", "loaded", "enabled", "active", False),
    )

    assert CursesConsole._service_cell(services[0], 38) == "LabFoundry            ▶ on"
    assert CursesConsole._service_cell(services[3], 38) == "Firewall              ▶ off"
    summary = CursesConsole._service_summary(services)
    assert summary == "2 running | 1 failed | 0 stopped | 1 unavailable | Firewall disabled"

    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(A_BOLD=1, color_pair=lambda value: value)
    assert console._service_attr(services[0]) == 10

    full_catalog = tuple(
        ServiceStatus(label, unit or service_id, "loaded", "enabled", "active", True)
        for label, service_id, unit in appliance_console.SERVICE_CATALOG
    )
    assert (len(full_catalog) + 1) // 2 == 7
    assert CursesConsole._service_grid_fits(30, len(full_catalog)) is True
    assert CursesConsole._service_grid_fits(29, len(full_catalog)) is False
    assert all(len(CursesConsole._service_cell(service, 38)) <= 37 for service in full_catalog)
    assert "Certificate Authority" in CursesConsole._service_cell(full_catalog[1], 38)
    assert "VCF Private Registry" in CursesConsole._service_cell(full_catalog[-1], 38)


def test_console_has_no_dedicated_time_service_surface():
    source = Path(appliance_console.__file__).read_text(encoding="utf-8")
    for forbidden in ("NtpSettings", "validate_ntp_servers", "configure_ntp", '"NTP servers"'):
        assert forbidden not in source
    assert '{"ntpd"}' not in source


def test_console_restores_main_surface_before_reopening_parent_menu():
    console = CursesConsole.__new__(CursesConsole)
    console._force_clear = False
    draws: list[bool] = []
    console.draw_main = lambda: draws.append(console._force_clear)

    console._restore_main_surface()

    assert draws == [True]


def test_console_authentication_is_requested_for_each_menu_entry(monkeypatch):
    console = CursesConsole.__new__(CursesConsole)
    prompts = iter(["first-password", "second-password"])
    console._prompt = lambda *args, **kwargs: next(prompts)
    console.message = ""
    console.message_error = False
    passwords: list[str] = []
    monkeypatch.setattr(appliance_console, "authenticate_root", lambda password: passwords.append(password) or True)

    assert console._require_authentication() is True
    assert console._require_authentication() is True
    assert passwords == ["first-password", "second-password"]


def test_console_firewall_toggle_persists_desired_state_and_selects_only_firewall(client, monkeypatch):
    from sqlalchemy import select

    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import FirewallSettings

    selected: list[set[str]] = []
    monkeypatch.setattr(appliance_console, "_submit_console_apply", lambda unit_ids, **kwargs: selected.append(unit_ids) or "job_firewall")

    assert configure_firewall(False) == "job_firewall"
    with SessionLocal() as db:
        firewall = db.scalar(select(FirewallSettings))
        assert firewall is not None
        assert firewall.enabled is False
    assert selected == [{"firewall"}]


def test_console_power_task_is_committed_before_real_helper_invocation(client, monkeypatch):
    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import Job, JobStatus

    observed: list[tuple[list[str], str, str]] = []

    def fake_run(command, **kwargs):
        with SessionLocal() as db:
            job = db.query(Job).filter(Job.type == "appliance-reboot").one()
            observed.append((command, job.status, job.created_by))
        return subprocess.CompletedProcess(command, 0, "scheduled\n", "")

    monkeypatch.setattr(appliance_console, "_run", fake_run)
    job_id = schedule_power("reboot")

    assert observed == [([str(appliance_console.HELPER_PATH), "appliance-power", "reboot", "--real"], JobStatus.RUNNING.value, "console:root")]
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job is not None
        assert job.status == JobStatus.SUCCEEDED.value
        assert job.created_by == "console:root"


def test_forced_real_apply_seam_rejects_non_console_jobs(client):
    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import Job, JobStatus
    from labfoundry.app.ui import run_appliance_apply_job

    with SessionLocal() as db:
        db.add(Job(id="job_not_console", type="appliance-apply", status=JobStatus.PENDING.value, created_by="admin"))
        db.commit()

    with pytest.raises(ValueError, match="restricted to local console"):
        run_appliance_apply_job("job_not_console", force_real=True)


def test_console_desired_state_edit_is_rejected_before_commit_when_apply_is_active(client):
    from sqlalchemy import select

    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import FirewallSettings, Job, JobStatus

    with SessionLocal() as db:
        firewall = db.scalar(select(FirewallSettings))
        assert firewall is not None
        original = firewall.enabled
        db.add(Job(id="job_active_apply", type="appliance-apply", status=JobStatus.RUNNING.value, created_by="admin"))
        db.commit()

    with pytest.raises(ConsoleOperationError, match="already running"):
        configure_firewall(not original)

    with SessionLocal() as db:
        firewall = db.scalar(select(FirewallSettings))
        assert firewall is not None
        assert firewall.enabled is original


def test_console_systemd_unit_replaces_only_tty1():
    unit = Path("image/common/systemd/labfoundry-console.service").read_text(encoding="utf-8")
    provision = Path("image/common/scripts/provision-labfoundry.sh").read_text(encoding="utf-8")
    manager = Path("image/common/systemd/labfoundry-console-manager.conf").read_text(encoding="utf-8")
    assert "TTYPath=/dev/tty1" in unit
    assert "Conflicts=getty@tty1.service" in unit
    assert "getty@tty2" not in unit
    assert "systemctl mask getty@tty1.service" in provision
    assert "systemctl enable labfoundry-console.service" in provision
    assert "getty@tty2" not in provision
    assert 'run_tdnf "Photon appliance package installation"' in provision
    assert "python3-curses" in provision and "procps-ng" in provision
    assert "ShowStatus=no" in manager
    assert "CtrlAltDelBurstAction=none" in manager
    assert "systemctl mask --force ctrl-alt-del.target" in provision
    assert "/etc/systemd/system.conf.d/labfoundry-console.conf" in provision
    deploy = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    assert "systemctl restart labfoundry-console.service" in deploy
    assert "systemctl is-active labfoundry-console.service" in deploy
    assert "/etc/systemd/system.conf.d/labfoundry-console.conf" in deploy
    assert "systemctl daemon-reexec" in deploy
    assert "systemctl mask --force ctrl-alt-del.target" in deploy


def test_console_service_isolation_preserves_console_network_and_firewall(monkeypatch, tmp_path, capsys):
    helper = load_helper_module()
    state_dir = tmp_path / "console"
    state_path = state_dir / "services.json"
    monkeypatch.setattr(helper, "CONSOLE_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "CONSOLE_SERVICE_STATE_PATH", state_path)
    monkeypatch.setattr(
        helper,
        "_console_unit_state",
        lambda unit: {"unit": unit, "enabled": True, "active": unit != "ntpd.service"},
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", fake_run)
    assert helper._handle_console("disable-services", []) == 0
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert {row["unit"] for row in saved["units"]} == set(helper.CONSOLE_MANAGED_SERVICE_UNITS)
    assert all(command[:3] == ["systemctl", "disable", "--now"] for command in commands)
    flattened = " ".join(" ".join(command) for command in commands)
    assert "labfoundry-console.service" not in flattened
    assert "systemd-networkd.service" not in flattened
    assert "labfoundry-firewall.service" not in flattened
    output = capsys.readouterr().out
    assert "management networking" in output


def test_console_service_restore_uses_saved_enable_and_active_state(monkeypatch, tmp_path):
    helper = load_helper_module()
    state_dir = tmp_path / "console"
    state_dir.mkdir()
    state_path = state_dir / "services.json"
    state_path.write_text(
        json.dumps(
            {
                "units": [
                    {"unit": "nginx.service", "enabled": True, "active": True},
                    {"unit": "ntpd.service", "enabled": False, "active": False},
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "CONSOLE_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "CONSOLE_SERVICE_STATE_PATH", state_path)
    commands: list[list[str]] = []
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: commands.append(command) or subprocess.CompletedProcess(command, 0, "", ""),
    )
    assert helper._handle_console("restore-services", []) == 0
    assert commands == [["systemctl", "enable", "nginx.service"], ["systemctl", "start", "nginx.service"]]
    assert not state_path.exists()


def test_console_service_restore_keeps_snapshot_when_restoration_is_incomplete(monkeypatch, tmp_path):
    helper = load_helper_module()
    state_dir = tmp_path / "console"
    state_dir.mkdir()
    state_path = state_dir / "services.json"
    state_path.write_text(
        json.dumps({"units": [{"unit": "nginx.service", "enabled": True, "active": True}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "CONSOLE_STATE_DIR", state_dir)
    monkeypatch.setattr(helper, "CONSOLE_SERVICE_STATE_PATH", state_path)
    monkeypatch.setattr(
        helper,
        "_run",
        lambda command: subprocess.CompletedProcess(command, 1, "", "restore failed"),
    )

    assert helper._handle_console("restore-services", []) == 1
    assert state_path.exists()
