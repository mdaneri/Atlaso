"""Test appliance console behavior."""

import importlib.machinery
import importlib.util
import json
import sqlite3
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import OperationalError as SQLAlchemyOperationalError

import atlaso.app.appliance_console as appliance_console
from atlaso.app.appliance_console import (
    ConsoleOperationError,
    CursesConsole,
    ServiceStatus,
    configure_firewall,
    management_urls,
    schedule_power,
    validate_dns_servers,
    validate_ipv6_management_values,
    validate_management_values,
)

HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "atlaso-helper"


def load_helper_module():
    """Return helper module."""
    loader = importlib.machinery.SourceFileLoader("atlaso_helper_console", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("atlaso_helper_console", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_console_management_validation_limits_dhcp_and_static_values():
    """Verify that console management validation limits dhcp and static values."""
    assert validate_management_values("dhcp", "", "") == ("dhcp", "", "")
    assert validate_management_values("static", "192.168.49.1/24", "192.168.49.254") == (
        "static",
        "192.168.49.1/24",
        "192.168.49.254",
    )
    with pytest.raises(ConsoleOperationError, match="on-link"):
        validate_management_values("static", "192.168.49.1/24", "192.168.50.1")
    with pytest.raises(ConsoleOperationError, match="on-link"):
        validate_management_values("static", "192.168.1.254/32", "192.168.1.1")
    with pytest.raises(ConsoleOperationError, match="cannot equal"):
        validate_management_values("static", "192.168.49.1/24", "192.168.49.1")
    with pytest.raises(ConsoleOperationError, match="cannot include"):
        validate_management_values("dhcp", "192.168.49.1/24", "")


def test_console_first_boot_network_review_submits_only_valid_nonsecret_values(tmp_path, monkeypatch):
    """Verify tty1 transitions a recoverable OVF review into a safe correction.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace first-boot state paths.
    """
    review_path = tmp_path / "network-review.json"
    correction_path = tmp_path / "network-correction.json"
    monkeypatch.setattr(appliance_console, "FIRST_BOOT_NETWORK_REVIEW_PATH", review_path)
    monkeypatch.setattr(appliance_console, "FIRST_BOOT_NETWORK_CORRECTION_PATH", correction_path)
    review_path.write_text(
        json.dumps(
            {
                "version": 1,
                "state": "network_review",
                "error": "Management gateway must be on-link for the configured prefix.",
                "ipv4_method": "static",
                "ipv4_cidr": "192.168.1.254/32",
                "ipv4_gateway": "192.168.1.1",
                "ipv6_mode": "automatic",
                "ipv6_cidr": "",
                "ipv6_gateway": "",
                "dns_servers": "192.168.1.2",
                "fqdn": "appliance.atlaso.internal",
                "ignored_password": "must-not-be-loaded",
            }
        ),
        encoding="utf-8",
    )

    review = appliance_console.load_first_boot_network_review()

    assert review is not None
    assert review.ipv4_cidr == "192.168.1.254/32"
    assert review.gateway == "192.168.1.1"
    assert review.fqdn == "appliance.atlaso.internal"
    assert "must-not-be-loaded" not in repr(review)
    with pytest.raises(ConsoleOperationError, match="on-link"):
        appliance_console.submit_first_boot_network_correction(
            "static",
            "192.168.1.254/32",
            "192.168.1.1",
            "automatic",
            "",
            "",
            "192.168.1.2",
        )
    assert not correction_path.exists()

    result = appliance_console.submit_first_boot_network_correction(
        "static",
        "192.168.1.254/24",
        "192.168.1.1",
        "automatic",
        "",
        "",
        "192.168.1.2",
    )

    correction = json.loads(correction_path.read_text(encoding="utf-8"))
    assert result == "First-time management network correction submitted"
    assert correction["ipv4_cidr"] == "192.168.1.254/24"
    assert correction["ipv4_gateway"] == "192.168.1.1"
    assert correction["ipv6_mode"] == "automatic"
    assert "password" not in str(correction).lower()


@pytest.mark.parametrize(
    ("reported", "expected"),
    [("x86_64", "amd64"), ("AMD64", "amd64"), ("aarch64", "arm64"), ("armv7l", "armv7"), ("riscv64", "riscv64"), ("", "unknown")],
)
def test_console_architecture_label_normalizes_common_platform_names(reported, expected):
    """Verify that console architecture label normalizes common platform names.

    Args:
        reported: Reported supplied to the test scenario.
        expected: Expected value used to verify the tested behavior.
    """
    assert appliance_console._architecture_label(reported) == expected


def test_console_dns_validation_accepts_compact_lists():
    """Verify that console dns validation accepts compact lists."""
    assert validate_dns_servers("1.1.1.1, 9.9.9.9") == ["1.1.1.1", "9.9.9.9"]
    with pytest.raises(ConsoleOperationError, match="DNS server"):
        validate_dns_servers("resolver.example.com")


def test_console_ipv6_management_validation_supports_independent_modes_and_gateways():
    """Verify that console ipv6 management validation supports independent modes and gateways."""
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
    """Verify that console management urls bracket ipv6 and ignore link local addresses."""
    assert management_urls("appliance.atlaso.internal", "192.168.49.10/24", "2001:db8:49::10/64") == (
        "https://appliance.atlaso.internal/",
        "https://192.168.49.10/",
        "https://[2001:db8:49::10]/",
    )
    assert management_urls("", "", "fe80::10/64") == ()
    assert management_urls(
        "appliance.atlaso.internal",
        "192.168.49.10/24",
        "2001:db8:49::10/64",
        https_enabled=False,
    ) == (
        "http://appliance.atlaso.internal/",
        "http://192.168.49.10/",
        "http://[2001:db8:49::10]/",
    )


def test_console_load_summary_uses_one_five_and_fifteen_minute_averages(monkeypatch):
    """Verify that console load summary uses one five and fifteen minute averages.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
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
    """Verify that console load status scales warning and critical thresholds by cpu count.

    Args:
        values: Candidate values consumed by test console load status scales warning and critical
            thresholds by CPU count.
        cpu_count: Number of CPU entries.
        expected: Expected value used to verify the tested behavior.
    """
    summary, severity = appliance_console._load_status(values, cpu_count)

    assert summary.startswith("1 min ")
    assert severity == expected


def test_console_load_colors_use_header_safe_warning_and_critical_pairs():
    """Verify that console load colors use header safe warning and critical pairs."""
    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(A_BOLD=0x100, color_pair=lambda value: value)

    assert console._load_attr("normal") == 1
    assert console._load_attr("warning") == 6 | 0x100
    assert console._load_attr("critical") == 7 | 0x100


def test_console_release_summary_drops_embedded_photon_metadata_lines():
    """Verify that console release summary drops embedded photon metadata lines."""
    release = "VMware Photon OS 5.0\nPHOTON_BUILD_NUMBER=12345\n"

    assert appliance_console._first_display_line(release, "Linux") == "VMware Photon OS 5.0"


def test_console_uses_bounded_recovery_redraws_after_service_activity():
    """Verify that console uses bounded recovery redraws after service activity."""
    assert CursesConsole._recovery_redraws(10.0) == [11.0, 13.0, 18.0]


def test_console_refresh_interval_defaults_to_five_seconds_and_is_bounded(monkeypatch):
    """Verify that console refresh interval defaults to five seconds and is bounded.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
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
    """Verify that console missing network inventory is initializing only during startup grace."""
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
    """Verify that console uninitialized physical interface table is network initialization.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    class UninitializedDatabase:
        """Represent uninitialized database."""
        def __enter__(self):
            """Enter the managed context.

            Raises:
                SQLAlchemyOperationalError: If the operation encounters an invalid state.
            """
            raise SQLAlchemyOperationalError(
                "SELECT * FROM physical_interfaces",
                {},
                sqlite3.OperationalError("no such table: physical_interfaces"),
            )

        def __exit__(self, *_args):
            """Exit the managed context without suppressing exceptions.

            Args:
                *_args: Additional positional arguments accepted by the callable.


            Returns:
                The exit result.
            """
            return False

    monkeypatch.setattr(appliance_console, "SessionLocal", UninitializedDatabase)

    with pytest.raises(
        appliance_console.ConsoleNetworkInventoryUnavailable,
        match="Management interface inventory is initializing",
    ):
        appliance_console.load_console_status()


def test_console_does_not_hide_unrelated_database_errors(monkeypatch):
    """Verify that console does not hide unrelated database errors.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    error = SQLAlchemyOperationalError(
        "SELECT * FROM settings",
        {},
        sqlite3.OperationalError("database disk image is malformed"),
    )

    class BrokenDatabase:
        """Represent broken database."""
        def __enter__(self):
            """Enter the managed context.

            Raises:
                SQLAlchemyOperationalError: Always, to exercise database-error propagation.
            """
            raise error

        def __exit__(self, *_args):
            """Exit the managed context without suppressing exceptions.

            Args:
                *_args: Additional positional arguments accepted by the callable.


            Returns:
                The exit result.
            """
            return False

    monkeypatch.setattr(appliance_console, "SessionLocal", BrokenDatabase)

    with pytest.raises(SQLAlchemyOperationalError) as raised:
        appliance_console.load_console_status()

    assert raised.value is error


def test_console_unrelated_status_failures_are_not_hidden_during_startup():
    """Verify that console unrelated status failures are not hidden during startup."""
    error = RuntimeError("database unavailable")

    assert appliance_console._console_status_failure(error, started_at=100.0, now=100.0) == (
        "Status unavailable: database unavailable",
        True,
    )


def test_console_draws_initializing_network_message_during_startup(monkeypatch):
    """Verify that console draws initializing network message during startup.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    class FakeCurses:
        """Represent fake curses.

        Attributes:
            A_BOLD: Symbolic value representing 256.
        """
        A_BOLD = 0x100

        @staticmethod
        def color_pair(value):
            """Return color pair.

            Args:
                value: Candidate value consumed by color pair.
            """
            return value

    class FakeScreen:
        """Represent fake screen."""
        @staticmethod
        def getmaxyx():
            """Return getmaxyx."""
            return (30, 80)

        @staticmethod
        def clear():
            """Remove operation.

            Returns:
                The clear result.
            """
            return None

        @staticmethod
        def erase():
            """Return erase."""
            return None

    def fail_status_load():
        """Handle fail status load.

        Raises:
            ConsoleNetworkInventoryUnavailable: If the operation encounters an invalid state.
        """
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
    """Verify that console text editor supports cursor navigation insertion and deletion."""
    class FakeCurses:
        """Represent fake curses.

        Attributes:
            KEY_LEFT: Symbolic value representing 1.
            KEY_RIGHT: Symbolic value representing 2.
            KEY_HOME: Symbolic value representing 3.
            KEY_END: Symbolic value representing 4.
            KEY_BACKSPACE: Symbolic value representing 5.
            KEY_DC: Symbolic value representing 6.
        """
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
    """Verify that console management form uses field navigation and cursor editing."""
    keys = [2, 1, ord("9"), 9, 9, 9, 9, 9, 9, 10]

    class FakeWindow:
        """Represent fake window."""
        def keypad(self, _enabled):
            """Return keypad.

            Args:
                _enabled: Whether the associated resource or behavior is enabled.
            """
            return None

        def erase(self):
            """Return erase."""
            return None

        def bkgd(self, *_args):
            """Return bkgd.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return None

        def box(self):
            """Return box."""
            return None

        def addnstr(self, *_args):
            """Return addnstr.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return None

        def move(self, *_args):
            """Return move.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return None

        def refresh(self):
            """Return refresh."""
            return None

        def getch(self):
            """Return getch."""
            return keys.pop(0)

    class FakeCurses:
        """Represent fake curses.

        Attributes:
            A_BOLD: Symbolic value representing 1.
            A_REVERSE: Symbolic value representing 2.
            KEY_LEFT: Symbolic value representing 1.
            KEY_DOWN: Symbolic value representing 2.
            KEY_RIGHT: Symbolic value representing 3.
            KEY_HOME: Symbolic value representing 4.
            KEY_END: Symbolic value representing 5.
            KEY_BACKSPACE: Symbolic value representing 6.
            KEY_DC: Symbolic value representing 7.
            KEY_UP: Symbolic value representing 8.
            KEY_BTAB: Symbolic value representing 353.
            KEY_ENTER: Symbolic value representing 343.
        """
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
            """Return color pair.

            Args:
                value: Candidate value consumed by color pair.
            """
            return value

        @staticmethod
        def curs_set(_value):
            """Return curs set.

            Args:
                _value: Candidate value consumed by curs set.
            """
            return None

        @staticmethod
        def newwin(*_args):
            """Return newwin.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
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
    """Verify that console top temporarily leaves and restores curses.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    events: list[str] = []

    class FakeCurses:
        """Represent fake curses."""
        class error(Exception):
            """Represent error."""
            pass

        @staticmethod
        def def_prog_mode():
            """Handle def prog mode."""
            events.append("save")

        @staticmethod
        def endwin():
            """Handle endwin."""
            events.append("end")

        @staticmethod
        def reset_prog_mode():
            """Remove prog mode."""
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
    """Verify that console top requires fresh root authentication.

    Args:
        authenticated: Authenticated supplied to the test scenario.
        expected_calls: Expected calls used to verify dependency interactions.
    """
    console = CursesConsole.__new__(CursesConsole)
    calls: list[str] = []
    console._require_authentication = lambda: authenticated
    console.show_top = lambda: calls.append("top")

    console.show_authenticated_top()

    assert len(calls) == expected_calls


def test_console_top_authentication_cancel_does_not_check_password(monkeypatch):
    """Verify that console top authentication cancel does not check password.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    console = CursesConsole.__new__(CursesConsole)
    console._prompt = lambda *args, **kwargs: None
    console.message = ""
    console.message_error = False
    calls: list[str] = []
    monkeypatch.setattr(appliance_console, "authenticate_root", lambda password: calls.append(password) or True)

    assert console._require_authentication() is False
    assert calls == []


def test_console_password_prompt_uses_light_network_field_style():
    """Verify that console password prompt uses light network field style."""
    field_attributes: list[int] = []
    rendered_text: list[str] = []
    rendered_rows: list[tuple[int, str]] = []

    class FakeWindow:
        """Represent fake window."""
        def keypad(self, _enabled):
            """Return keypad.

            Args:
                _enabled: Whether the associated resource or behavior is enabled.
            """
            return None

        def bkgd(self, *_args):
            """Return bkgd.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return None

        def box(self):
            """Return box."""
            return None

        def addnstr(self, row, _column, value, _length, attribute):
            """Handle addnstr.

            Args:
                row: Database or collection row to process.
                _column:  column supplied by the caller.
                value: Value to process.
                _length:  length supplied by the caller.
                attribute: Attribute supplied by the caller.
            """
            rendered_text.append(value)
            rendered_rows.append((row, value))
            if row == 3:
                field_attributes.append(attribute)

        def move(self, *_args):
            """Return move.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return None

        def refresh(self):
            """Return refresh."""
            return None

        def get_wch(self):
            """Return wch."""
            return "\x1b"

    class FakeCurses:
        """Represent fake curses.

        Attributes:
            A_BOLD: Symbolic value representing 1.
            KEY_LEFT: Symbolic value representing 1.
            KEY_RIGHT: Symbolic value representing 2.
            KEY_UP: Symbolic value representing 3.
            KEY_DOWN: Symbolic value representing 4.
            KEY_BTAB: Symbolic value representing 353.
            KEY_ENTER: Symbolic value representing 343.
        """
        A_BOLD = 1
        KEY_LEFT = 1
        KEY_RIGHT = 2
        KEY_UP = 3
        KEY_DOWN = 4
        KEY_BTAB = 353
        KEY_ENTER = 343

        @staticmethod
        def color_pair(value):
            """Return color pair.

            Args:
                value: Candidate value consumed by color pair.
            """
            return value

        @staticmethod
        def curs_set(_value):
            """Return curs set.

            Args:
                _value: Candidate value consumed by curs set.
            """
            return None

        @staticmethod
        def newwin(*_args):
            """Return newwin.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
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
    """Verify that console password prompt preserves literal root password characters."""
    keys = iter([*"VMware01!", "\n"])

    class FakeWindow:
        """Represent fake window."""
        def keypad(self, _enabled):
            """Return keypad.

            Args:
                _enabled: Whether the associated resource or behavior is enabled.
            """
            return None

        def bkgd(self, *_args):
            """Return bkgd.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return None

        def box(self):
            """Return box."""
            return None

        def addnstr(self, *_args):
            """Return addnstr.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return None

        def move(self, *_args):
            """Return move.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return None

        def refresh(self):
            """Return refresh."""
            return None

        def get_wch(self):
            """Return wch."""
            return next(keys)

    class FakeCurses:
        """Represent fake curses.

        Attributes:
            A_BOLD: Symbolic value representing 1.
            KEY_LEFT: Symbolic value representing 1.
            KEY_RIGHT: Symbolic value representing 2.
            KEY_UP: Symbolic value representing 3.
            KEY_DOWN: Symbolic value representing 4.
            KEY_BTAB: Symbolic value representing 353.
            KEY_ENTER: Symbolic value representing 343.
        """
        A_BOLD = 1
        KEY_LEFT = 1
        KEY_RIGHT = 2
        KEY_UP = 3
        KEY_DOWN = 4
        KEY_BTAB = 353
        KEY_ENTER = 343

        @staticmethod
        def color_pair(value):
            """Return color pair.

            Args:
                value: Candidate value consumed by color pair.
            """
            return value

        @staticmethod
        def curs_set(_value):
            """Return curs set.

            Args:
                _value: Candidate value consumed by curs set.
            """
            return None

        @staticmethod
        def newwin(*_args):
            """Return newwin.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return FakeWindow()

    console = CursesConsole.__new__(CursesConsole)
    console.curses = FakeCurses
    console.stdscr = SimpleNamespace(getmaxyx=lambda: (30, 80))

    assert console._prompt("Photon OS root authentication", "Root password:", secret=True) == "VMware01!"


def test_console_top_authentication_failure_is_visible(monkeypatch):
    """Verify that console top authentication failure is visible.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
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
    """Verify that console shell is audited and returns to curses.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    console = CursesConsole.__new__(CursesConsole)
    events: list[object] = []
    console.message = ""
    console.message_error = False
    console._run_interactive = lambda command, label: events.append((command, label)) or 0
    monkeypatch.setattr(appliance_console, "record_console_shell", lambda action: events.append(action))

    console.show_shell()

    assert events == ["open", (["/usr/bin/bash", "--login"], "Bash console"), "close"]


def test_console_management_rows_use_stable_table_columns():
    """Verify that console management rows use stable table columns."""
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
    """Verify that console help pages cover status keys navigation and safety."""
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
    """Verify that console help modal pages forward and closes."""
    keys = iter([343, 343, 343, 343, 343])
    framed_titles: list[str] = []

    class FakeWindow:
        """Represent fake window."""
        def keypad(self, _enabled):
            """Return keypad.

            Args:
                _enabled: Whether the associated resource or behavior is enabled.
            """
            return None

        def erase(self):
            """Return erase."""
            return None

        def bkgd(self, *_args):
            """Return bkgd.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return None

        def box(self):
            """Return box."""
            return None

        def addnstr(self, row, _column, value, *_args):
            """Handle addnstr.

            Args:
                row: Persistent database row affected by the operation.
                _column: Column supplied to the test scenario.
                value: Candidate value consumed by addnstr.
                *_args: Additional positional arguments accepted by the callable.
            """
            if row == 0:
                framed_titles.append(value)

        def refresh(self):
            """Return refresh."""
            return None

        def getch(self):
            """Return getch."""
            return next(keys)

    class FakeCurses:
        """Represent fake curses.

        Attributes:
            A_BOLD: Symbolic value representing 1.
            KEY_F1: Symbolic value representing 265.
            KEY_RESIZE: Symbolic value representing 410.
            KEY_LEFT: Symbolic value representing 260.
            KEY_RIGHT: Symbolic value representing 261.
            KEY_UP: Symbolic value representing 259.
            KEY_DOWN: Symbolic value representing 258.
            KEY_PPAGE: Symbolic value representing 339.
            KEY_NPAGE: Symbolic value representing 338.
            KEY_BTAB: Symbolic value representing 353.
            KEY_ENTER: Symbolic value representing 343.
        """
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
            """Return color pair.

            Args:
                value: Candidate value consumed by color pair.
            """
            return value

        @staticmethod
        def newwin(*_args):
            """Return newwin.

            Args:
                *_args: Additional positional arguments accepted by the callable.
            """
            return FakeWindow()

    console = CursesConsole.__new__(CursesConsole)
    console.curses = FakeCurses
    console.stdscr = SimpleNamespace(getmaxyx=lambda: (30, 80))

    console.show_help()

    assert len(framed_titles) == len(appliance_console.HELP_PAGES)
    assert "Console help 1/5 - Screen overview" in framed_titles[0]
    assert "Console help 5/5 - Recovery and safety" in framed_titles[-1]


def test_console_footer_includes_help_and_compact_power_label():
    """Verify that console footer includes help and compact power label."""
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


def test_console_first_boot_review_renders_branded_recovery_state(monkeypatch):
    """Verify the full-screen console names first-time network review explicitly.

    Args:
        monkeypatch: Pytest helper used to replace console status loading.
    """
    rendered: list[str] = []
    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(A_BOLD=1, color_pair=lambda value: value)
    console.message = ""
    console.message_error = False
    console._safe_add = lambda _row, _column, value, *_args: rendered.append(value)
    console._fill_line = lambda *_args: None
    console._refresh_screen = lambda: None
    monkeypatch.setattr(appliance_console, "_package_version", lambda: "0.9.95")
    review = appliance_console.FirstBootNetworkReview(
        error="Management gateway must be on-link for the configured prefix.",
        ipv4_method="static",
        ipv4_cidr="192.168.1.254/32",
        gateway="192.168.1.1",
        ipv6_mode="disabled",
        ipv6_cidr="",
        ipv6_gateway="",
        dns_servers=("192.168.1.2",),
        fqdn="appliance.atlaso.internal",
    )

    console._draw_first_boot_network_review(review, 30, 80)

    text = "\n".join(rendered)
    assert "Atlaso Appliance 0.9.95" in text
    assert "First-time initialization" in text
    assert "Network configuration requires review" in text
    assert "Press F2 or Enter" in text
    assert "<F2> Review network" in text


def test_console_first_boot_initialization_locks_privileged_actions(monkeypatch):
    """Verify tty1 explicitly renders the locked pre-customization state.

    Args:
        monkeypatch: Pytest helper used to replace the displayed package version.
    """
    rendered: list[str] = []
    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(A_BOLD=1, color_pair=lambda value: value)
    console._safe_add = lambda _row, _column, value, *_args: rendered.append(value)
    console._fill_line = lambda *_args: None
    console._refresh_screen = lambda: None
    monkeypatch.setattr(appliance_console, "_package_version", lambda: "0.9.96")

    console._draw_first_boot_initializing(30)

    text = "\n".join(rendered)
    assert "First-time initialization" in text
    assert "Privileged console actions remain locked" in text
    assert "<F1> Help" in text
    assert "<F2>" not in text
    assert "<F4>" not in text
    assert "<F12>" not in text


def test_console_first_boot_access_persists_until_acknowledged(tmp_path, monkeypatch):
    """Verify the one-time envelope survives redraws and explicit acknowledgement removes it.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace the fixed runtime path.
    """

    access_path = tmp_path / "first-boot-access.json"
    access_path.write_text(
        json.dumps(
            {
                "username": "admin",
                "password": "A!a1-admin-once",
                "root_password": "A!a1-root-once",
                "ssh_host_key": "ssh-ed25519 AAAAhostkey",
            }
        ),
        encoding="utf-8",
    )
    access_path.chmod(0o600)
    monkeypatch.setattr(appliance_console, "FIRST_BOOT_ACCESS_PATH", access_path)
    monkeypatch.setattr(appliance_console, "_first_boot_access_owner_is_root", lambda _metadata: True)

    access = appliance_console.load_first_boot_access()
    assert access is not None
    assert appliance_console.load_first_boot_access() == access

    appliance_console.acknowledge_first_boot_access()

    assert appliance_console.load_first_boot_access() is None
    assert not access_path.exists()


def test_console_draws_first_boot_access_acknowledgement(monkeypatch):
    """Verify the transient access screen names every value and its destructive acknowledgement.

    Args:
        monkeypatch: Pytest helper used to replace the displayed package version.
    """

    rendered: list[str] = []
    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(A_BOLD=1, color_pair=lambda value: value)
    console._safe_add = lambda _row, _column, value, *_args: rendered.append(value)
    console._fill_line = lambda *_args: None
    console._refresh_screen = lambda: None
    monkeypatch.setattr(appliance_console, "_package_version", lambda: "0.9.220")
    access = appliance_console.FirstBootAccess(
        username="admin",
        password="A!a1-admin-once",
        root_password="A!a1-root-once",
        ssh_host_key="ssh-ed25519 AAAAhostkey",
    )

    console._draw_first_boot_access(access, 30, 80)

    text = "\n".join(rendered)
    assert "Record this one-time access information" in text
    assert "Administrator: admin" in text
    assert "Administrator password:" in text
    assert "A!a1-admin-once" in text
    assert "Root password:" in text
    assert "A!a1-root-once" in text
    assert "ssh-ed25519 AAAAhostkey" in text
    assert "<Enter> Acknowledge" in text


def test_console_first_boot_access_wraps_generated_passwords_at_minimum_width(monkeypatch):
    """Render complete generated credentials on the supported 72-column console.

    Args:
        monkeypatch: Pytest helper used to replace the displayed package version.
    """

    rendered: list[tuple[int, int, str]] = []
    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(A_BOLD=1, color_pair=lambda value: value)
    console._safe_add = lambda row, column, value, *_args: rendered.append((row, column, value))
    console._fill_line = lambda *_args: None
    console._refresh_screen = lambda: None
    monkeypatch.setattr(appliance_console, "_package_version", lambda: "0.9.223")
    admin_password = "A" * 47
    root_password = "R" * 47
    access = appliance_console.FirstBootAccess(
        username="admin",
        password=admin_password,
        root_password=root_password,
        ssh_host_key="ssh-ed25519 " + "K" * 68,
    )

    console._draw_first_boot_access(access, 22, 72)

    assert "".join(value for row, _column, value in rendered if row in {9, 10}) == admin_password
    assert "".join(value for row, _column, value in rendered if row in {12, 13}) == root_password
    assert all(len(value) <= 72 - column - 1 for _row, column, value in rendered)


def test_console_first_boot_lock_ignores_privileged_action_keys(tmp_path, monkeypatch):
    """Verify pre-customization key handling cannot enter privileged workflows.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace first-boot state loading.
    """
    lock_path = tmp_path / "initializing"
    lock_path.touch()
    keys = iter((4, 12, 2))
    called: list[str] = []
    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(
        KEY_F1=1,
        KEY_F2=2,
        KEY_F3=3,
        KEY_F4=4,
        KEY_F12=12,
        KEY_RESIZE=99,
        KEY_ENTER=10,
    )
    console.stdscr = SimpleNamespace(getch=lambda: next(keys))
    console.draw_main = lambda: None
    console._recovery_redraws = lambda _last_refresh: 0
    console.show_help = lambda: called.append("help")
    console.customize = lambda: called.append("customize")
    console.show_authenticated_top = lambda: called.append("top")
    console.show_shell = lambda: called.append("shell")
    console.power_menu = lambda: called.append("power")
    monkeypatch.setattr(appliance_console, "FIRST_BOOT_INITIALIZATION_LOCK_PATH", lock_path)
    monkeypatch.setattr(appliance_console, "load_first_boot_network_review", lambda: None)

    with pytest.raises(StopIteration):
        console.run()

    assert called == []


def test_console_non_ovf_completion_restores_ordinary_actions(tmp_path, monkeypatch):
    """Verify no-envelope cleanup leaves the normal tty1 workflow usable.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest helper used to replace first-boot state loading.
    """
    lock_path = tmp_path / "initializing"
    called: list[str] = []
    keys = iter((2,))
    console = CursesConsole.__new__(CursesConsole)
    console.curses = SimpleNamespace(
        KEY_F1=1,
        KEY_F2=2,
        KEY_F3=3,
        KEY_F4=4,
        KEY_F12=12,
        KEY_RESIZE=99,
        KEY_ENTER=10,
    )
    console.stdscr = SimpleNamespace(getch=lambda: next(keys))
    console.draw_main = lambda: None
    console._recovery_redraws = lambda _last_refresh: []
    console.customize = lambda: called.append("customize")
    console.show_help = lambda: called.append("help")
    console.show_authenticated_top = lambda: called.append("top")
    console._require_authentication = lambda: False
    console.power_menu = lambda: called.append("power")
    monkeypatch.setattr(appliance_console, "FIRST_BOOT_INITIALIZATION_LOCK_PATH", lock_path)
    monkeypatch.setattr(appliance_console, "load_first_boot_network_review", lambda: None)

    with pytest.raises(StopIteration):
        console.run()

    assert called == ["customize"]


def test_console_appliance_services_use_full_catalog_and_optional_units(monkeypatch):
    """Verify that console appliance services use full catalog and optional units.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui

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
                "LoadState": "not-found" if unit == "atlaso-kmip.service" else "loaded",
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
    """Verify that console enabled optional service without unit is unavailable.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui

    rows = [
        {"service": service_id, "enabled": service_id == "kms", "running": False}
        for _label, service_id, _unit in appliance_console.SERVICE_CATALOG
    ]
    monkeypatch.setattr(ui, "services_template_context", lambda db: {"service_rows": rows})
    monkeypatch.setattr(appliance_console, "_systemd_unit_states", lambda units: {})

    statuses = appliance_console._appliance_service_statuses(SimpleNamespace(), firewall_enabled=False)

    assert next(status for status in statuses if status.label == "KMS / KMIP").display_label == "? on"


def test_console_service_rows_fit_normal_tty_and_compact_summary_reports_exceptions():
    """Verify that console service rows fit normal tty and compact summary reports exceptions."""
    services = (
        ServiceStatus("Atlaso", "atlaso.service", "loaded", "enabled", "active"),
        ServiceStatus("LDAP", "slapd.service", "loaded", "enabled", "failed"),
        ServiceStatus("KMS", "atlaso-kmip.service", "not-found", "", "inactive"),
        ServiceStatus("Firewall", "atlaso-firewall.service", "loaded", "enabled", "active", False),
    )

    assert CursesConsole._service_cell(services[0], 38) == "Atlaso                ▶ on"
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
    """Verify that console has no dedicated time service surface."""
    source = Path(appliance_console.__file__).read_text(encoding="utf-8")
    for forbidden in ("NtpSettings", "validate_ntp_servers", "configure_ntp", '"NTP servers"'):
        assert forbidden not in source
    assert '{"ntpd"}' not in source


def test_console_restores_main_surface_before_reopening_parent_menu():
    """Verify that console restores main surface before reopening parent menu."""
    console = CursesConsole.__new__(CursesConsole)
    console._force_clear = False
    draws: list[bool] = []
    console.draw_main = lambda: draws.append(console._force_clear)

    console._restore_main_surface()

    assert draws == [True]


def test_console_authentication_is_requested_for_each_menu_entry(monkeypatch):
    """Verify that console authentication is requested for each menu entry.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
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
    """Verify that console firewall toggle persists desired state and selects only firewall.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import FirewallSettings

    selected: list[set[str]] = []
    monkeypatch.setattr(appliance_console, "_submit_console_apply", lambda unit_ids, **kwargs: selected.append(unit_ids) or "job_firewall")

    assert configure_firewall(False) == "job_firewall"
    with SessionLocal() as db:
        firewall = db.scalar(select(FirewallSettings))
        assert firewall is not None
        assert firewall.enabled is False
    assert selected == [{"firewall"}]


def test_console_management_correction_reconciles_firewall_bootstrap_and_settings(client, monkeypatch):
    """Verify that management correction recovers the complete front door in order.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    events: list[tuple[str, object]] = []

    def fake_submit(unit_ids, **_kwargs):
        """Record one scoped console apply submission.

        Args:
            unit_ids: Apply unit identifiers selected by the console.
            **_kwargs: Additional submission options ignored by the test.
        """
        events.append(("apply", set(unit_ids)))
        return f"job_{len([event for event in events if event[0] == 'apply'])}"

    monkeypatch.setattr(appliance_console, "_submit_console_apply", fake_submit)
    monkeypatch.setattr(
        appliance_console,
        "_recover_management_plane",
        lambda stage: events.append(("recover", stage)),
    )

    result = appliance_console.configure_management(
        "dhcp",
        "",
        "",
        "disabled",
        "",
        "",
        "192.0.2.53",
    )

    assert result == "tasks job_1 and job_2"
    assert events == [
        ("apply", {"network", "firewall"}),
        ("recover", "Network and Firewall were applied"),
        ("apply", {"appliance_settings"}),
        ("recover", "Appliance Settings were applied"),
    ]


def test_console_management_recovery_reports_the_failed_layer(monkeypatch):
    """Verify that constrained recovery failures remain actionable.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    monkeypatch.setattr(
        appliance_console,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "validating nginx configuration failed"),
    )

    with pytest.raises(
        ConsoleOperationError,
        match="Network and Firewall were applied, but management-plane recovery failed: validating nginx",
    ):
        appliance_console._recover_management_plane("Network and Firewall were applied")


def test_console_power_task_is_committed_before_real_helper_invocation(client, monkeypatch):
    """Verify that console power task is committed before real helper invocation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    observed: list[tuple[list[str], str, str]] = []

    def fake_run(command, **kwargs):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
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
    """Verify that forced real apply seam rejects non console jobs.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.ui import run_appliance_apply_job

    with SessionLocal() as db:
        db.add(Job(id="job_not_console", type="appliance-apply", status=JobStatus.PENDING.value, created_by="admin"))
        db.commit()

    with pytest.raises(ValueError, match="restricted to local console"):
        run_appliance_apply_job("job_not_console", force_real=True)


def test_console_settings_apply_does_not_predict_management_restart(client, monkeypatch):
    """Verify forced-real console tasks wait for helper restart confirmation.

    Args:
        client: HTTP test client used to initialize an isolated database.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui as ui_module
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    selected = [{"id": "appliance_settings", "label": "Appliance Settings"}]
    payload = {
        "selected_units": ["appliance_settings"],
        "skipped_changed_units": [],
        "captured_units": [{"unit_id": "appliance_settings"}],
        "units": [],
        "dry_run": False,
        "source": "local_appliance_console",
    }
    captured_results = []

    monkeypatch.setattr(ui_module, "appliance_apply_units", lambda _db: [])
    monkeypatch.setattr(
        appliance_console,
        "_captured_apply_payload",
        lambda _units, _selected_ids: (selected, payload),
    )

    def complete_job(job_id: str, *, force_real: bool) -> None:
        """Capture the committed task context and mark the fake execution successful.

        Args:
            job_id: Persisted Appliance Apply task identifier.
            force_real: Whether the console requested the constrained real adapter seam.
        """
        assert force_real is True
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            assert job is not None
            captured_results.append(json.loads(job.result or "{}"))
            job.status = JobStatus.SUCCEEDED.value
            db.commit()

    monkeypatch.setattr(ui_module, "run_appliance_apply_job", complete_job)

    appliance_console._submit_console_apply({"appliance_settings"})

    assert "management_status_transition" not in captured_results[0]


def test_console_vcf_apply_waits_for_the_complete_download_queue(client):
    """Verify console apply participates in the queue-wide VCFDT admission gate.

    Args:
        client: HTTP test client used to initialize an isolated database.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    with SessionLocal() as db:
        db.add(
            Job(
                id="job_console_queue_guard",
                type="vcf-depot-download",
                status=JobStatus.PENDING.value,
                vcf_depot_operation=True,
                vcf_depot_profile_id=41,
                created_by="admin",
            )
        )
        db.commit()

    with pytest.raises(ConsoleOperationError, match="job_console_queue_guard.*pending"):
        appliance_console._submit_console_apply({"vcf_offline_depot"})

    with SessionLocal() as db:
        assert db.query(Job).filter(Job.type == "appliance-apply").count() == 0


def test_console_desired_state_edit_is_rejected_before_commit_when_apply_is_active(client):
    """Verify that console desired state edit is rejected before commit when apply is active.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import FirewallSettings, Job, JobStatus

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
    """Verify that console systemd unit replaces only tty1."""
    unit = Path("image/common/systemd/atlaso-console.service").read_text(encoding="utf-8")
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    manager = Path("image/common/systemd/atlaso-console-manager.conf").read_text(encoding="utf-8")
    assert "TTYPath=/dev/tty1" in unit
    assert "Conflicts=getty@tty1.service" in unit
    assert "After=local-fs.target systemd-vconsole-setup.service" in unit
    assert "Before=atlaso-data-disks.service" in unit
    assert "systemd-networkd.service" not in unit
    assert "getty@tty2" not in unit
    assert "systemctl mask getty@tty1.service" in provision
    assert "systemctl enable atlaso-console.service" in provision
    assert "getty@tty2" not in provision
    assert 'run_tdnf "Photon appliance package installation"' in provision
    assert "python3-curses" in provision and "procps-ng" in provision
    assert "ShowStatus=no" in manager
    assert "CtrlAltDelBurstAction=none" in manager
    assert "systemctl mask --force ctrl-alt-del.target" in provision
    assert "/etc/systemd/system.conf.d/atlaso-console.conf" in provision
    deploy = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    assert "systemctl restart atlaso-console.service" in deploy
    assert "systemctl is-active atlaso-console.service" in deploy
    assert "/etc/systemd/system.conf.d/atlaso-console.conf" in deploy
    assert "systemctl daemon-reexec" in deploy
    assert "systemctl mask --force ctrl-alt-del.target" in deploy


def test_console_service_isolation_preserves_console_network_and_firewall(monkeypatch, tmp_path, capsys):
    """Verify that console service isolation preserves console network and firewall.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
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
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(helper, "_run", fake_run)
    assert helper._handle_console("disable-services", []) == 0
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert {row["unit"] for row in saved["units"]} == set(helper.CONSOLE_MANAGED_SERVICE_UNITS)
    assert all(command[:3] == ["systemctl", "disable", "--now"] for command in commands)
    flattened = " ".join(" ".join(command) for command in commands)
    assert "atlaso-console.service" not in flattened
    assert "systemd-networkd.service" not in flattened
    assert "atlaso-firewall.service" not in flattened
    output = capsys.readouterr().out
    assert "management networking" in output


def test_console_service_restore_uses_saved_enable_and_active_state(monkeypatch, tmp_path):
    """Verify that console service restore uses saved enable and active state.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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
    """Verify that console service restore keeps snapshot when restoration is incomplete.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
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


def test_console_management_plane_recovery_retries_bootstrap_and_verifies_readiness(monkeypatch, tmp_path, capsys):
    """Verify that the helper repairs bootstrap and proves stable loopback readiness.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    marker = tmp_path / "first-boot-https.applied"
    include = tmp_path / "atlaso.conf"
    management_config = tmp_path / "management.conf"
    certificate = tmp_path / "certificate.pem"
    key = tmp_path / "private-key.pem"
    include.write_text(
        "include /etc/atlaso/nginx/sites.d/*.conf;\n",
        encoding="utf-8",
    )
    marker.write_text("", encoding="utf-8")
    management_config.write_text("", encoding="utf-8")
    monkeypatch.setattr(helper, "FIRST_BOOT_HTTPS_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_config)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in {"curl", "nginx"} else None,
    )
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return deterministic recovery command results.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command == ["systemctl", "restart", helper.FIRST_BOOT_HTTPS_UNIT]:
            certificate.write_text("certificate", encoding="utf-8")
            key.write_text("key", encoding="utf-8")
            management_config.write_text(
                "\n".join(
                    [
                        "listen 443 ssl default_server;",
                        f"ssl_certificate {certificate};",
                        f"ssl_certificate_key {key};",
                        "proxy_pass http://127.0.0.1:8000;",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            marker.write_text(helper.FIRST_BOOT_HTTPS_MARKER_TEXT, encoding="utf-8")
        if command and command[0] == "/usr/bin/curl":
            status = "308" if command[-1] == "http://127.0.0.1/" else "200"
            return subprocess.CompletedProcess(command, 0, status, "")
        return subprocess.CompletedProcess(command, 0, "active\n", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_console("recover-management-plane", []) == 0
    output = capsys.readouterr().out
    assert '"management_plane": "ready"' in output
    assert '"bootstrap_retried": true' in output
    assert '"management_https_enabled": true' in output
    assert ["systemctl", "reset-failed", helper.FIRST_BOOT_HTTPS_UNIT] in commands
    assert ["systemctl", "restart", helper.FIRST_BOOT_HTTPS_UNIT] in commands
    assert ["/usr/bin/nginx", "-t"] in commands
    assert ["systemctl", "enable", "nginx.service", "atlaso.service"] in commands
    assert ["systemctl", "reload", "nginx.service"] in commands
    assert ["systemctl", "is-active", "nginx.service", "atlaso.service"] in commands


def test_console_management_plane_recovery_verifies_http_only_mode(monkeypatch, tmp_path, capsys):
    """Verify that recovery accepts the applied HTTP-only management contract.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    marker = tmp_path / "first-boot-https.applied"
    marker.write_text(helper.FIRST_BOOT_HTTPS_MARKER_TEXT, encoding="utf-8")
    include = tmp_path / "atlaso.conf"
    include.write_text(
        "include /etc/atlaso/nginx/sites.d/*.conf;\n",
        encoding="utf-8",
    )
    management_config = tmp_path / "management.conf"
    management_config.write_text(
        "listen 80 default_server;\nproxy_pass http://127.0.0.1:8000;\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "FIRST_BOOT_HTTPS_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_config)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in {"curl", "nginx"} else None,
    )
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Return successful HTTP-only recovery results.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command and command[0] == "/usr/bin/curl":
            return subprocess.CompletedProcess(command, 0, "200", "")
        return subprocess.CompletedProcess(command, 0, "active\n", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_console("recover-management-plane", []) == 0
    output = capsys.readouterr().out
    assert '"management_https_enabled": false' in output
    assert '"nginx HTTP readiness": "200"' in output
    curl_urls = [command[-1] for command in commands if command and command[0] == "/usr/bin/curl"]
    assert "http://127.0.0.1/openapi.json" in curl_urls
    assert all(not url.startswith("https://") for url in curl_urls)


def test_console_management_plane_recovery_stops_after_nginx_validation_failure(monkeypatch, tmp_path, capsys):
    """Verify that invalid nginx configuration prevents service reload and readiness claims.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    marker = tmp_path / "first-boot-https.applied"
    marker.write_text(helper.FIRST_BOOT_HTTPS_MARKER_TEXT, encoding="utf-8")
    include = tmp_path / "atlaso.conf"
    include.write_text(
        "include /etc/atlaso/nginx/sites.d/*.conf;\n",
        encoding="utf-8",
    )
    management_config = tmp_path / "management.conf"
    management_config.write_text(
        "listen 80 default_server;\nproxy_pass http://127.0.0.1:8000;\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "FIRST_BOOT_HTTPS_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_config)
    monkeypatch.setattr(helper.shutil, "which", lambda name: f"/usr/bin/{name}")
    commands: list[list[str]] = []

    def fake_run(command: list[str]) -> subprocess.CompletedProcess[str]:
        """Fail nginx validation and record all attempted commands.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        if command == ["/usr/bin/nginx", "-t"]:
            return subprocess.CompletedProcess(command, 1, "", "nginx syntax invalid")
        return subprocess.CompletedProcess(command, 0, "active\n", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    assert helper._handle_console("recover-management-plane", []) == 1
    error = capsys.readouterr().err
    assert "validating nginx configuration failed" in error
    assert ["systemctl", "reload", "nginx.service"] not in commands
    assert ["systemctl", "start", "nginx.service"] not in commands
