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


def synthetic_root_owned_publication(monkeypatch, directory):
    """Model root ownership only inside a synthetic private receipt filesystem.

    Args:
        monkeypatch: Restore filesystem metadata interception after the test.
        directory: Isolated publication directory whose real modes and identity remain checked.
    """
    import os

    original_lstat = Path.lstat
    original_fstat = os.fstat

    def fstat(descriptor):
        """Model ownership only for descriptors bound to original receipt file identities.

        Args:
            descriptor: Open descriptor whose identity and permission bits remain authoritative.
        """
        metadata = original_fstat(descriptor)
        for path in directory.iterdir():
            candidate = original_lstat(path)
            if (metadata.st_dev, metadata.st_ino) == (candidate.st_dev, candidate.st_ino):
                fields = list(metadata)
                fields[4] = 0
                return os.stat_result(fields)
        return metadata

    def lstat(path, *args, **kwargs):
        """Retain real metadata except the synthetic publication owner's UID.

        Args:
            path: Path being inspected.
            *args: Positional arguments forwarded to the real filesystem call.
            **kwargs: Keyword arguments forwarded to the real filesystem call.
        """
        metadata = original_lstat(path, *args, **kwargs)
        if path == directory or directory in path.parents:
            fields = list(metadata)
            fields[4] = 0
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(os, "fstat", fstat)


@pytest.mark.parametrize("mode", [0o700, 0o750])
def test_synthetic_publication_ownership_preserves_private_mode_guard(monkeypatch, tmp_path, mode):
    """Exercise the POSIX owner guard on every host without suppressing permission checks.

    Args:
        monkeypatch: Model only synthetic filesystem metadata and POSIX availability.
        tmp_path: Isolated receipt directory and unrelated metadata control.
        mode: Private mode or a group-readable directory that must remain refused.
    """
    import os
    import stat

    loader = importlib.machinery.SourceFileLoader("atlaso_receipt_owner_guard", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    directory = tmp_path / "publication"
    directory.mkdir()
    original_lstat = Path.lstat

    def metadata(path, *args, **kwargs):
        """Model an unprivileged test directory with its supplied permission bits.

        Args:
            path: Filesystem path whose metadata is requested.
            *args: Positional filesystem options.
            **kwargs: Keyword filesystem options.
        """
        result = original_lstat(path, *args, **kwargs)
        if path == directory:
            fields = list(result)
            fields[0] = stat.S_IFDIR | mode
            fields[4] = 1001
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(bootstrap.os, "getuid", lambda: 1001, raising=False)
    monkeypatch.setattr(bootstrap, "CONSOLE_PUBLICATION_DIRECTORY", directory)
    before = directory.lstat()
    outside = tmp_path.lstat()
    with pytest.raises(ValueError, match="private and root-owned"):
        bootstrap.console_publication_path("job_owner_guard")
    synthetic_root_owned_publication(monkeypatch, directory)
    after = directory.lstat()
    assert after.st_uid == 0
    assert (after.st_mode, after.st_dev, after.st_ino) == (before.st_mode, before.st_dev, before.st_ino)
    assert tmp_path.lstat() == outside
    receipt = directory / "receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    with receipt.open("rb") as stream:
        owned = os.fstat(stream.fileno())
        real = original_lstat(receipt)
        assert owned.st_uid == 0
        assert (owned.st_mode, owned.st_dev, owned.st_ino) == (real.st_mode, real.st_dev, real.st_ino)
    unrelated = tmp_path / "unrelated.json"
    unrelated.write_text("{}", encoding="utf-8")
    with unrelated.open("rb") as stream:
        assert os.fstat(stream.fileno()).st_uid == original_lstat(unrelated).st_uid
    if mode == 0o700:
        assert bootstrap.console_publication_path("job_owner_guard") == directory / "job_owner_guard.publication.json"
    else:
        with pytest.raises(ValueError, match="private and root-owned"):
            bootstrap.console_publication_path("job_owner_guard")


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
        "_refresh_management_addresses",
        lambda interface_id, **kwargs: events.append(("observe", interface_id)),
    )
    monkeypatch.setattr(
        appliance_console,
        "_recover_management_plane",
        lambda stage, **kwargs: events.append(("recover", stage)),
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
    assert events[1][0] == "observe"
    assert isinstance(events[1][1], int)
    assert [event for event in events if event[0] != "observe"] == [
        ("apply", {"network", "firewall"}),
        ("recover", "Network and Firewall were applied"),
        ("apply", {"appliance_settings"}),
        ("recover", "Appliance Settings were applied"),
    ]


def test_console_management_refreshes_changed_dhcp_lease_before_recovery_and_settings(client, monkeypatch):
    """Use fresh production discovery before either dependent capture.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace host operations and timing with controlled test observations.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services import networking

    with SessionLocal() as db:
        interface = appliance_console._management_interface(db)
        interface.host_ip_cidr = "192.168.167.172/24"
        interface.mac_address = "00:50:56:12:34:56"
        db.commit()

    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", lambda **kwargs: [
        networking.HostPhysicalInterface(
            name="eth0", mac_address="00:50:56:12:34:56", driver=None, speed=None,
            host_ip_cidr="192.168.167.172/24", host_dhcp_ip_cidr="192.168.167.174/24",
            host_mtu=1500, host_admin_state="up", oper_state="up",
        ),
    ])
    captures = []

    def capture(stage, **kwargs):
        """Record the acquired address at each dependent capture.

        Args:
            stage: Recovery stage recorded with the captured management address.
            **kwargs: Completed Network task binding for certificate recovery.
        """
        with SessionLocal() as db:
            interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
            captures.append((stage, interface.host_ip_cidr))

    def submit(units, **kwargs):
        """Observe address state before Appliance Settings apply.

        Args:
            units: Apply units selected by the console.
            **kwargs: Completed Network snapshot supplied for dependent capture.
        """
        if units == {"appliance_settings"}:
            capture("settings")
        else:
            with SessionLocal() as db:
                db.add(appliance_console.Job(
                    id="job_test", type="appliance-apply", status="succeeded", created_by="console:root",
                    result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview":
                        networking.render_network_config(
                            interfaces=list(db.scalars(select(PhysicalInterface))),
                            vlans=list(db.scalars(select(appliance_console.VlanInterface))),
                        )}]}),
                ))
                db.commit()
        return "job_test"

    monkeypatch.setattr(appliance_console, "_submit_console_apply", submit)
    monkeypatch.setattr(appliance_console, "_recover_management_plane", capture)
    appliance_console.configure_management("dhcp", "", "", "disabled", "", "", "192.0.2.53")

    assert captures == [
        ("Network and Firewall were applied", "192.168.167.174/24"),
        ("settings", "192.168.167.174/24"),
        ("Appliance Settings were applied", "192.168.167.174/24"),
    ]
    with SessionLocal() as db:
        interface = appliance_console._management_interface(db)
        assert interface.ipv4_method == "dhcp"
        assert interface.ip_cidr is None
        assert interface.desired_state_source == "console"


@pytest.mark.parametrize("observed,count,ipv6_enabled,observed6,desired", [
    ("192.168.167.172/24", 0, False, None, None),
    (None, 1, False, None, None),
    ("169.254.1.2/16", 1, False, None, None),
    ("::1/128", 1, False, None, None),
    ("192.168.167.174/24", 1, True, "fe80::1/64", None),
    ("192.168.167.172/24", 1, False, None, "192.168.167.173/24"),
])
def test_console_management_observation_rejects_unverified_addresses(
    client, monkeypatch, observed, count, ipv6_enabled, observed6, desired,
):
    """An outage, wrong family, incomplete dual stack or stale static address cannot pass.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace host operations and timing with controlled test observations.
        observed: Observed IPv4 CIDR, or no acquired address.
        count: Whether discovery returns the matching interface.
        ipv6_enabled: Whether the desired management configuration requires IPv6.
        observed6: Observed IPv6 CIDR, or no acquired address.
        desired: Desired static IPv4 CIDR, or dynamic addressing.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.networking import HostPhysicalInterface

    with SessionLocal() as db:
        interface = appliance_console._management_interface(db)
        interface.ip_cidr = desired
        interface.ipv6_enabled = ipv6_enabled
        interface.ipv6_cidr = None
        interface_id = interface.id
        name, mac = interface.name, interface.mac_address
        db.commit()
    observation = HostPhysicalInterface(
        name=name, mac_address=mac, driver=None, speed=None, host_ip_cidr=observed,
        host_ipv6_cidr=observed6, host_mtu=1500, host_admin_state="up", oper_state="up",
    )
    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", lambda **kwargs: [observation] if count else [])
    with pytest.raises(ConsoleOperationError, match="fresh management address observation"):
        appliance_console._refresh_management_addresses(interface_id, timeout=0)


def test_console_completed_snapshot_clears_disabled_lingering_ipv6(client, monkeypatch):
    """Disabled IPv6 cannot enter certificate addresses after completed Network observation.

    Args:
        client: Initialized appliance database.
        monkeypatch: Replace native discovery with a lingering disabled-family address.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, PhysicalInterface, VlanInterface
    from atlaso.app.services.networking import HostPhysicalInterface
    from atlaso.app.ui import management_ui_addresses

    with SessionLocal() as db:
        interface = appliance_console._management_interface(db)
        interface.ipv4_method = "dhcp"
        interface.ip_cidr = None
        interface.ipv6_enabled = False
        interface.ipv6_cidr = None
        interface.host_ipv6_cidr = "2001:db8::172/64"
        interface_id, name, mac = interface.id, interface.name, interface.mac_address
        db.flush()
        preview = appliance_console.render_network_config(
            interfaces=list(db.scalars(select(PhysicalInterface))), vlans=list(db.scalars(select(VlanInterface))))
        db.add(Job(id="job_disabled_ipv6", type="appliance-apply", status=JobStatus.SUCCEEDED.value, created_by="local_appliance_console",
                   result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]})))
        db.commit()
    observation = HostPhysicalInterface(name=name, mac_address=mac, driver=None, speed=None,
        host_ip_cidr="192.168.167.174/24", host_dhcp_ip_cidr="192.168.167.174/24",
        host_ipv6_cidr="2001:db8::172/64", host_dynamic_ipv6_cidr="2001:db8::173/64",
        host_mtu=1500, host_admin_state="up", oper_state="up")
    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", lambda **kwargs: [observation])
    appliance_console._refresh_management_addresses(interface_id, network_job_id="job_disabled_ipv6", timeout=0)
    with SessionLocal() as db:
        assert db.get(PhysicalInterface, interface_id).host_ipv6_cidr is None
        assert "2001:db8::172" not in management_ui_addresses(db)
        assert "2001:db8::173" not in management_ui_addresses(db)
        # A stale row from a pre-upgrade inventory sync is also excluded at projection.
        db.get(PhysicalInterface, interface_id).host_ipv6_cidr = "2001:db8::172/64"
        assert "2001:db8::172" not in management_ui_addresses(db)


def test_console_management_waits_for_both_dynamic_families(client, monkeypatch):
    """A later complete observation can finish acquisition without inventing desired addresses.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace host operations and timing with controlled test observations.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.networking import HostPhysicalInterface

    with SessionLocal() as db:
        interface = appliance_console._management_interface(db)
        interface.ip_cidr = None
        interface.ipv4_method = "dhcp"
        interface.ipv6_enabled = True
        interface.ipv6_cidr = None
        interface_id = interface.id
        name, mac = interface.name, interface.mac_address
        db.commit()
    observation = HostPhysicalInterface(
        name=name, mac_address=mac, driver=None, speed=None, host_ip_cidr="192.168.167.174/24",
        host_dhcp_ip_cidr="192.168.167.174/24", host_mtu=1500, host_admin_state="up", oper_state="up",
    )
    from dataclasses import replace

    observations = iter([
        replace(observation, host_dhcp_ip_cidr=None, host_ipv6_cidr="2001:db8::172/64", host_dynamic_ipv6_cidr="2001:db8::174/64"),
        observation,
        replace(observation, host_ipv6_cidr="2001:db8::172/64"),
        replace(observation, host_ipv6_cidr="2001:db8::172/64", host_dynamic_ipv6_cidr="2001:db8::174/64",
                host_dynamic_ipv6_cidrs=("2001:db8::174/64", "2001:db8:2::174/64")),
    ])
    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", lambda **kwargs: [next(observations)])
    monkeypatch.setattr(appliance_console.time, "sleep", lambda seconds: None)
    appliance_console._refresh_management_addresses(interface_id)
    with SessionLocal() as db:
        interface = db.get(appliance_console.PhysicalInterface, interface_id)
        assert interface.ip_cidr is None
        assert interface.ipv6_cidr is None
        assert interface.host_ipv6_cidr == "2001:db8::174/64"
        assert interface.host_ipv6_cidrs == ["2001:db8::174/64", "2001:db8:2::174/64"]
        from atlaso.app.services.appliance_settings import management_ui_context
        from atlaso.app.ui import managed_ca_certificate_specs, management_ui_addresses

        expected = {"192.168.167.174", "2001:db8::174", "2001:db8:2::174"}
        assert set(management_ui_addresses(db)) == expected
        assert set(management_ui_context([interface], [])["addresses"]) == expected
        spec = next(spec for spec in managed_ca_certificate_specs(db) if spec.owner == "appliance:https")
        assert set(spec.ip_addresses) == expected
        from atlaso.app.services.settings_archive import (
            _model_kwargs,
            export_settings_archive,
        )

        archive = export_settings_archive(db, actor="admin")
        assert all("host_ipv6_cidrs" not in row for row in archive["data"]["physical_interfaces"])
        assert "host_ipv6_cidrs" not in _model_kwargs(appliance_console.PhysicalInterface, {"host_ipv6_cidrs": interface.host_ipv6_cidrs})


def test_console_management_observation_outage_preserves_entire_database(client, monkeypatch):
    """An empty discovery cannot erase NIC intent or unrelated bindings during retry.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace host operations and timing with controlled test observations.
    """
    from sqlalchemy import select

    from atlaso.app.database import Base, SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        for interface in db.scalars(select(PhysicalInterface)):
            interface.inventory_source = "host"
            interface.desired_state_source = "console"
        interface_id = appliance_console._management_interface(db).id
        db.commit()
        before = {table.name: list(db.execute(table.select())) for table in Base.metadata.sorted_tables}
    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", lambda **kwargs: [])
    with pytest.raises(ConsoleOperationError, match="fresh management address observation"):
        appliance_console._refresh_management_addresses(interface_id, timeout=0)
    with SessionLocal() as db:
        after = {table.name: list(db.execute(table.select())) for table in Base.metadata.sorted_tables}
    assert after == before


@pytest.mark.parametrize("admin_state,oper_state", [("down", "up"), ("up", "down"), ("up", "unknown")])
def test_console_management_rejects_retained_address_on_down_link(client, monkeypatch, admin_state, oper_state):
    """A retained usable address cannot prove a disconnected link is ready.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace host operations and timing with controlled test observations.
        admin_state: Observed host administrative link state.
        oper_state: Observed native operational link state.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.networking import HostPhysicalInterface

    with SessionLocal() as db:
        interface = appliance_console._management_interface(db)
        interface_id = interface.id
        old_cidr = interface.host_ip_cidr
        observation = HostPhysicalInterface(
            name=interface.name, mac_address=interface.mac_address, driver=None, speed=None,
            host_ip_cidr=interface.ip_cidr, host_mtu=1500, host_admin_state=admin_state, oper_state=oper_state,
        )
    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", lambda **kwargs: [observation])
    with pytest.raises(ConsoleOperationError, match="fresh management address observation"):
        appliance_console._refresh_management_addresses(interface_id, timeout=0)
    with SessionLocal() as db:
        assert db.get(appliance_console.PhysicalInterface, interface_id).host_ip_cidr == old_cidr


def test_console_management_bounds_stalled_discovery_by_remaining_deadline(client, monkeypatch):
    """The production subprocess receives the remaining budget and a stall fails closed.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace host operations and timing with controlled test observations.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import networking

    with SessionLocal() as db:
        interface_id = appliance_console._management_interface(db).id
    clock = iter([0, 10, 30])
    monkeypatch.setattr(
        appliance_console, "time", SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda seconds: None),
    )
    timeouts = []

    def stalled_run(command, **kwargs):
        """Simulate a native discovery timeout at the supplied deadline.

        Args:
            command: Native discovery command whose timeout is simulated.
            **kwargs: Subprocess options containing the remaining acquisition timeout.
        """
        timeouts.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(networking.subprocess, "run", stalled_run)
    with pytest.raises(ConsoleOperationError, match="fresh management address observation"):
        appliance_console._refresh_management_addresses(interface_id)
    assert timeouts == [20]


def test_console_management_observation_failure_stops_dependent_work(client, monkeypatch):
    """Network success must not become a false recovery-success audit on observation failure.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace host operations and timing with controlled test observations.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent

    selected = []
    monkeypatch.setattr(appliance_console, "_submit_console_apply", lambda units: selected.append(units) or "job_network")

    def fail_observation(interface_id, **kwargs):
        """Stop dependent work with a controlled observation failure.

        Args:
            interface_id: Stable identity of the selected management interface.
            **kwargs: Completed-task observation options.
        """
        raise ConsoleOperationError("fresh management address observation failed")

    monkeypatch.setattr(appliance_console, "_refresh_management_addresses", fail_observation)
    monkeypatch.setattr(appliance_console, "_recover_management_plane", lambda stage, **kwargs: pytest.fail("recovery started before observation"))
    with pytest.raises(ConsoleOperationError, match="fresh management address observation"):
        appliance_console.configure_management("dhcp", "", "", "disabled", "", "", "192.0.2.53")
    assert selected == [{"network", "firewall"}]
    with SessionLocal() as db:
        assert not db.scalars(select(AuditEvent).where(AuditEvent.action == "console_recover_management_plane")).all()


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


@pytest.mark.parametrize("owned_dns_only", [True, False])
def test_console_ntp_apply_includes_only_owned_dns_dependency(client, monkeypatch, owned_dns_only):
    """Console NTP Apply captures DNS only when its own records caused the delta.

    Args:
        client: HTTP test client.
        monkeypatch: Pytest fixture used to replace dependencies.
        owned_dns_only: Whether the DNS delta contains only NTP-owned changes.
    """
    from atlaso.app import appliance_console, ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    units = [
        {
            "id": unit_id, "label": unit_id, "changed": True,
            "validation_errors": [], "validation_warnings": [],
            "snapshot_hash": unit_id, "summary": [], "config_path": "/tmp/example",
            "config_preview": unit_id, "config_diff": "",
        }
        for unit_id in ("dnsmasq", "ntpd")
    ]
    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db: units)
    monkeypatch.setattr(ui, "ntp_owned_dns_is_only_pending_change", lambda _db, _unit: owned_dns_only)

    def finish(job_id, *, force_real):
        """Mark the captured Apply job complete.

        Args:
            job_id: Identifier of the captured Apply job.
            force_real: Whether real execution was requested.
        """
        assert force_real is True
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            job.status = JobStatus.SUCCEEDED.value
            db.commit()

    monkeypatch.setattr(ui, "run_appliance_apply_job", finish)
    job_id = appliance_console._submit_console_apply({"ntpd"})
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        assert json.loads(job.result)["selected_units"] == (
            ["ntpd", "dnsmasq"] if owned_dns_only else ["ntpd"]
        )


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
    assert "Environment=ATLASO_HELPER_USE_SYSTEMD_RUN=1" in unit
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


@pytest.mark.parametrize("network_job_id", [None, "job_completed_network"])
@pytest.mark.parametrize("already_complete", [False, True])
@pytest.mark.parametrize("http_port,https_port", [(80, 443), (8080, 8443)])
@pytest.mark.parametrize("slow_recovery", [False, True])
def test_console_management_plane_recovery_retries_bootstrap_and_verifies_readiness(monkeypatch, tmp_path, capsys, network_job_id, already_complete, http_port, https_port, slow_recovery):
    """Verify that the helper repairs bootstrap and proves stable loopback readiness.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
        network_job_id: Exact completed Network binding, or ordinary recovery.
        already_complete: First boot completed before the management address changed.
        http_port: Preserved applied HTTP port.
        https_port: Preserved applied HTTPS port.
        slow_recovery: Bootstrap and readiness together exceed the previous service cap.
    """
    helper = load_helper_module()
    clock = [0.0]
    if slow_recovery:
        monkeypatch.setattr(helper.time, "monotonic", lambda: clock[0])
    marker = tmp_path / "first-boot-https.applied"
    main_config = tmp_path / "nginx.conf"
    main_config.write_text(
        "http {\n  include /etc/nginx/conf.d/atlaso.conf;\n}\n",
        encoding="utf-8",
    )
    include = tmp_path / "atlaso.conf"
    management_config = tmp_path / "management.conf"
    certificate = tmp_path / "certificate.pem"
    key = tmp_path / "private-key.pem"
    include.write_text(helper.FIRST_BOOT_HTTPS_INCLUDE_TEXT, encoding="utf-8")
    marker.write_text("", encoding="utf-8")
    management_config.write_text("", encoding="utf-8")
    monkeypatch.setattr(helper, "FIRST_BOOT_HTTPS_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main_config)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_config)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in {"curl", "nginx"} else None,
    )
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(helper, "_console_management_leaf_is_active", lambda expected: True)
    monkeypatch.setattr(helper, "_console_publication_fingerprint", lambda job: ("a" * 64, "b" * 64))
    commands: list[list[str]] = []
    monkeypatch.setattr(helper, "CONSOLE_BOOTSTRAP_BINDING_DIRECTORY", tmp_path / "binding")
    monkeypatch.setattr(helper, "fcntl", None)
    bootstrap_command = ["systemctl", "restart", helper.FIRST_BOOT_HTTPS_UNIT]

    def fake_run(command: list[str], *, timeout=None) -> subprocess.CompletedProcess[str]:
        """Return deterministic recovery command results.

        Args:
            command: Command and arguments to execute.
            timeout: Bounded systemd command deadline.
        """
        commands.append(command)
        if "--acknowledge-console-publication" in command:
            # The same serialized binding must survive beyond bootstrap through acknowledgement.
            binding = helper.CONSOLE_BOOTSTRAP_BINDING_DIRECTORY / "network.env"
            assert binding.read_text(encoding="utf-8") == f"ATLASO_CONSOLE_NETWORK_JOB_ID={network_job_id}\n"
        if command[:2] == ["systemctl", "show"]:
            return subprocess.CompletedProcess(command, 0, "ActiveState=active\nSubState=exited\nJob=0\n", "")
        if command == bootstrap_command:
            if slow_recovery:
                clock[0] += 35
            binding = helper.CONSOLE_BOOTSTRAP_BINDING_DIRECTORY / "network.env"
            if network_job_id:
                assert binding.read_text() == f"ATLASO_CONSOLE_NETWORK_JOB_ID={network_job_id}\n"
            else:
                assert not binding.exists()
            include.write_text(helper.FIRST_BOOT_HTTPS_INCLUDE_TEXT, encoding="utf-8")
            certificate.write_text("certificate", encoding="utf-8")
            key.write_text("key", encoding="utf-8")
            management_config.write_text(
                "\n".join(
                    [
                        f"listen {https_port} ssl default_server;",
                        f"listen {http_port} default_server;",
                        f"ssl_certificate {certificate};",
                        f"ssl_certificate_key {key};",
                        "proxy_pass http://127.0.0.1:8000;",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            if network_job_id is None:
                marker.write_text(helper.FIRST_BOOT_HTTPS_MARKER_TEXT, encoding="utf-8")
        if command and command[0] == "/usr/bin/curl":
            http_suffix = f":{http_port}" if http_port != 80 else ""
            https_suffix = f":{https_port}" if https_port != 443 else ""
            expected = {
                f"http://127.0.0.1{http_suffix}/": "308",
                f"https://127.0.0.1{https_suffix}/openapi.json": "200",
                "http://127.0.0.1:8000/openapi.json": "200",
            }
            assert command[-1] in expected
            if slow_recovery:
                # The real curl boundary cannot consume twelve seconds: each
                # probe has --max-time=3 and a remaining-budget process timeout.
                assert timeout is not None and timeout <= 3
                clock[0] += timeout
            return subprocess.CompletedProcess(command, 0, expected[command[-1]], "")
        return subprocess.CompletedProcess(command, 0, "active\n", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    if already_complete:
        with helper._console_bootstrap_binding(network_job_id):
            fake_run(bootstrap_command)
        commands.clear()
        clock[0] = 0.0

    assert helper._handle_console("recover-management-plane", [network_job_id] if network_job_id else []) == 0
    output = capsys.readouterr().out
    assert '"management_plane": "ready"' in output
    retried = not already_complete or network_job_id is not None
    assert f'"bootstrap_retried": {str(retried).lower()}' in output
    assert '"management_https_enabled": true' in output
    assert (["systemctl", "reset-failed", helper.FIRST_BOOT_HTTPS_UNIT] in commands) is retried
    assert (bootstrap_command in commands) is retried
    assert not (helper.CONSOLE_BOOTSTRAP_BINDING_DIRECTORY / "network.env").exists()
    assert ["/usr/bin/nginx", "-t"] in commands
    assert ["systemctl", "enable", "nginx.service", "atlaso.service"] in commands
    assert ["systemctl", "reload", "nginx.service"] in commands
    assert ["systemctl", "is-active", "nginx.service", "atlaso.service"] in commands
    acknowledgements = [command for command in commands if "--acknowledge-console-publication" in command]
    assert bool(acknowledgements) is (network_job_id is not None)
    if network_job_id is not None:
        assert marker.read_text() == ""
        if slow_recovery:
            assert clock[0] == 80
            assert clock[0] < helper.CONSOLE_RECOVERY_OPERATION_SECONDS < helper.CONSOLE_RECOVERY_RUNTIME_SECONDS


@pytest.mark.parametrize("network_job_id", [None, "job_http_ready"])
@pytest.mark.parametrize("final_result", [0, 2])
@pytest.mark.parametrize("http_port", [80, 8080])
def test_console_management_plane_recovery_verifies_http_only_mode(monkeypatch, tmp_path, capsys, network_job_id, final_result, http_port):
    """Verify that recovery accepts the applied HTTP-only management contract.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
        network_job_id: Completed task binding or ordinary recovery.
        final_result: Post-readiness admitted binding accepts or refuses later drift.
        http_port: Preserved applied HTTP listener port.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "CONSOLE_BOOTSTRAP_BINDING_DIRECTORY", tmp_path / "binding")
    monkeypatch.setattr(helper, "fcntl", None)
    marker = tmp_path / "first-boot-https.applied"
    main_config = tmp_path / "nginx.conf"
    main_config.write_text(
        "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n",
        encoding="utf-8",
    )
    marker.write_text(helper.FIRST_BOOT_HTTPS_MARKER_TEXT, encoding="utf-8")
    include = tmp_path / "atlaso.conf"
    include.write_text(helper.FIRST_BOOT_HTTPS_INCLUDE_TEXT, encoding="utf-8")
    management_config = tmp_path / "management.conf"
    management_config.write_text(
        f"listen {http_port} default_server;\nproxy_pass http://127.0.0.1:8000;\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "FIRST_BOOT_HTTPS_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main_config)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_config)
    monkeypatch.setattr(
        helper.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in {"curl", "nginx"} else None,
    )
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_options) -> subprocess.CompletedProcess[str]:
        """Return successful HTTP-only recovery results.

        Args:
            **_options: Additional subprocess options unused by this test double.
            command: Command and arguments to execute.
        """
        if "--verify-console-http" in command:
            assert len([row for row in commands if row[0] == "/usr/bin/curl"]) == 10
            assert command[-2:] == [network_job_id, str(http_port)]
            return subprocess.CompletedProcess(command, final_result, "", "")
        commands.append(command)
        if command[:2] == ["systemctl", "show"]:
            return subprocess.CompletedProcess(command, 0, "ActiveState=active\nSubState=exited\nJob=0\n", "")
        if command and command[0] == "/usr/bin/curl":
            return subprocess.CompletedProcess(command, 0, "200", "")
        return subprocess.CompletedProcess(command, 0, "active\n", "")

    monkeypatch.setattr(helper, "_run", fake_run)

    outcome = helper._recover_console_management_plane(network_job_id=network_job_id)
    assert outcome == (1 if network_job_id and final_result else 0)
    output = capsys.readouterr().out
    if outcome:
        assert '"management_plane": "ready"' not in output
        return
    assert '"management_https_enabled": false' in output
    assert '"nginx HTTP readiness": "200"' in output
    curl_urls = [command[-1] for command in commands if command and command[0] == "/usr/bin/curl"]
    origin = "http://127.0.0.1" + (f":{http_port}" if http_port != 80 else "")
    assert origin + "/openapi.json" in curl_urls
    assert all(not url.startswith("https://") for url in curl_urls)


def test_console_management_plane_recovery_stops_after_nginx_validation_failure(monkeypatch, tmp_path, capsys):
    """Verify that invalid nginx configuration prevents service reload and readiness claims.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "CONSOLE_BOOTSTRAP_BINDING_DIRECTORY", tmp_path / "binding")
    monkeypatch.setattr(helper, "fcntl", None)
    marker = tmp_path / "first-boot-https.applied"
    main_config = tmp_path / "nginx.conf"
    main_config.write_text(
        "http {\n  include /etc/nginx/conf.d/atlaso.conf;\n}\n",
        encoding="utf-8",
    )
    marker.write_text(helper.FIRST_BOOT_HTTPS_MARKER_TEXT, encoding="utf-8")
    include = tmp_path / "atlaso.conf"
    include.write_text(helper.FIRST_BOOT_HTTPS_INCLUDE_TEXT, encoding="utf-8")
    management_config = tmp_path / "management.conf"
    management_config.write_text(
        "listen 80 default_server;\nproxy_pass http://127.0.0.1:8000;\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "FIRST_BOOT_HTTPS_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main_config)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_config)
    monkeypatch.setattr(helper.shutil, "which", lambda name: f"/usr/bin/{name}")
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_options) -> subprocess.CompletedProcess[str]:
        """Fail nginx validation and record all attempted commands.

        Args:
            **_options: Additional subprocess options unused by this test double.
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


def test_console_first_boot_https_contract_rejects_commented_include(monkeypatch, tmp_path):
    """Reject an include path that nginx sees only inside a comment.

    Args:
        monkeypatch: Pytest fixture used to replace deployed filesystem paths.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    marker = tmp_path / "first-boot-https.applied"
    main_config = tmp_path / "nginx.conf"
    main_config.write_text(
        "http {\n  # include /etc/nginx/conf.d/atlaso.conf;\n}\n",
        encoding="utf-8",
    )
    include = tmp_path / "atlaso.conf"
    management_config = tmp_path / "management.conf"
    marker.write_text(helper.FIRST_BOOT_HTTPS_MARKER_TEXT, encoding="utf-8")
    include.write_text(
        "# include /etc/atlaso/nginx/sites.d/*.conf;\n",
        encoding="utf-8",
    )
    management_config.write_text(
        "listen 80 default_server;\nproxy_pass http://127.0.0.1:8000;\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "FIRST_BOOT_HTTPS_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main_config)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_config)

    assert helper._console_first_boot_https_contract_is_complete() is False


def test_console_first_boot_https_contract_accepts_annotated_active_outer_include(
    monkeypatch,
    tmp_path,
):
    """Accept a valid active outer include followed by a same-line comment.

    Args:
        monkeypatch: Pytest fixture used to replace deployed filesystem paths.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    marker = tmp_path / "first-boot-https.applied"
    main_config = tmp_path / "nginx.conf"
    include = tmp_path / "atlaso.conf"
    management_config = tmp_path / "management.conf"
    marker.write_text(helper.FIRST_BOOT_HTTPS_MARKER_TEXT, encoding="utf-8")
    main_config.write_text(
        "http {\n  include /etc/nginx/conf.d/atlaso.conf; # managed sites\n}\n",
        encoding="utf-8",
    )
    include.write_text(helper.FIRST_BOOT_HTTPS_INCLUDE_TEXT, encoding="utf-8")
    management_config.write_text(
        "listen 80 default_server;\nproxy_pass http://127.0.0.1:8000;\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "FIRST_BOOT_HTTPS_MARKER_PATH", marker)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main_config)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management_config)

    assert helper._console_first_boot_https_contract_is_complete() is True


@pytest.mark.parametrize("pending_cidr", [None, "192.168.167.175/24"])
def test_console_observation_uses_applied_snapshot_with_pending_edits(client, monkeypatch, pending_cidr):
    """Verify an applied static address independently and retain newer pending intent.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace native discovery with the applied static address.
        pending_cidr: New static address, or a newer DHCP selection.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.networking import (
        HostPhysicalInterface,
        render_network_config,
    )

    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        target.ipv4_method = "static"
        target.ip_cidr = "192.168.167.173/24"
        target.ipv6_enabled = False
        target.ipv6_cidr = None
        applied_preview = render_network_config(
            interfaces=list(db.scalars(select(appliance_console.PhysicalInterface))),
            vlans=list(db.scalars(select(appliance_console.VlanInterface))),
        )
        target.ipv4_method = "static" if pending_cidr else "dhcp"
        target.ip_cidr = pending_cidr
        interface_id = target.id
        observed = HostPhysicalInterface(
            name=target.name, mac_address=target.mac_address, driver=None, speed=None,
            host_ip_cidr="192.168.167.173/24", host_mtu=1500, host_admin_state="up", oper_state="up",
        )
        db.add(appliance_console.Job(
            id="job_applied", type="appliance-apply", status="succeeded", created_by="console:root",
            result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": applied_preview}]}),
        ))
        db.commit()
    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", lambda **kwargs: [observed])
    with pytest.raises(ConsoleOperationError, match="newer address edits remain pending"):
        appliance_console._refresh_management_addresses(interface_id, network_job_id="job_applied", timeout=0)
    with SessionLocal() as db:
        target = db.get(appliance_console.PhysicalInterface, interface_id)
        assert target.ip_cidr == pending_cidr
        assert target.ipv4_method == ("static" if pending_cidr else "dhcp")
        assert target.host_ip_cidr == "192.168.167.173/24"


@pytest.mark.parametrize("edit", ["address", "admin_down"])
def test_console_recovery_interval_edit_stops_settings_capture(client, monkeypatch, edit):
    """Reject unapplied management changes made during recovery before Settings admission.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace privileged execution while preserving real Settings admission.
        edit: Pending address or administrative-state change during recovery.
    """
    from atlaso.app import ui as ui_module
    from atlaso.app.database import SessionLocal

    if edit == "admin_down":
        with SessionLocal() as db:
            db.add(appliance_console.PhysicalInterface(
                name="eth-console-alternate", mac_address="02:00:00:00:05:33", role="access", mode="access",
                admin_state="up", oper_state="up", ip_cidr="192.0.2.1/24", access_management_ui_enabled=True,
            ))
            db.commit()
    submit_settings = appliance_console._submit_console_apply

    def submit(units, **kwargs):
        """Simulate Network completion and retain the production Settings admission gate.

        Args:
            units: Requested scoped apply units.
            **kwargs: Completed Network task binding for Settings.
        """
        if units == {"appliance_settings"}:
            return submit_settings(units, **kwargs)
        with SessionLocal() as db:
            network = next(unit for unit in ui_module.appliance_apply_units(db) if unit["id"] == "network")
            db.add(appliance_console.Job(
                id="job_network_snapshot", type="appliance-apply", status="succeeded", created_by="console:root",
                result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": network["config_preview"]}]}),
            ))
            db.commit()
        return "job_network_snapshot"

    def recover(stage, **kwargs):
        """Save another management address while the recovery interval is active.

        Args:
            stage: Description of the initial correction phase.
            **kwargs: Completed Network task binding for certificate recovery.
        """
        with SessionLocal() as db:
            target = appliance_console._management_interface(db)
            if edit == "address":
                target.ipv4_method = "static"
                target.ip_cidr = "192.168.167.175/24"
            else:
                target.admin_state = "down"
            db.commit()

    monkeypatch.setattr(appliance_console, "_submit_console_apply", submit)
    monkeypatch.setattr(appliance_console, "_refresh_management_addresses", lambda *args, **kwargs: None)
    monkeypatch.setattr(appliance_console, "_recover_management_plane", recover)
    monkeypatch.setattr(ui_module, "run_appliance_apply_job", lambda *args, **kwargs: pytest.fail("Settings executed"))
    with pytest.raises(ConsoleOperationError, match="changed during recovery"):
        appliance_console.configure_management("dhcp", "", "", "disabled", "", "", "192.0.2.53")
    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        if edit == "address":
            assert target.ip_cidr == "192.168.167.175/24"
        else:
            assert target.admin_state == "down"
        assert db.query(appliance_console.Job).count() == 1


def test_console_observation_serializes_pending_decision(client, monkeypatch):
    """Detect an edit admitted before the observation lock and retain it as pending.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Interleave a writer before observation acquires its real lock.
    """
    from sqlalchemy.orm import Session

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.networking import HostPhysicalInterface

    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        target.ipv4_method = "static"
        target.ip_cidr = "192.168.167.173/24"
        target.ipv6_enabled = False
        target.ipv6_cidr = None
        interface_id = target.id
        observed = HostPhysicalInterface(
            name=target.name, mac_address=target.mac_address, driver=None, speed=None,
            host_ip_cidr=target.ip_cidr, host_mtu=1500, host_admin_state="up", oper_state="up",
        )
        db.commit()
    lock = appliance_console.acquire_network_objects_write_lock
    refresh = Session.refresh
    commit = Session.commit
    observation = {}

    def acquire(db):
        """Model a completed writer before observation wins lock admission.

        Args:
            db: Observation transaction awaiting writer admission.
        """
        with SessionLocal() as writer:
            writer.get(appliance_console.PhysicalInterface, interface_id).ip_cidr = "192.168.167.175/24"
            writer.commit()
        lock(db)
        observation["db"] = db
        observation["transaction"] = db.get_transaction()

    def locked_refresh(db, instance, *args, **kwargs):
        """Require the final refresh to run inside the admitted transaction.

        Args:
            db: Session refreshing the observed interface.
            instance: Interface being refreshed.
            *args: Additional refresh arguments.
            **kwargs: Additional refresh options.
        """
        assert db is observation["db"]
        assert db.get_transaction() is observation["transaction"]
        return refresh(db, instance, *args, **kwargs)

    def locked_commit(db):
        """Require observation publication to retain the same transaction.

        Args:
            db: Session publishing verified host addresses.
        """
        if db is observation.get("db"):
            assert db.get_transaction() is observation["transaction"]
            observation["committed"] = True
        return commit(db)

    monkeypatch.setattr(appliance_console, "acquire_network_objects_write_lock", acquire)
    def discover(**kwargs):
        """Require native observation inside the admitted writer transaction.

        Args:
            **kwargs: Additional options supplied by the production caller.
        """
        assert observation["db"].get_transaction() is observation["transaction"]
        return [observed]

    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", discover)
    monkeypatch.setattr(Session, "refresh", locked_refresh)
    monkeypatch.setattr(Session, "commit", locked_commit)
    with pytest.raises(ConsoleOperationError, match="newer address edits remain pending"):
        appliance_console._refresh_management_addresses(interface_id, timeout=0)
    assert observation["committed"] is True
    with SessionLocal() as db:
        target = db.get(appliance_console.PhysicalInterface, interface_id)
        assert target.ip_cidr == "192.168.167.175/24"
        assert target.host_ip_cidr == "192.168.167.173/24"


@pytest.mark.parametrize("edit", ["vlan", "admin_down", "unchanged"])
def test_console_observation_rejects_other_management_path_edits(client, monkeypatch, edit):
    """Reject changes outside the observed address tuple before dependent recovery.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Supply native evidence for the completed management address.
        edit: Pending VLAN/admin-state change, or unchanged completed paths.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.networking import (
        HostPhysicalInterface,
        render_network_config,
    )

    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        target.ipv4_method = "static"
        target.ip_cidr = "192.168.167.173/24"
        target.ipv6_enabled = False
        target.ipv6_cidr = None
        interface_id = target.id
        observed = HostPhysicalInterface(
            name=target.name, mac_address=target.mac_address, driver=None, speed=None,
            host_ip_cidr=target.ip_cidr, host_mtu=1500, host_admin_state="up", oper_state="up",
        )
        preview = render_network_config(interfaces=list(db.scalars(select(appliance_console.PhysicalInterface))),
                                        vlans=list(db.scalars(select(appliance_console.VlanInterface))))
        db.add(appliance_console.Job(
            id="job_completed_paths", type="appliance-apply", status="succeeded", created_by="console:root",
            result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]}),
        ))
        db.commit()
        if edit == "vlan":
            db.add(appliance_console.VlanInterface(
                name=f"{target.name}.533", parent_interface=target.name, vlan_id=533,
                ip_cidr="192.0.2.1/24", enabled=True, access_management_ui_enabled=True,
            ))
        elif edit == "admin_down":
            target.admin_state = "down"
        db.commit()
    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", lambda **kwargs: [observed])
    if edit == "unchanged":
        appliance_console._refresh_management_addresses(interface_id, network_job_id="job_completed_paths", timeout=0)
    else:
        with pytest.raises(ConsoleOperationError, match="Certificate recovery and Appliance Settings were not started"):
            appliance_console._refresh_management_addresses(interface_id, network_job_id="job_completed_paths", timeout=0)
    with SessionLocal() as db:
        target = db.get(appliance_console.PhysicalInterface, interface_id)
        assert target.host_ip_cidr == "192.168.167.173/24"
        if edit == "vlan":
            assert db.scalar(select(appliance_console.VlanInterface).where(
                appliance_console.VlanInterface.vlan_id == 533)).access_management_ui_enabled is True
        elif edit == "admin_down":
            assert target.admin_state == "down"


@pytest.mark.parametrize("edit", ["address", "vlan", "admin_down", "unchanged"])
@pytest.mark.parametrize("bound_job", [True, False])
def test_console_bootstrap_binds_certificate_issuance_to_completed_network(client, monkeypatch, edit, bound_job):
    """Reject intervening pending paths before issuance and retain the lock through commit.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace certificate issuance while recording its transaction ownership.
        edit: Desired path change admitted before bootstrap, or unchanged completed state.
        bound_job: Use the console task binding or ordinary saved Network baseline.
    """
    import importlib.machinery
    import importlib.util

    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.networking import render_network_config

    loader = importlib.machinery.SourceFileLoader("atlaso_console_bound_bootstrap", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        preview = render_network_config(interfaces=list(db.scalars(select(appliance_console.PhysicalInterface))),
                                        vlans=list(db.scalars(select(appliance_console.VlanInterface))))
        db.add(appliance_console.Job(
            id="job_certificate_binding", type="appliance-apply", status="succeeded", created_by="console:root",
            result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]}),
        ))
        db.commit()
        if edit == "address":
            target.ip_cidr = "192.0.2.175/24"
        elif edit == "admin_down":
            target.admin_state = "down"
        elif edit == "vlan":
            db.add(appliance_console.VlanInterface(
                name=f"{target.name}.534", parent_interface=target.name, vlan_id=534,
                ip_cidr="198.51.100.1/24", enabled=True, access_management_ui_enabled=True,
            ))
        db.commit()
    events = []
    lock = bootstrap.acquire_network_objects_write_lock
    commit = Session.commit
    ownership = {}

    def acquire(db):
        """Record the real admitted Network writer transaction.

        Args:
            db: Bootstrap transaction acquiring writer admission.
        """
        lock(db)
        ownership["db"] = db
        ownership["transaction"] = db.get_transaction()
        events.append("lock")

    def issue(db, *, commit, managed_owners):
        """Assert issuance occurs without releasing Network writer admission.

        Args:
            db: Admitted bootstrap transaction.
            commit: Whether issuance may release the guarded transaction.
            managed_owners: Optional management-only issuance selection.
        """
        assert commit is False
        assert managed_owners == ({"appliance:https"} if bound_job else None)
        assert db.get_transaction() is ownership["transaction"]
        events.append("issue")
        return []

    def record_commit(db):
        """Assert issuance publication retains the admitted transaction.

        Args:
            db: Bootstrap transaction committing the issued certificate state.
        """
        assert db is ownership["db"] and db.get_transaction() is ownership["transaction"]
        events.append("commit")
        return commit(db)

    monkeypatch.setattr(bootstrap, "acquire_network_objects_write_lock", acquire)
    monkeypatch.setattr(bootstrap, "ensure_ca_state", issue)
    monkeypatch.setattr(bootstrap, "load_appliance_apply_baselines", lambda db: {"network": {"config_preview": preview}})
    monkeypatch.setattr(Session, "commit", record_commit)
    with SessionLocal() as db:
        errors = bootstrap.ensure_recovery_ca_state(db, "job_certificate_binding" if bound_job else None)
    assert bool(errors) is (edit != "unchanged")
    assert events == (["lock", "issue", "commit"] if edit == "unchanged" else ["lock"])


def test_completed_bootstrap_refreshes_bound_network_without_first_boot_reconciliation(client, monkeypatch, tmp_path):
    """A completed appliance must reach guarded issuance without resetting pending intent.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace first-boot and certificate filesystem operations.
        tmp_path: Isolate the absent signer staging path.
    """
    import importlib.machinery
    import importlib.util

    loader = importlib.machinery.SourceFileLoader("atlaso_completed_bound_bootstrap", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    monkeypatch.setattr(bootstrap, "first_boot_https_artifacts_are_complete", lambda: True)
    monkeypatch.setattr(bootstrap, "DEVELOPMENT_ROOT_CA_STAGING_PATH", tmp_path / "absent")
    monkeypatch.setattr(bootstrap, "console_publication_path", lambda job: tmp_path / "publication.json")
    monkeypatch.setattr(bootstrap, "import_staged_development_root_ca", lambda *_args: False)

    def reject_first_boot(*_args, **_kwargs):
        """Prevent initialization from overwriting the completed Network state.

        Args:
            *_args: Unused dependency arguments.
            **_kwargs: Unused dependency keywords.
        """
        raise AssertionError("bound recovery performed first-boot reconciliation")

    for name in ("init_db", "seed_initial_data", "sync_host_physical_interfaces"):
        monkeypatch.setattr(bootstrap, name, reject_first_boot)
    called = []

    def guarded_issuance(db, job_id, *, commit, management_snapshot):
        """Stop at the guarded issuance boundary before any filesystem mutation.

        Args:
            db: Existing appliance transaction.
            job_id: Completed task binding reaching the guard.
            commit: Whether guarded issuance may release its transaction.
            management_snapshot: Frozen applied Settings identity.
        """
        called.append(job_id)
        return ["intentional test stop before certificate publication"]

    monkeypatch.setattr(bootstrap, "recovery_root_matches_baseline", lambda db: True)
    monkeypatch.setattr(bootstrap, "load_appliance_apply_baselines", lambda db: {"appliance_settings": {"config_preview": json.dumps({"fqdn": "applied.example.test", "management_https_enabled": True, "web_terminal_enabled": False, "web_terminal_addresses": [], "management_https_cert_path": "/etc/atlaso/https/certs/applied.crt", "management_https_key_path": "/etc/atlaso/https/certs/applied.key"})}})
    monkeypatch.setattr(bootstrap, "ensure_recovery_ca_state", guarded_issuance)
    assert bootstrap.main("job_completed_network") == 2
    assert called == ["job_completed_network"]


@pytest.mark.parametrize("site", ["listen 8080 default_server;\nproxy_pass http://127.0.0.1:8000;\n",
                                  "listen 8443 ssl default_server;\nproxy_pass http://127.0.0.1:8000;\n"])
def test_bound_bootstrap_preserves_applied_front_door(client, monkeypatch, tmp_path, site):
    """Refresh certificates twice without rewriting the saved protocol or listener ports.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Redirect certificate staging and native validation.
        tmp_path: Isolated management configuration and certificate staging.
        site: Applied HTTP-only or custom HTTPS-port configuration.
    """
    import importlib.machinery
    import importlib.util

    loader = importlib.machinery.SourceFileLoader("atlaso_preserved_front_door", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    config = tmp_path / "management.conf"
    config.write_text(site)
    monkeypatch.setattr(bootstrap, "NGINX_MANAGEMENT_PATH", config)
    monkeypatch.setattr(bootstrap, "first_boot_https_artifacts_are_complete", lambda: True)
    monkeypatch.setattr(bootstrap, "CA_STAGED_CONFIG_PATH", str(tmp_path / "ca.json"))
    receipt = tmp_path / "publication.json"
    monkeypatch.setattr(bootstrap, "console_publication_path", lambda job: receipt)
    calls = []
    monkeypatch.setattr(bootstrap, "recovery_root_matches_baseline", lambda db: True)
    monkeypatch.setattr(bootstrap, "load_appliance_apply_baselines", lambda db: {"appliance_settings": {"config_preview": json.dumps({"fqdn": "applied.example.test", "management_https_enabled": True, "web_terminal_enabled": False, "web_terminal_addresses": [], "management_https_cert_path": "/etc/atlaso/https/certs/applied.crt", "management_https_key_path": "/etc/atlaso/https/certs/applied.key"})}})
    monkeypatch.setattr(bootstrap, "record_ca_publication_baseline", lambda *args, **kwargs: None)
    monkeypatch.setattr(bootstrap, "ensure_recovery_ca_state", lambda db, job, **kwargs: calls.append(job) or [])
    monkeypatch.setattr(bootstrap, "render_ca_apply_payload", lambda *_args, **_kwargs: '{"root": {}, "certificates": []}')
    monkeypatch.setattr(bootstrap, "apply_ca_files", lambda *args: 0)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(bootstrap, "run", lambda command: subprocess.CompletedProcess(command, 0, "", ""))
    for _ in range(2):
        assert bootstrap.main("job_completed_network") == 0
        assert config.read_text() == site
    assert calls == ["job_completed_network", "job_completed_network"]


def test_console_bootstrap_timeout_stops_service_before_removing_binding(tmp_path, monkeypatch):
    """Clean a timed-out restart only after systemd proves the service job idle.

    Args:
        tmp_path: Isolated root-private runtime binding directory.
        monkeypatch: Simulate a stalled restart and completed cancellation.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "CONSOLE_BOOTSTRAP_BINDING_DIRECTORY", tmp_path / "binding")
    monkeypatch.setattr(helper, "fcntl", None)
    commands = []

    def run(command, *, timeout):
        """Stall restart and report the systemd stop as completed.

        Args:
            command: Systemd command under test.
            timeout: Required inner deadline below the outer console timeout.
        """
        commands.append(command)
        assert timeout <= 40
        if command[1] == "restart":
            raise subprocess.TimeoutExpired(command, timeout)
        return subprocess.CompletedProcess(command, 0, "ActiveState=inactive\nSubState=dead\nJob=0\n", "")

    monkeypatch.setattr(helper, "_run", run)
    with pytest.raises(ValueError, match="bootstrap timed out"):
        with helper._console_bootstrap_binding("job_completed"):
            helper._console_restart_bootstrap()
    assert ["systemctl", "stop", "--no-block", helper.FIRST_BOOT_HTTPS_UNIT] in commands
    assert not (helper.CONSOLE_BOOTSTRAP_BINDING_DIRECTORY / "network.env").exists()


def test_console_bootstrap_binding_cleans_failure_and_preserves_stale_state(tmp_path, monkeypatch):
    """Release only this invocation's binding and refuse an existing one.

    Args:
        tmp_path: Isolated runtime directory for the test.
        monkeypatch: Replace Linux runtime ownership/flock checks in this pure contract test.
    """
    helper = load_helper_module()
    directory = tmp_path / "binding"
    monkeypatch.setattr(helper, "CONSOLE_BOOTSTRAP_BINDING_DIRECTORY", directory)
    monkeypatch.setattr(helper, "fcntl", None)
    monkeypatch.setattr(helper, "_console_bootstrap_is_idle", lambda: True)
    binding = directory / "network.env"
    with pytest.raises(RuntimeError, match="service dependency failed"):
        with helper._console_bootstrap_binding("job_completed"):
            assert binding.read_text() == "ATLASO_CONSOLE_NETWORK_JOB_ID=job_completed\n"
            raise RuntimeError("service dependency failed")
    assert not binding.exists()
    with pytest.raises(ValueError, match="binding changed"):
        with helper._console_bootstrap_binding("job_completed"):
            replacement = directory / "replacement.env"
            replacement.write_text("ATLASO_CONSOLE_NETWORK_JOB_ID=replacement_job\n")
            replacement.replace(binding)
    assert binding.read_text() == "ATLASO_CONSOLE_NETWORK_JOB_ID=replacement_job\n"
    binding.write_text("ATLASO_CONSOLE_NETWORK_JOB_ID=previous_job\n")
    monkeypatch.setattr(helper, "_console_bootstrap_is_idle", lambda: False)
    with pytest.raises(ValueError, match="previous console bootstrap binding remains"):
        with helper._console_bootstrap_binding("job_completed"):
            pytest.fail("Stale binding was admitted")
    assert binding.read_text() == "ATLASO_CONSOLE_NETWORK_JOB_ID=previous_job\n"
    monkeypatch.setattr(helper, "_console_bootstrap_is_idle", lambda: True)
    with helper._console_bootstrap_binding("job_retry"):
        assert binding.read_text() == "ATLASO_CONSOLE_NETWORK_JOB_ID=job_retry\n"
    assert not binding.exists()


def test_console_recovery_cli_dispatches_completed_task_id(monkeypatch):
    """Exercise the CLI parser with the production console's non-path task argument.

    Args:
        monkeypatch: Replace privileged execution after argument admission.
    """
    helper = load_helper_module()
    calls = []
    monkeypatch.setattr(helper, "_should_run_real_action_with_systemd", lambda action: False)
    monkeypatch.setattr(helper, "_handle_console", lambda action, args: calls.append((action, args)) or 0)
    assert helper.main(["atlaso-helper", "console", "recover-management-plane", "job_0123456789ab", "--real"]) == 0
    assert calls == [("recover-management-plane", ["job_0123456789ab"])]


@pytest.mark.parametrize("ready", [True, False])
@pytest.mark.parametrize("artifacts_complete", [True, False])
@pytest.mark.parametrize("pending", ["service", "certificate", "root", "root_key", "settings", "missing_settings", "missing_paths", "profile_policy", "subject_policy", "legacy_policy", "missing_dynamic_ack", "native_dhcp_ack", "native_slaac_ack", "native_vlan_ack"])
@pytest.mark.parametrize("apply_result", [0, 1])
def test_completed_recovery_publishes_only_management_and_records_exact_baseline(client, monkeypatch, tmp_path, pending, apply_result, artifacts_complete, ready):
    """Keep unrelated intent pending and acknowledge the management leaf only after success.

    Args:
        client: Initialized real database fixture.
        monkeypatch: Replace privileged file publication and nginx validation.
        tmp_path: Isolated synthetic certificate staging.
        pending: Unapplied service hostname, certificate row, or trust-root path edit.
        apply_result: Successful publication or simulated helper failure.
        artifacts_complete: Intact or missing first-boot evidence must use the same recovery path.
        ready: Outer reload/readiness success permits acknowledgement; failure leaves the CA baseline pending.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        ApplianceSettings,
        CaCertificate,
        CaProfile,
        CaSettings,
        LdapSettings,
    )
    from atlaso.app.services.ca import render_ca_apply_payload
    from atlaso.app.services.networking import render_network_config
    from atlaso.app.ui import (
        ensure_ca_state,
        load_appliance_apply_baselines,
        make_appliance_apply_unit,
        save_appliance_apply_baselines,
    )

    loader = importlib.machinery.SourceFileLoader("atlaso_scoped_ca_recovery", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    with SessionLocal() as db:
        appliance = db.scalar(select(ApplianceSettings))
        appliance.fqdn = "management.applied.example.test"
        appliance.web_terminal_enabled = False
        ca = db.scalar(select(CaSettings))
        ca.enabled = True
        ldap = db.scalar(select(LdapSettings))
        ldap.enabled = True
        ldap.ldaps_enabled = True
        ldap.hostname = "ldap.applied.example.test"
        assert ensure_ca_state(db) == []
        certificates = db.scalars(select(CaCertificate).order_by(CaCertificate.common_name)).all()
        public = render_ca_apply_payload(ca, certificates, include_private_keys=False, profiles=db.scalars(select(CaProfile)).all())
        summary = ["service enabled", f"{len(db.scalars(select(CaProfile)).all())} profiles", f"{len(certificates)} certificate requests"]
        bootstrap.record_ca_publication_baseline(db, public, summary, management_only=False)
        db.commit()
        before = load_appliance_apply_baselines(db)["ca"]
        baselines = load_appliance_apply_baselines(db)
        baselines["appliance_settings"] = {"config_preview": json.dumps({
            "fqdn": appliance.fqdn, "management_https_enabled": True,
            "management_public_https_port": 8443 if pending == "settings" else 443,
            "web_terminal_enabled": True, "web_terminal_addresses": ["198.51.100.44"],
            "management_https_cert_path": "/etc/atlaso/https/certs/nginx-previous-hostname.crt",
            "management_https_key_path": "/etc/atlaso/https/certs/nginx-previous-hostname.key",
        })}
        if pending == "missing_settings":
            del baselines["appliance_settings"]
        elif pending == "missing_paths":
            applied_settings = json.loads(baselines["appliance_settings"]["config_preview"])
            del applied_settings["management_https_key_path"]
            baselines["appliance_settings"]["config_preview"] = json.dumps(applied_settings)
        save_appliance_apply_baselines(db, baselines)
        ldap_leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "ldap:ldaps"))
        old_leaf = {column.name: getattr(ldap_leaf, column.name) for column in CaCertificate.__table__.columns}
        if pending == "service":
            ldap.hostname = "ldap.pending.example.test"
        elif pending == "certificate":
            ldap_leaf.common_name = "certificate.pending.example.test"
        elif pending == "profile_policy":
            db.scalar(select(CaProfile).where(CaProfile.name == "VCF service TLS")).validity_days = 7
        elif pending == "subject_policy":
            ca.organization = "Pending organization"
        elif pending == "legacy_policy":
            legacy = json.loads(before["config_preview"])
            del legacy["issuance_policy"]
            baselines["ca"]["config_preview"] = json.dumps(legacy)
            save_appliance_apply_baselines(db, baselines)
            before = load_appliance_apply_baselines(db)["ca"]
        elif pending == "root":
            ca.storage_path = "/etc/atlaso/ca-pending"
        elif pending == "settings":
            appliance.fqdn = "management.pending.example.test"
            appliance.web_terminal_enabled = True
            appliance.web_terminal_interfaces_json = '["pending-interface"]'
        elif pending == "root_key":
            ca.root_private_key_encrypted = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https")).private_key_encrypted
        target = appliance_console._management_interface(db)
        target.ipv4_method = "static"
        target.ip_cidr = "192.0.2.74/24"
        if pending in {"missing_dynamic_ack", "native_dhcp_ack"}:
            target.ipv4_method, target.ip_cidr, target.host_ip_cidr = "dhcp", None, "192.0.2.74/24"
        if pending == "native_slaac_ack":
            target.ipv6_enabled = True
            target.ipv6_cidr = None
            target.host_ipv6_cidr = "2001:db8::74/64"
            target.host_ipv6_cidrs = ["2001:db8::74/64", "2001:db8:1::74/64"]
        native_identity = (target.name, target.mac_address)
        if pending == "native_vlan_ack":
            db.add(appliance_console.PhysicalInterface(name="pr899-https-trunk", mac_address="00:15:5d:aa:bb:41",
                                                      role="access", mode="trunk", admin_state="up", oper_state="up"))
            db.add(appliance_console.VlanInterface(name="pr899-https-trunk.541", parent_interface="pr899-https-trunk",
                                                  vlan_id=541, ip_cidr="198.51.100.41/24", enabled=True,
                                                  access_management_ui_enabled=True))
            db.flush()
        preview = render_network_config(interfaces=list(db.scalars(select(appliance_console.PhysicalInterface))),
                                        vlans=list(db.scalars(select(appliance_console.VlanInterface))))
        db.add(appliance_console.Job(id="job_scoped_ca", type="appliance-apply", status="succeeded", created_by="console:root",
                                    result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]})))
        db.commit()
        expected_leaf = {column.name: getattr(ldap_leaf, column.name) for column in CaCertificate.__table__.columns}
    publication_directory = tmp_path / "publication"
    publication_directory.mkdir(mode=0o700)
    synthetic_root_owned_publication(monkeypatch, publication_directory)
    monkeypatch.setattr(bootstrap, "CONSOLE_PUBLICATION_DIRECTORY", publication_directory)
    stage = tmp_path / "ca.json"
    nginx_config = tmp_path / "nginx.conf"
    nginx_config.write_text("ssl_certificate /etc/atlaso/https/certs/nginx-previous-hostname.crt;\n"
                            "ssl_certificate_key /etc/atlaso/https/certs/nginx-previous-hostname.key;\n")
    captured = []
    ownership = {}
    issue = bootstrap.ensure_recovery_ca_state

    def admitted_issuance(db, job_id, *, commit, management_snapshot):
        """Retain the real writer transaction identity for the publication assertion.

        Args:
            db: Admitted writer transaction.
            job_id: Completed Network task.
            commit: Guarded publication must keep the transaction open.
            management_snapshot: Frozen applied hostname and terminal addresses.
        """
        if pending == "settings":
            # Simulate another Settings save after admission; issuance must never reread it.
            db.scalar(select(ApplianceSettings)).fqdn = "management.concurrent.example.test"
            db.flush()
        result = issue(db, job_id, commit=commit, management_snapshot=management_snapshot)
        ownership["db"] = db
        ownership["transaction"] = db.get_transaction()
        return result

    monkeypatch.setattr(bootstrap, "ensure_recovery_ca_state", admitted_issuance)
    monkeypatch.setattr(bootstrap, "CA_STAGED_CONFIG_PATH", str(stage))

    def publish(owned_path):
        """Interleave ordinary CA staging with the worker-owned publication payload.

        Args:
            owned_path: Private recovery staging artifact passed to the native helper.
        """
        assert ownership["db"].get_transaction() is ownership["transaction"]
        assert ownership["transaction"].is_active
        ownership["staging"] = owned_path
        assert owned_path != stage
        if bootstrap.os.name == "posix":
            assert owned_path.parent.stat().st_mode & 0o077 == 0
        # Ordinary CA Apply can replace and then remove its fixed path during recovery.
        stage.write_text("ordinary CA Apply payload")
        stage.unlink()
        payload = json.loads(owned_path.read_text(encoding="utf-8"))
        leaf = payload["certificates"][0]
        assert "ssl_certificate " + leaf["cert_path"] + ";" in nginx_config.read_text()
        assert "ssl_certificate_key " + leaf["key_path"] + ";" in nginx_config.read_text()
        (tmp_path / "nginx-active-certificate.pem").write_text(leaf["certificate_pem"])
        captured.append(payload)
        return apply_result

    monkeypatch.setattr(bootstrap, "apply_ca_files", publish)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/" + name)
    def validate_active_nginx(command):
        """Check the certificate at the preserved nginx destination, not just syntax.

        Args:
            command: Native nginx validation invocation replaced at the fixture boundary.
        """
        from cryptography import x509

        leaf = x509.load_pem_x509_certificate((tmp_path / "nginx-active-certificate.pem").read_bytes())
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert sans.get_values_for_type(x509.DNSName) == ["management.applied.example.test"]
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(bootstrap, "run", validate_active_nginx)
    monkeypatch.setattr(bootstrap, "first_boot_https_artifacts_are_complete", lambda: artifacts_complete)
    monkeypatch.setattr(bootstrap, "init_db", lambda: pytest.fail("Bound recovery must not reseed first boot"))
    monkeypatch.setattr(bootstrap, "write_nginx_management_config", lambda **kwargs: pytest.fail("Bound recovery must preserve applied nginx settings"))
    result = bootstrap.main("job_scoped_ca")
    if "staging" in ownership:
        assert not ownership["staging"].exists()
        assert not ownership["staging"].parent.exists()
    if pending in {"root", "root_key", "missing_settings", "missing_paths", "profile_policy", "subject_policy", "legacy_policy"}:
        assert result == 2 and captured == [] and not stage.exists()
        with SessionLocal() as db:
            assert load_appliance_apply_baselines(db)["ca"] == before
        return
    assert result == apply_result
    with SessionLocal() as db:
        assert load_appliance_apply_baselines(db)["ca"] == before
    if not apply_result and not ready and pending == "service":
        # A writer admitted after publication must also block late acknowledgement.
        with SessionLocal() as db:
            appliance_console._management_interface(db).ip_cidr = "192.0.2.75/24"
            db.commit()
        assert bootstrap.acknowledge_console_publication("job_scoped_ca", bootstrap.hashlib.sha256((publication_directory / "job_scoped_ca.publication.json").read_bytes()).hexdigest()) == 2
    if not apply_result and not ready and pending == "certificate":
        receipt_path = publication_directory / "job_scoped_ca.publication.json"
        verified_digest = bootstrap.hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        # Equivalent JSON at a replaced receipt must not reuse the earlier served-leaf proof.
        receipt_path.write_bytes(receipt_path.read_bytes() + b"\n")
        assert bootstrap.acknowledge_console_publication("job_scoped_ca", verified_digest) == 2
    if not apply_result and ready and pending == "missing_dynamic_ack":
        with SessionLocal() as db:
            appliance_console._management_interface(db).host_ip_cidr = None
            db.commit()
        digest = bootstrap.hashlib.sha256((publication_directory / "job_scoped_ca.publication.json").read_bytes()).hexdigest()
        assert bootstrap.acknowledge_console_publication("job_scoped_ca", digest) == 2
        with SessionLocal() as db:
            assert load_appliance_apply_baselines(db)["ca"] == before
        return
    if not apply_result and ready and pending == "native_vlan_ack":
        from atlaso.app.services import networking

        receipt_path = publication_directory / "job_scoped_ca.publication.json"
        original = receipt_path.read_bytes()
        digest = bootstrap.hashlib.sha256(original).hexdigest()
        native_rows = [{"ifname": "pr899-https-trunk", "ifindex": 15, "address": "00:15:5d:aa:bb:41",
                        "link_type": "ether", "flags": ["UP"], "operstate": "UP"}]
        def native_run(command, **kwargs):
            """Expose only native VLAN withdrawal while original publication and applied paths stay unchanged.

            Args:
                command: Native command whose execution is modeled.
                **kwargs: Additional options supplied by the production caller.
            """
            assert command == ["ip", "-d", "-j", "address", "show"] and kwargs["timeout"] <= 5
            return subprocess.CompletedProcess(command, 0, json.dumps(native_rows), "")

        monkeypatch.setattr(networking.subprocess, "run", native_run)
        monkeypatch.setattr(bootstrap.ssl, "get_server_certificate",
                            lambda *args, **kwargs: captured[0]["certificates"][0]["certificate_pem"])
        assert bootstrap.acknowledge_console_publication("job_scoped_ca", digest) == 2
        assert receipt_path.read_bytes() == original
        with SessionLocal() as db:
            assert load_appliance_apply_baselines(db)["ca"] == before
        native_rows.append({"ifname": "pr899-https-trunk.541", "link_index": 15, "flags": ["UP"], "operstate": "UP",
                            "linkinfo": {"info_kind": "vlan", "info_data": {"id": 541}},
                            "addr_info": [{"family": "inet", "local": "198.51.100.41", "prefixlen": 24, "scope": "global"}]})
        assert bootstrap.acknowledge_console_publication("job_scoped_ca", digest) == 0
        return
    if not apply_result and ready and pending in {"native_dhcp_ack", "native_slaac_ack"}:
        from dataclasses import replace

        from atlaso.app.services.networking import HostPhysicalInterface

        receipt_path = publication_directory / "job_scoped_ca.publication.json"
        original = receipt_path.read_bytes()
        digest = bootstrap.hashlib.sha256(original).hexdigest()
        host = HostPhysicalInterface(name=native_identity[0], mac_address=native_identity[1], driver=None,
                                     speed=None, host_ip_cidr="192.0.2.74/24", host_mtu=1500,
                                     host_admin_state="up", oper_state="up", host_dhcp_ip_cidr="192.0.2.74/24",
                                     host_dynamic_ipv6_cidrs=("2001:db8::74/64", "2001:db8:1::74/64"))
        def discover(*, timeout, require_success):
            """Attest the native probe's deadline and strict result requirement.

            Args:
                timeout: Bounded native discovery timeout supplied by the caller.
                require_success: Require native discovery to succeed before observation publication.
            """
            assert timeout == 5 and require_success is True
            return [host]

        monkeypatch.setattr(bootstrap, "discover_host_physical_interfaces", discover)
        monkeypatch.setattr(bootstrap.ssl, "get_server_certificate",
                            lambda *args, **kwargs: captured[0]["certificates"][0]["certificate_pem"])
        good = host
        changed = (replace(host, host_dhcp_ip_cidr="192.0.2.75/24") if pending == "native_dhcp_ack"
                   else replace(host, host_dynamic_ipv6_cidrs=("2001:db8:1::74/64",)))
        unavailable = (replace(good, host_dhcp_ip_cidr=None) if pending == "native_dhcp_ack"
                       else replace(good, host_dynamic_ipv6_cidrs=()))
        for candidate in (changed, unavailable, replace(good, oper_state="down"),
                          replace(good, mac_address="00:00:00:00:00:99")):
            host = candidate
            assert bootstrap.acknowledge_console_publication("job_scoped_ca", digest) == 2
            assert receipt_path.read_bytes() == original
            with SessionLocal() as db:
                assert load_appliance_apply_baselines(db)["ca"] == before
        def timed_out(**kwargs):
            """Model native discovery exceeding its bounded budget.

            Args:
                **kwargs: Additional options supplied by the production caller.
            """
            raise subprocess.TimeoutExpired("ip", 5)

        monkeypatch.setattr(bootstrap, "discover_host_physical_interfaces", timed_out)
        assert bootstrap.acknowledge_console_publication("job_scoped_ca", digest) == 2
        host = good
        monkeypatch.setattr(bootstrap, "discover_host_physical_interfaces", discover)
        assert bootstrap.acknowledge_console_publication("job_scoped_ca", digest) == 0
        return
    if not apply_result and ready:
        digest = bootstrap.hashlib.sha256((publication_directory / "job_scoped_ca.publication.json").read_bytes()).hexdigest()
        monkeypatch.setattr(bootstrap.ssl, "get_server_certificate", lambda address, *, timeout:
                            bootstrap.ssl.DER_cert_to_PEM_cert(b"different served leaf"))
        assert bootstrap.acknowledge_console_publication("job_scoped_ca", digest) == 2
        with SessionLocal() as db:
            assert load_appliance_apply_baselines(db)["ca"] == before
        def served_leaf(address, *, timeout):
            """Return the published leaf only at the captured applied listener.

            Args:
                address: Loopback address and applied HTTPS port.
                timeout: Bounded TLS handshake deadline.
            """
            assert address == ("127.0.0.1", 8443 if pending == "settings" else 443)
            assert timeout == 3
            return captured[0]["certificates"][0]["certificate_pem"]

        monkeypatch.setattr(bootstrap.ssl, "get_server_certificate", served_leaf)
        assert bootstrap.acknowledge_console_publication("job_scoped_ca", digest) == 0
    assert [leaf["managed_owner"] for leaf in captured[0]["certificates"]] == ["appliance:https"]
    management_leaf = captured[0]["certificates"][0]
    assert management_leaf["cert_path"] == "/etc/atlaso/https/certs/nginx-previous-hostname.crt"
    assert management_leaf["key_path"] == "/etc/atlaso/https/certs/nginx-previous-hostname.key"
    assert management_leaf["chain_path"] == "/etc/atlaso/https/certs/nginx-previous-hostname-chain.pem"
    assert management_leaf["common_name"] == "management.applied.example.test"
    from cryptography import x509

    leaf_certificate = x509.load_pem_x509_certificate(management_leaf["certificate_pem"].encode())
    sans = leaf_certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "198.51.100.44" in [str(address) for address in sans.get_values_for_type(x509.IPAddress)]
    assert sans.get_values_for_type(x509.DNSName) == ["management.applied.example.test"]
    assert captured[0]["root"]["crl_path"] == captured[0]["root"]["crl_pem"] == ""
    with SessionLocal() as db:
        ldap_leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "ldap:ldaps"))
        assert {column.name: getattr(ldap_leaf, column.name) for column in CaCertificate.__table__.columns} == expected_leaf
        assert db.scalar(select(LdapSettings)).hostname == ("ldap.pending.example.test" if pending == "service" else "ldap.applied.example.test")
        after = load_appliance_apply_baselines(db)["ca"]
        if apply_result or not ready:
            assert after == before
            if not apply_result:
                assert (publication_directory / "job_scoped_ca.publication.json").exists()
                return
            old_management = next(row for row in json.loads(before["config_preview"])["certificates"] if row["managed_owner"] == "appliance:https")
            assert db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https")).fingerprint == old_management["fingerprint"]
        else:
            applied = json.loads(after["config_preview"])
            assert next(row for row in applied["certificates"] if row["managed_owner"] == "ldap:ldaps")["common_name"] == old_leaf["common_name"]
            current = render_ca_apply_payload(db.scalar(select(CaSettings)), db.scalars(select(CaCertificate).order_by(CaCertificate.common_name)).all(), include_private_keys=False, profiles=db.scalars(select(CaProfile)).all())
            current_unit = make_appliance_apply_unit(unit_id="ca", label="Certificate Authority", page_url="/certificate-authority",
                                                    context={}, summary=summary, validation_errors=[], config_path=str(stage),
                                                    config_preview=current, baseline=after)
            assert (current_unit["snapshot_hash"] == after["snapshot_hash"]) is (pending in {"service", "settings"})
            assert after["snapshot_hash"] != before["snapshot_hash"]


@pytest.mark.parametrize("nginx_result", [0, 2])
@pytest.mark.parametrize("edit", ["unchanged", "physical", "vlan", "missing_job", "failed_job", "missing_dynamic"])
def test_completed_http_only_recovery_does_not_require_or_publish_ca(client, monkeypatch, tmp_path, nginx_result, edit):
    """An applied HTTP-only front door remains usable with CA disabled.

    Args:
        tmp_path: Isolated temporary directory for synthetic publication receipts.
        client: Initialized database fixture.
        monkeypatch: Replace native nginx validation and forbid certificate work.
        nginx_result: Valid applied site or missing/invalid site must not trigger first-boot rendering.
        edit: Intervening physical/VLAN drift or unavailable completed Network evidence.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, CaSettings
    from atlaso.app.ui import save_appliance_apply_baselines

    loader = importlib.machinery.SourceFileLoader("atlaso_http_only_recovery", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    publication = tmp_path / "http-publication"
    publication.mkdir(mode=0o700)
    synthetic_root_owned_publication(monkeypatch, publication)
    monkeypatch.setattr(bootstrap, "CONSOLE_PUBLICATION_DIRECTORY", publication)
    with SessionLocal() as db:
        db.scalar(select(ApplianceSettings)).management_https_enabled = False
        db.scalar(select(CaSettings)).enabled = False
        target = appliance_console._management_interface(db)
        target.ipv4_method = "dhcp" if edit == "missing_dynamic" else "static"
        target.ip_cidr = None if edit == "missing_dynamic" else "192.0.2.63/24"
        target.host_ip_cidr = "192.0.2.63/24"
        target.ipv6_enabled = False
        db.flush()
        preview = bootstrap.render_network_config(
            interfaces=list(db.scalars(select(appliance_console.PhysicalInterface))),
            vlans=list(db.scalars(select(appliance_console.VlanInterface))),
        )
        if edit != "missing_job":
            db.add(appliance_console.Job(
                id="job_http_only", type="appliance-apply", status="failed" if edit == "failed_job" else "succeeded",
                created_by="console:root", result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]}),
            ))
        save_appliance_apply_baselines(db, {"appliance_settings": {"config_preview": json.dumps({"management_https_enabled": False})}})
        db.commit()
        if edit == "physical":
            target.ip_cidr = "192.0.2.64/24"
        elif edit == "vlan":
            db.add(appliance_console.VlanInterface(
                name=f"{target.name}.534", parent_interface=target.name, vlan_id=534,
                ip_cidr="198.51.100.1/24", enabled=True, access_management_ui_enabled=True,
            ))
        elif edit == "missing_dynamic":
            target.host_ip_cidr = None
        db.commit()

    def forbidden(*args, **kwargs):
        """Reject certificate work for this explicitly applied HTTP-only mode.

        Args:
            *args: Unexpected publication arguments.
            **kwargs: Unexpected publication options.
        """
        pytest.fail("HTTP-only recovery attempted certificate publication")

    for name in ("recovery_root_matches_baseline", "ensure_recovery_ca_state", "apply_ca_files", "record_ca_publication_baseline"):
        monkeypatch.setattr(bootstrap, name, forbidden)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(bootstrap, "first_boot_https_artifacts_are_complete", lambda: False)
    monkeypatch.setattr(bootstrap, "init_db", forbidden)
    monkeypatch.setattr(bootstrap, "write_nginx_management_config", forbidden)
    admitted = {}
    lock = bootstrap.acquire_network_objects_write_lock

    def acquire(db):
        """Retain the actual writer transaction through HTTP validation.

        Args:
            db: Database session participating in the admitted transaction.
        """
        lock(db)
        admitted["db"] = db
        admitted["transaction"] = db.get_transaction()

    calls = []

    def validate(command):
        """Only the matching completed path may reach native validation under writer admission.

        Args:
            command: Native command whose execution is modeled.
        """
        assert admitted["db"].get_transaction() is admitted["transaction"]
        assert edit == "unchanged"
        calls.append(command)
        return subprocess.CompletedProcess(command, nginx_result, "", "")

    monkeypatch.setattr(bootstrap, "acquire_network_objects_write_lock", acquire)
    monkeypatch.setattr(bootstrap, "run", validate)
    assert bootstrap.main("job_http_only") == (nginx_result if edit == "unchanged" else 2)
    assert len(calls) == (1 if edit == "unchanged" else 0)
    assert not admitted["db"].in_transaction()


@pytest.mark.parametrize("installed", [b"published leaf", b"other valid nginx leaf"])
@pytest.mark.parametrize("served", [b"published leaf", b"other valid nginx leaf"])
def test_console_management_leaf_proof_rejects_old_worker(monkeypatch, tmp_path, served, installed):
    """Reject a valid nginx leaf at a different path unless it matches the task publication.

    Args:
        monkeypatch: Replace the bounded loopback TLS transport.
        tmp_path: Synthetic public certificate and applied site paths.
        served: Current published identity or a different valid nginx worker identity.
        installed: The leaf currently present at the nginx path, independent of the captured publication.
    """
    helper = load_helper_module()
    certificate = tmp_path / "leaf.pem"
    certificate.write_text(helper.ssl.DER_cert_to_PEM_cert(installed))
    directory = tmp_path / "publication"
    directory.mkdir(mode=0o700)
    receipt = {"network_job_id": "job_proven_leaf", "public_payload": json.dumps({"certificates": [
        {"managed_owner": "appliance:https", "fingerprint": helper.hashlib.sha256(b"published leaf").hexdigest()}]})}
    raw = json.dumps(receipt).encode()
    path = directory / "job_proven_leaf.publication.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    monkeypatch.setattr(helper, "CONSOLE_BOOTSTRAP_BINDING_DIRECTORY", directory)
    monkeypatch.setattr(helper, "fcntl", None)
    site = tmp_path / "management.conf"
    site.write_text(f"listen 127.0.0.1:8443 ssl;\nssl_certificate {certificate};\n")
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", site)
    calls = []
    monkeypatch.setattr(helper.ssl, "get_server_certificate",
                        lambda address, *, timeout: calls.append((address, timeout)) or helper.ssl.DER_cert_to_PEM_cert(served))
    fingerprint, digest = helper._console_publication_fingerprint("job_proven_leaf")
    assert digest == helper.hashlib.sha256(raw).hexdigest()
    assert helper._console_management_leaf_is_active(fingerprint) is (served == b"published leaf")
    assert calls == [(("127.0.0.1", 8443), 3)]


@pytest.mark.parametrize("failure", [None, "reload", "readiness"])
def test_console_acknowledges_publication_only_after_outer_recovery(monkeypatch, tmp_path, failure):
    """A successful bootstrap cannot acknowledge CA when outer reload or readiness fails.

    Args:
        monkeypatch: Replace privileged service commands and loopback checks.
        tmp_path: Task-local serialized bootstrap binding directory.
        failure: Outer service-reload failure, readiness timeout, or successful recovery.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "CONSOLE_BOOTSTRAP_BINDING_DIRECTORY", tmp_path / "binding")
    monkeypatch.setattr(helper, "fcntl", None)
    monkeypatch.setattr(helper, "_console_first_boot_https_contract_is_complete", lambda **kwargs: True)
    monkeypatch.setattr(helper, "_console_bootstrap_is_idle", lambda: True)
    monkeypatch.setattr(helper, "_console_management_leaf_is_active", lambda expected: True)
    monkeypatch.setattr(helper, "_console_publication_fingerprint", lambda job: ("a" * 64, "b" * 64))
    monkeypatch.setattr(helper, "_console_management_readiness_checks", lambda: (True, (("app", "https://127.0.0.1/", True, "200"),)))
    monkeypatch.setattr(helper, "_console_management_http_status", lambda *args, **kwargs: "200")
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(helper.time, "sleep", lambda seconds: None)
    commands = []

    def command_result(command, **kwargs):
        """Record the real recovery ordering at the host-command boundary.

        Args:
            command: Service or publication acknowledgement invocation.
            **kwargs: Bounded service timeout options.
        """
        commands.append(command)
        code = 1 if failure == "reload" and command[:2] == ["systemctl", "reload"] else 0
        return subprocess.CompletedProcess(command, code, "active", "")

    monkeypatch.setattr(helper, "_run", command_result)
    assert helper._recover_console_management_plane(timeout_seconds=0 if failure == "readiness" else 1,
                                                   network_job_id="job_outer_ready") == (1 if failure else 0)
    acknowledgements = [command for command in commands if "--acknowledge-console-publication" in command]
    assert bool(acknowledgements) is (failure is None)
    if acknowledgements:
        assert commands.index(["systemctl", "is-active", *helper.MANAGEMENT_PLANE_UNITS]) < commands.index(acknowledgements[0])


def test_recovery_ca_helper_reads_owned_artifact_during_ordinary_staging(tmp_path, monkeypatch):
    """Both helper stages retain recovery ownership while ordinary CA staging changes.

    Args:
        tmp_path: Isolated nonsecret publication artifacts.
        monkeypatch: Replace native helper execution with observed file consumption.
    """
    loader = importlib.machinery.SourceFileLoader("atlaso_owned_ca_helper", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    ordinary = tmp_path / "atlaso-ca.json"
    owned = tmp_path / "recovery-ca.json"
    owned.write_text('{"certificates": ["management-only"]}')
    monkeypatch.setattr(bootstrap, "CA_STAGED_CONFIG_PATH", str(ordinary))
    actions = []

    def interleaved_helper(command):
        """Consume the submitted path after an ordinary writer replaces its fixed artifact.

        Args:
            command: Native CA helper dispatch.
        """
        ordinary.write_text('{"certificates": ["unrelated"], "crl": "ordinary"}')
        assert Path(command[3]) == owned
        assert json.loads(Path(command[3]).read_text()) == {"certificates": ["management-only"]}
        actions.append(command[2])
        ordinary.unlink()
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(bootstrap, "run", interleaved_helper)
    assert bootstrap.apply_ca_files(owned) == 0
    assert actions == ["validate", "apply"]


@pytest.mark.parametrize("state", ["ready", "ipv6_only", "missing_ipv4", "missing_ipv6", "wrong_mac", "missing_listener", "late_edit"])
def test_console_observes_all_applied_physical_management_listeners(client, monkeypatch, state):
    """A newly enabled flagged-access listener must acquire every family before recovery.

    Args:
        client: Initialized appliance database fixture.
        monkeypatch: Replace native discovery with two source-qualified observations.
        state: Ready, unavailable-family, identity-failure, or later desired-edit case.
    """
    from dataclasses import replace

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, PhysicalInterface, VlanInterface
    from atlaso.app.services.networking import HostPhysicalInterface
    from atlaso.app.ui import management_ui_addresses

    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        target.ipv4_method = "dhcp"
        target.ip_cidr = None
        target.ipv6_enabled = False
        target.host_ip_cidr = "192.168.167.170/24"
        listener = PhysicalInterface(name="pr899-access", mac_address="00:15:5d:aa:bb:19", role="access", mode="access",
                                     admin_state="up", oper_state="up", access_management_ui_enabled=True,
                                     ipv4_method="dhcp", ip_cidr=None, ipv6_enabled=True, ipv6_cidr=None,
                                     host_ip_cidr="192.168.167.171/24", host_ipv6_cidr="2001:db8::171/64",
                                     desired_state_source="user")
        if state == "ipv6_only":
            listener.ipv4_method = "static"
        db.add(listener)
        db.flush()
        target_id, listener_id = target.id, listener.id
        preview = appliance_console.render_network_config(
            interfaces=list(db.scalars(select(PhysicalInterface))), vlans=list(db.scalars(select(VlanInterface))))
        db.add(Job(id="job_all_dynamic_paths", type="appliance-apply", status=JobStatus.SUCCEEDED.value,
                   created_by="local_appliance_console",
                   result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]})))
        observations = [
            HostPhysicalInterface(name=target.name, mac_address=target.mac_address, driver=None, speed=None,
                                  host_ip_cidr="192.168.167.170/24", host_dhcp_ip_cidr="192.168.167.174/24",
                                  host_mtu=1500, host_admin_state="up", oper_state="up"),
            HostPhysicalInterface(name=listener.name, mac_address=listener.mac_address, driver=None, speed=None,
                                  host_ip_cidr="192.168.167.171/24", host_dhcp_ip_cidr=None if state == "missing_ipv4" else "192.168.167.176/24",
                                  host_ipv6_cidr="2001:db8::171/64", host_dynamic_ipv6_cidr=None if state == "missing_ipv6" else "2001:db8::176/64",
                                  host_mtu=1500, host_admin_state="up", oper_state="up"),
        ]
        if state == "wrong_mac":
            observations[1] = replace(observations[1], mac_address="00:15:5d:aa:bb:99")
        elif state == "missing_listener":
            observations.pop()
        elif state == "late_edit":
            listener.ipv4_method = "static"
            listener.ip_cidr = "192.168.167.177/24"
        db.commit()
    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", lambda **kwargs: observations)
    if state in {"ready", "ipv6_only"}:
        appliance_console._refresh_management_addresses(target_id, network_job_id="job_all_dynamic_paths", timeout=0)
    else:
        with pytest.raises(ConsoleOperationError, match="newer address edits" if state == "late_edit" else "fresh management address observation"):
            appliance_console._refresh_management_addresses(target_id, network_job_id="job_all_dynamic_paths", timeout=0)
    with SessionLocal() as db:
        target, listener = db.get(PhysicalInterface, target_id), db.get(PhysicalInterface, listener_id)
        published = state in {"ready", "ipv6_only", "late_edit"}
        assert target.host_ip_cidr == ("192.168.167.174/24" if published else "192.168.167.170/24")
        assert listener.host_ip_cidr == (None if state == "ipv6_only" else "192.168.167.176/24" if published else "192.168.167.171/24")
        assert listener.host_ipv6_cidr == ("2001:db8::176/64" if published else "2001:db8::171/64")
        assert listener.desired_state_source == "user"
        if state in {"ready", "ipv6_only"}:
            assert {"192.168.167.174", "2001:db8::176"} <= set(management_ui_addresses(db))
            assert ("192.168.167.176" in management_ui_addresses(db)) is (state == "ready")
            assert listener.ip_cidr is None and listener.ipv6_cidr is None
        elif state == "late_edit":
            assert listener.ip_cidr == "192.168.167.177/24"


@pytest.mark.parametrize("missing", [True, False])
def test_console_reobserves_after_service_start_and_settings_apply(client, monkeypatch, missing):
    """Each service start can clear inventory, so both later dependent stages reacquire it.

    Args:
        client: Initialized appliance database.
        monkeypatch: Exercise real observation around simulated service startup and Apply.
        missing: A missing successor lease must stop before Settings and second recovery.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.networking import HostPhysicalInterface

    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        identity, name, mac = target.id, target.name, target.mac_address
    captures, probes = [], []
    refresh = appliance_console._refresh_management_addresses

    def observe(interface_id, **kwargs):
        """Retain production observation with a bounded zero-wait test budget.

        Args:
            interface_id: Physical interface selected for admitted observation.
            **kwargs: Additional options supplied by the production caller.
        """
        return refresh(interface_id, timeout=0, **kwargs)

    def discover(**kwargs):
        """Acquire a different usable lease after each simulated service restart.

        Args:
            **kwargs: Additional options supplied by the production caller.
        """
        suffix = 174 + len(probes)
        probes.append(suffix)
        unavailable = missing and len(probes) > 1
        return [HostPhysicalInterface(name=name, mac_address=mac, driver=None, speed=None,
            host_ip_cidr="192.168.167.170/24", host_dhcp_ip_cidr=None if unavailable else f"192.168.167.{suffix}/24",
            host_ipv6_cidr="2001:db8::170/64", host_dynamic_ipv6_cidr=None if unavailable else f"2001:db8::{suffix}/64",
            host_mtu=1500, host_admin_state="up", oper_state="up")]

    def capture(stage, **kwargs):
        """Model service startup clearing dynamic inventory after its initial publication.

        Args:
            stage: Console stage requesting an atomic observation snapshot.
            **kwargs: Additional options supplied by the production caller.
        """
        with SessionLocal() as db:
            target = db.get(appliance_console.PhysicalInterface, identity)
            captures.append((stage, target.host_ip_cidr, target.host_ipv6_cidr))
            if stage != "Appliance Settings were applied":
                target.host_ip_cidr = target.host_ipv6_cidr = None
                db.commit()

    def submit(units, **kwargs):
        """Capture the real completed Network snapshot and simulated Settings restart.

        Args:
            units: Captured appliance units supplied by the caller.
            **kwargs: Additional options supplied by the production caller.
        """
        if units == {"appliance_settings"}:
            capture("settings")
            return "job_settings_started"
        with SessionLocal() as db:
            preview = appliance_console.render_network_config(
                interfaces=list(db.query(appliance_console.PhysicalInterface)),
                vlans=list(db.query(appliance_console.VlanInterface)))
            db.add(appliance_console.Job(id="job_started", type="appliance-apply", status="succeeded",
                created_by="console:root", result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]})))
            db.commit()
        return "job_started"

    monkeypatch.setattr(appliance_console, "_refresh_management_addresses", observe)
    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", discover)
    monkeypatch.setattr(appliance_console, "_submit_console_apply", submit)
    monkeypatch.setattr(appliance_console, "_recover_management_plane", capture)
    if missing:
        with pytest.raises(ConsoleOperationError, match="fresh management address observation"):
            appliance_console.configure_management("dhcp", "", "", "automatic", "", "", "192.0.2.53")
        assert [entry[0] for entry in captures] == ["Network and Firewall were applied"]
    else:
        appliance_console.configure_management("dhcp", "", "", "automatic", "", "", "192.0.2.53")
        assert captures == [
            ("Network and Firewall were applied", "192.168.167.174/24", "2001:db8::174/64"),
            ("settings", "192.168.167.175/24", "2001:db8::175/64"),
            ("Appliance Settings were applied", "192.168.167.176/24", "2001:db8::176/64"),
        ]


@pytest.mark.parametrize("family", [4, 6])
def test_bound_issuance_refuses_cleared_dynamic_observation(client, monkeypatch, family):
    """Inventory clearing after console observation cannot issue an incomplete leaf.

    Args:
        client: Initialized appliance database.
        monkeypatch: Detect any forbidden issuance after missing observation.
        family: Requested dynamic address family cleared before writer admission.
    """
    from atlaso.app.database import SessionLocal

    loader = importlib.machinery.SourceFileLoader("atlaso_missing_dynamic_bootstrap", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        target.ipv4_method, target.ip_cidr = "dhcp", None
        target.ipv6_enabled, target.ipv6_cidr = True, None
        target.host_ip_cidr = None if family == 4 else "192.0.2.174/24"
        target.host_ipv6_cidr = None if family == 6 else "2001:db8::174/64"
        preview = appliance_console.render_network_config(
            interfaces=list(db.query(appliance_console.PhysicalInterface)), vlans=list(db.query(appliance_console.VlanInterface)))
        db.add(appliance_console.Job(id="job_missing_dynamic", type="appliance-apply", status="succeeded",
            created_by="console:root", result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]})))
        db.commit()
    monkeypatch.setattr(bootstrap, "ensure_ca_state", lambda *args, **kwargs: pytest.fail("Missing dynamic observation must prevent issuance"))
    with SessionLocal() as db:
        errors = bootstrap.ensure_recovery_ca_state(db, "job_missing_dynamic", commit=False)
        assert errors and "dynamic management observation is unavailable" in errors[0]


@pytest.mark.parametrize("edit", ["unchanged", "physical", "vlan", "dynamic", "mode", "port", "native_dhcp", "native_slaac", "refreshed_dhcp", "timeout", "native_vlan", "native_vlan_unchanged"])
def test_http_final_recheck_refuses_drift_after_bootstrap(client, monkeypatch, tmp_path, edit):
    """HTTP readiness cannot certify Network or applied-mode drift after initial bootstrap validation.

    Args:
        tmp_path: Isolated temporary directory for synthetic publication receipts.
        client: Initialized appliance database.
        monkeypatch: Replace nginx validation and forbid CA mutation.
        edit: Change committed during the outer readiness samples.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.ui import save_appliance_apply_baselines

    loader = importlib.machinery.SourceFileLoader("atlaso_http_final_recheck", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    publication = tmp_path / "http-publication"
    publication.mkdir(mode=0o700)
    synthetic_root_owned_publication(monkeypatch, publication)
    monkeypatch.setattr(bootstrap, "CONSOLE_PUBLICATION_DIRECTORY", publication)
    applied = {"management_https_enabled": False, "management_public_http_port": 8080}
    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        target.ipv4_method = "dhcp"
        target.ip_cidr = None
        target.host_ip_cidr = "192.0.2.63/24"
        target.ipv6_enabled = edit == "native_slaac"
        target.ipv6_cidr = None
        target.host_ipv6_cidr = "2001:db8::63/64"
        target.host_ipv6_cidrs = ["2001:db8::63/64", "2001:db8:1::63/64"] if target.ipv6_enabled else []
        native_identity = (target.name, target.mac_address)
        if edit.startswith("native_vlan"):
            db.add(appliance_console.PhysicalInterface(name="pr899-http-trunk", mac_address="00:15:5d:aa:bb:40",
                                                      role="access", mode="trunk", admin_state="up", oper_state="up"))
            db.add(appliance_console.VlanInterface(name="pr899-http-trunk.540", parent_interface="pr899-http-trunk",
                                                  vlan_id=540, ip_cidr="198.51.100.40/24", enabled=True,
                                                  access_management_ui_enabled=True))
            db.flush()
        db.flush()
        preview = bootstrap.render_network_config(interfaces=list(db.scalars(select(appliance_console.PhysicalInterface))),
                                                 vlans=list(db.scalars(select(appliance_console.VlanInterface))))
        db.add(appliance_console.Job(id="job_http_final", type="appliance-apply", status="succeeded", created_by="console:root",
                                    result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]})))
        save_appliance_apply_baselines(db, {"appliance_settings": {"config_preview": json.dumps(applied)}})
        db.commit()
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(bootstrap, "run", lambda cmd: subprocess.CompletedProcess(cmd, 0, "", ""))
    assert bootstrap.main("job_http_final") == 0
    original_receipt = (publication / "job_http_final.publication.json").read_bytes()
    from atlaso.app.services.networking import HostPhysicalInterface

    def discover(*, timeout, require_success):
        """Model kernel-only drift during final readiness without changing persisted observations.

        Args:
            timeout: Bounded native discovery timeout supplied by the caller.
            require_success: Require native discovery to succeed before observation publication.
        """
        assert 0 <= timeout <= 5 and require_success is True
        if edit == "timeout":
            raise subprocess.TimeoutExpired("ip", 5)
        return [HostPhysicalInterface(name=native_identity[0], mac_address=native_identity[1], driver=None,
                                      speed=None, host_ip_cidr="192.0.2.63/24", host_mtu=1500,
                                      host_admin_state="up", oper_state="up",
                                      host_dhcp_ip_cidr="192.0.2.64/24" if edit in {"native_dhcp", "refreshed_dhcp"} else "192.0.2.63/24",
                                      host_dynamic_ipv6_cidrs=("2001:db8:1::63/64",))]

    monkeypatch.setattr(bootstrap, "discover_host_physical_interfaces", discover)
    if edit.startswith("native_vlan"):
        from atlaso.app.services import networking

        def native_vlan_run(command, **kwargs):
            """Withdraw only the native VLAN after initial HTTP capture while DB state stays applied.

            Args:
                command: Native command whose execution is modeled.
                **kwargs: Additional options supplied by the production caller.
            """
            assert command == ["ip", "-d", "-j", "address", "show"] and kwargs["timeout"] <= 5
            rows = [{"ifname": "pr899-http-trunk", "ifindex": 14, "address": "00:15:5d:aa:bb:40",
                     "link_type": "ether", "flags": ["UP"], "operstate": "UP"}]
            if edit == "native_vlan_unchanged":
                rows.append({"ifname": "pr899-http-trunk.540", "link_index": 14, "flags": ["UP"], "operstate": "UP",
                             "linkinfo": {"info_kind": "vlan", "info_data": {"id": 540}},
                             "addr_info": [{"family": "inet", "local": "198.51.100.40", "prefixlen": 24, "scope": "global"}]})
            return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

        monkeypatch.setattr(networking.subprocess, "run", native_vlan_run)
    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        if edit == "physical":
            target.admin_state = "down"
        elif edit == "vlan":
            db.add(appliance_console.VlanInterface(name=f"{target.name}.534", parent_interface=target.name, vlan_id=534,
                                                  ip_cidr="198.51.100.1/24", enabled=True, access_management_ui_enabled=True))
        elif edit == "dynamic":
            target.host_ip_cidr = None
        elif edit == "refreshed_dhcp":
            target.host_ip_cidr = "192.0.2.64/24"
        elif edit in {"mode", "port"}:
            applied["management_https_enabled" if edit == "mode" else "management_public_http_port"] = True if edit == "mode" else 80
            save_appliance_apply_baselines(db, {"appliance_settings": {"config_preview": json.dumps(applied)}})
        db.commit()
    assert bootstrap.verify_console_http_recovery("job_http_final", 8080) == (0 if edit in {"unchanged", "native_vlan_unchanged"} else 2)
    assert (publication / "job_http_final.publication.json").read_bytes() == original_receipt


@pytest.mark.parametrize("case", ["ready", "down", "access", "missing", "native_parent_missing", "native_parent_down",
                                  "native_parent_mac", "native_vlan_missing", "native_vlan_down", "native_vlan_parent",
                                  "native_vlan_tag", "native_vlan_address", "native_ipv6_address", "native_tentative",
                                  "native_expired", "native_timeout", "native_failed", "native_duplicate"])
def test_console_refuses_ineligible_completed_vlan_with_working_physical_listener(client, monkeypatch, case):
    """A working dedicated listener cannot mask an ineligible completed management VLAN.

    Args:
        client: Initialized appliance database.
        monkeypatch: Supply only the proven dedicated native observation.
        case: Administrative or native link/identity/address failure with a working dedicated listener.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.services import networking
    from atlaso.app.services.networking import HostPhysicalInterface

    parent_state = case if case in {"down", "access", "missing"} else "ready"
    loader = importlib.machinery.SourceFileLoader("atlaso_vlan_eligibility", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        target.ipv4_method = "static"
        target.ip_cidr = "192.0.2.63/24"
        target.ipv6_enabled = False
        target.host_ip_cidr = "192.0.2.62/24"
        identity = target.id
        host = HostPhysicalInterface(name=target.name, mac_address=target.mac_address, driver=None, speed=None,
                                     host_ip_cidr=target.ip_cidr, host_mtu=1500, host_admin_state="up", oper_state="up")
        if parent_state != "missing":
            db.add(appliance_console.PhysicalInterface(name="pr899-trunk", mac_address="00:15:5d:aa:bb:32",
                                                      role="access", mode="access" if parent_state == "access" else "trunk",
                                                      admin_state="down" if parent_state == "down" else "up", oper_state="up"))
        db.add(appliance_console.VlanInterface(name="pr899-trunk.532", parent_interface="pr899-trunk", vlan_id=532,
                                              role="access", ip_cidr="198.51.100.32/24", enabled=True,
                                              ipv6_cidr="2001:db8:532::32/64",
                                              access_management_ui_enabled=True))
        db.flush()
        preview = appliance_console.render_network_config(interfaces=list(db.scalars(select(appliance_console.PhysicalInterface))),
                                                          vlans=list(db.scalars(select(appliance_console.VlanInterface))))
        db.add(appliance_console.Job(id="job_vlan_eligibility", type="appliance-apply", status="succeeded",
                                    created_by="console:root", result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]})))
        db.commit()
    calls = []
    def discover(**kwargs):
        """Record whether an ineligible snapshot reaches native observation.

        Args:
            **kwargs: Additional options supplied by the production caller.
        """
        calls.append(kwargs)
        return [host]

    monkeypatch.setattr(appliance_console, "discover_host_physical_interfaces", discover)
    native_parent = {"ifname": "pr899-trunk", "ifindex": 12, "address": "00:15:5d:aa:bb:32", "link_type": "ether",
                     "flags": ["UP", "LOWER_UP"], "operstate": "UP"}
    native_vlan = {"ifname": "pr899-trunk.532", "ifindex": 13, "link_index": 12, "flags": ["UP", "LOWER_UP"],
                   "operstate": "UP", "linkinfo": {"info_kind": "vlan", "info_data": {"id": 532}},
                   "addr_info": [{"family": "inet", "local": "198.51.100.32", "prefixlen": 24, "scope": "global"},
                                 {"family": "inet6", "local": "2001:db8:532::32", "prefixlen": 64, "scope": "global"}]}
    native_rows = [native_parent, native_vlan]
    if case == "native_parent_missing":
        native_rows.remove(native_parent)
    elif case == "native_parent_down":
        native_parent["operstate"] = "DOWN"
    elif case == "native_parent_mac":
        native_parent["address"] = "00:15:5d:aa:bb:99"
    elif case == "native_vlan_missing":
        native_rows.remove(native_vlan)
    elif case == "native_vlan_down":
        native_vlan["flags"] = []
    elif case == "native_vlan_parent":
        native_vlan["link_index"] = 99
    elif case == "native_vlan_tag":
        native_vlan["linkinfo"]["info_data"]["id"] = 533
    elif case == "native_vlan_address":
        native_vlan["addr_info"][0]["local"] = "198.51.100.33"
    elif case == "native_ipv6_address":
        native_vlan["addr_info"].pop()
    elif case == "native_tentative":
        native_vlan["addr_info"][1]["tentative"] = True
    elif case == "native_expired":
        native_vlan["addr_info"][0]["valid_life_time"] = 0
    elif case == "native_duplicate":
        native_rows.append(native_vlan.copy())
    native_calls = []
    def native_run(command, **kwargs):
        """Supply real iproute2 VLAN and parent evidence or its bounded failure.

        Args:
            command: Native command whose execution is modeled.
            **kwargs: Additional options supplied by the production caller.
        """
        if command == ["ip", "-j", "-4", "route", "show", "default"]:
            return subprocess.CompletedProcess(command, 0, "[]", "")
        assert command == ["ip", "-d", "-j", "address", "show"]
        assert 0 <= kwargs["timeout"] <= 5
        native_calls.append(command)
        if case == "native_timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 1 if case == "native_failed" else 0, json.dumps(native_rows), "")

    monkeypatch.setattr(networking.subprocess, "run", native_run)
    if case == "ready":
        appliance_console._refresh_management_addresses(identity, network_job_id="job_vlan_eligibility", timeout=0)
        assert len(calls) == 1
    elif parent_state != "ready":
        with pytest.raises(ConsoleOperationError, match="path is ineligible"):
            appliance_console._refresh_management_addresses(identity, network_job_id="job_vlan_eligibility", timeout=0)
        assert calls == []
        with pytest.raises(ConsoleOperationError, match="Appliance Settings were not submitted"):
            appliance_console._submit_console_apply({"appliance_settings"}, network_job_id="job_vlan_eligibility")
    else:
        with pytest.raises(ConsoleOperationError, match="fresh management address observation"):
            appliance_console._refresh_management_addresses(identity, network_job_id="job_vlan_eligibility", timeout=0)
        assert len(calls) == 1
        assert len(native_calls) == 1
    with SessionLocal() as db:
        assert bootstrap.completed_network_binding_is_current(db, "job_vlan_eligibility") is (parent_state == "ready")
        assert bootstrap.recovery_dynamic_addresses_available(db, preview) is (parent_state == "ready")
        assert db.get(appliance_console.PhysicalInterface, identity).host_ip_cidr == ("192.0.2.63/24" if case == "ready" else "192.0.2.62/24")
        if parent_state == "ready":
            if case == "ready":
                assert bootstrap.recovery_dynamic_address_binding(db, preview, native=True) == {}
            else:
                with pytest.raises(ValueError, match="Native management VLAN"):
                    bootstrap.recovery_dynamic_address_binding(db, preview, native=True)


@pytest.mark.parametrize("https", [False, True])
@pytest.mark.parametrize("bound", [False, True])
def test_console_recovery_reserves_complete_final_attestation(monkeypatch, https, bound):
    """Late stable readiness retains service, native discovery and served-leaf worst cases.

    Args:
        monkeypatch: Replace privileged commands and control the shared clock.
        https: Whether final proof also includes the served TLS leaf.
        bound: Whether native and served-leaf attestation are required.
    """
    helper = load_helper_module()
    clock = [83.0 if bound else 93.0]
    calls = []
    monkeypatch.setattr(helper.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(helper.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(helper, "_console_first_boot_https_contract_is_complete", lambda **kwargs: True)
    monkeypatch.setattr(helper, "_console_restart_bootstrap", lambda: None)
    monkeypatch.setattr(helper, "_console_publication_fingerprint", lambda job: ("a" * 64, "b" * 64))
    monkeypatch.setattr(helper, "_console_management_leaf_is_active", lambda fingerprint: True)
    monkeypatch.setattr(helper, "_console_management_readiness_checks", lambda: (https,
        (("nginx HTTP readiness", "http://127.0.0.1:8080/openapi.json", False, "200"),)))

    native_status = helper._console_management_http_status

    def status(*args, **kwargs):
        """Consume the final readiness sample up to its separate deadline.

        Args:
            *args: Positional arguments supplied by the production caller.
            **kwargs: Additional options supplied by the production caller.
        """
        if clock[0] in {87, 97}:
            assert helper._console_recovery_remaining() == 1
            return native_status(*args, **kwargs)
        return "200"

    def run(command, *, timeout):
        """Exercise all final permitted durations at the actual outer command boundary.

        Args:
            command: Native command whose execution is modeled.
            timeout: Bounded native discovery timeout supplied by the caller.
        """
        calls.append((command, timeout))
        if command[0] == "/usr/bin/curl":
            assert timeout == 1
            clock[0] += 1
            return subprocess.CompletedProcess(command, 0, "200", "")
        if command == ["systemctl", "is-active", *helper.MANAGEMENT_PLANE_UNITS]:
            assert timeout == 2
            clock[0] += 2
        if "--acknowledge-console-publication" in command or "--verify-console-http" in command:
            assert timeout >= 10
            clock[0] += 5 + (3 if https else 0)
        return subprocess.CompletedProcess(command, 0, "active", "")

    monkeypatch.setattr(helper, "_console_management_http_status", status)
    monkeypatch.setattr(helper, "_run", run)
    token = helper._CONSOLE_RECOVERY_DEADLINE.set(100.0)
    try:
        assert helper._recover_console_management_plane_bound(60, network_job_id="job_final_budget" if bound else None) == 0
        assert clock[0] == ((98 if https else 95) if bound else 100)
        assert helper._CONSOLE_RECOVERY_DEADLINE.get() == 100
        assert any("--acknowledge-console-publication" in command or "--verify-console-http" in command
                   for command, _timeout in calls) is bound
    finally:
        helper._CONSOLE_RECOVERY_DEADLINE.reset(token)


def test_bound_recovery_refuses_revoked_management_leaf_before_issuance(client, monkeypatch):
    """A committed managed revocation blocks scoped recovery without publication or baseline writes.

    Args:
        client: Initialized isolated appliance database.
        monkeypatch: Forbid certificate reconciliation after revoked-row admission.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate
    from atlaso.app.services.networking import render_network_config
    from atlaso.app.ui import load_appliance_apply_baselines

    loader = importlib.machinery.SourceFileLoader("atlaso_revoked_bound_recovery", "scripts/appliance/atlaso-bootstrap-https")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    bootstrap = importlib.util.module_from_spec(spec)
    loader.exec_module(bootstrap)
    with SessionLocal() as db:
        target = appliance_console._management_interface(db)
        target.ipv4_method, target.ip_cidr, target.ipv6_enabled = "static", "192.0.2.10/24", False
        target.admin_state, target.host_admin_state, target.oper_state = "up", "up", "up"
        leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        if leaf is None:
            leaf = CaCertificate(common_name="revoked.example.test", managed_owner="appliance:https")
            db.add(leaf)
        leaf.status, leaf.serial_number = "revoked", "revoked-management-serial"
        preview = render_network_config(interfaces=list(db.scalars(select(appliance_console.PhysicalInterface))),
                                        vlans=list(db.scalars(select(appliance_console.VlanInterface))))
        db.add(appliance_console.Job(id="job_revoked_leaf", type="appliance-apply", status="succeeded",
               created_by="console:root", result=json.dumps({"captured_units": [{"unit_id": "network", "config_preview": preview}]})))
        db.commit()
        identity = leaf.id
        prior = load_appliance_apply_baselines(db)
    monkeypatch.setattr(bootstrap, "ensure_ca_state", lambda *_args, **_kwargs: pytest.fail("Revocation reached issuance"))
    with SessionLocal() as db:
        errors = bootstrap.ensure_recovery_ca_state(db, "job_revoked_leaf", commit=False)
        assert len(errors) == 1 and "certificate is revoked" in errors[0]
        assert load_appliance_apply_baselines(db) == prior
        assert db.get(CaCertificate, identity).status == "revoked"
        db.rollback()
