"""Tests for narrowly removing the stock Photon nginx welcome server."""

import importlib.machinery
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "atlaso-helper"


def load_helper_module():
    """Load the appliance helper using the repository's source-loader convention."""
    loader = importlib.machinery.SourceFileLoader("atlaso_helper", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("atlaso_helper", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


STOCK_SERVER = """server {
    listen 80;
    server_name localhost;
    location / {
        root html;
        index index.html index.htm;
    }
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root html;
    }
}"""


def test_removes_only_stock_server_and_preserves_every_other_byte():
    """Remove the direct stock HTTP child while retaining surrounding source verbatim."""
    helper = load_helper_module()
    prefix = "# operator header { remains a comment\nhttp {\n    # before stock\n"
    suffix = "\n    server { listen 8080; server_name custom; }\n}\n# trailer }\n"
    source = prefix + STOCK_SERVER + suffix

    result = helper._without_stock_nginx_welcome_server(source)

    assert result == prefix + suffix


def test_matches_stock_tokens_across_whitespace_and_comments():
    """Whitespace and comments do not change the stock directive sequence."""
    helper = load_helper_module()
    stock = """server # server opening comment {
{
    listen # default HTTP
        80;
    server_name
        localhost;
    location # root path
        / {
        root html;
        index index.html
              index.htm;
    }
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root html;
    }
}"""
    source = "http {\n" + stock + "\n}\n"

    assert helper._without_stock_nginx_welcome_server(source) == "http {\n\n}\n"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("listen 80;", "listen 80 default_server;"),
        ("server_name localhost;", "server_name _;"),
        ("server_name localhost;", "server_name localhost#custom\n;"),
        ("root html;", "root /srv/www;"),
        ("index index.html index.htm;", "index index.htm;"),
        ("error_page 500 502 503 504 /50x.html;", "error_page 500 /50x.html;"),
        ("location = /50x.html {", "location = /custom-error.html {"),
        ("    listen 80;", "    listen 80;\n    access_log off;"),
    ],
)
def test_preserves_server_when_any_stock_directive_is_changed_or_extended(old, new):
    """A near match remains operator-owned when its semantics differ from stock."""
    helper = load_helper_module()
    source = "http {\n" + STOCK_SERVER.replace(old, new, 1) + "\n}\n"

    assert helper._without_stock_nginx_welcome_server(source) == source


def test_removes_only_direct_child_of_top_level_http_context():
    """Similar blocks in nested and stream contexts are outside the target scope."""
    helper = load_helper_module()
    nested = """    server {
        listen 80;
        server_name localhost;
        location / {
            root html;
            index index.html index.htm;
        }
        error_page 500 502 503 504 /50x.html;
        location = /50x.html { root html; }
    }"""
    source = (
        "stream {\n"
        + STOCK_SERVER
        + "\n}\nhttp {\n    map $host $target {\n"
        + nested
        + "\n    }\n"
        + STOCK_SERVER
        + "\n}\n"
    )
    expected = (
        "stream {\n"
        + STOCK_SERVER
        + "\n}\nhttp {\n    map $host $target {\n"
        + nested
        + "\n    }\n\n}\n"
    )

    assert helper._without_stock_nginx_welcome_server(source) == expected


def test_quoted_escaped_braces_and_comment_markers_do_not_change_scan_boundaries():
    """Braces and comment markers in quoted values remain ordinary token data."""
    helper = load_helper_module()
    custom = r'''    server {
        listen 8080;
        server_name "quoted # { brace }";
        add_header X-Example "escaped \" } { # value";
        set $escaped \{literal\};
        # a closing brace } and opening brace { are comments
        location / { return 200; }
    }'''
    prefix = "http {\n" + custom + "\n"
    source = prefix + STOCK_SERVER + "\n}\n"

    assert helper._without_stock_nginx_welcome_server(source) == prefix + "\n}\n"


@pytest.mark.parametrize(
    "source",
    [
        "http {\n" + STOCK_SERVER,
        "http {\n" + STOCK_SERVER + "\n}\nhttp {\n}\n",
        "# http {\n" + STOCK_SERVER + "\n",
        "http {\n    server { listen 80; # unterminated }\n",
        'http {\n    server { server_name "unterminated;\n'
        + STOCK_SERVER
        + "\n}\n",
    ],
)
def test_preserves_malformed_or_ambiguous_configuration(source):
    """Malformed or multiply-scoped inputs are returned untouched."""
    helper = load_helper_module()

    assert helper._without_stock_nginx_welcome_server(source) == source


def test_existing_include_still_triggers_stock_removal_and_is_idempotent(tmp_path, monkeypatch):
    """An existing Atlaso include does not skip the cold-start stock cleanup."""
    helper = load_helper_module()
    main_config = tmp_path / "nginx.conf"
    include_path = tmp_path / "sites-enabled" / "atlaso.conf"
    prefix = "worker_processes auto;\nhttp {\n"
    suffix = f"    include {include_path};\n}}\n"
    main_config.write_text(prefix + STOCK_SERVER + "\n" + suffix, encoding="utf-8")
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main_config)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include_path)

    helper._ensure_nginx_main_config_includes_atlaso()
    first_result = main_config.read_text(encoding="utf-8")
    helper._ensure_nginx_main_config_includes_atlaso()

    assert first_result == prefix + "\n" + suffix
    assert main_config.read_text(encoding="utf-8") == first_result


def test_existing_include_leaves_custom_main_config_byte_identical(tmp_path, monkeypatch):
    """An already-managed file without the stock block is not rewritten."""
    helper = load_helper_module()
    main_config = tmp_path / "nginx.conf"
    include_path = tmp_path / "sites-enabled" / "atlaso.conf"
    source = (
        "# custom header\nworker_processes auto;\nhttp {\n"
        "    server { listen 80; server_name example.test; }\n"
        f"    include {include_path};\n"
        "}\n# exact trailing bytes\n"
    )
    main_config.write_text(source, encoding="utf-8")
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main_config)
    monkeypatch.setattr(helper, "NGINX_CONF_INCLUDE_PATH", include_path)

    helper._ensure_nginx_main_config_includes_atlaso()

    assert main_config.read_text(encoding="utf-8") == source


@pytest.mark.parametrize("status", [None, "success", "failed"])
def test_installed_helper_migrates_settled_upgrade_before_service_start(tmp_path, monkeypatch, status):
    """An older updater still installs the fresh helper consumed by pre-start."""
    helper = load_helper_module()
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", tmp_path / "backups")
    main = tmp_path / "nginx.conf"
    source = "events {}\nhttp {\n" + STOCK_SERVER + "\n}\n"
    main.write_text(source, encoding="utf-8")
    finalizer = tmp_path / "finalizer.json"
    if status is not None:
        finalizer.write_text(json.dumps({"status": status, "rolled_back": True}), encoding="utf-8")
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer)
    monkeypatch.setattr(helper, "_guard_appliance_update_status_startup", lambda: {"success": True})
    checked = []

    def validate():
        """Prove migration precedes nginx's own configuration/start admission."""
        checked.append(main.read_text(encoding="utf-8"))
        return subprocess.CompletedProcess(["nginx", "-t"], 0, "", "")

    monkeypatch.setattr(helper, "_nginx_test_command", validate)
    assert helper._guard_interrupted_release_startup()["success"] is True
    assert checked == ["events {}\nhttp {\n\n}\n"]
    assert helper._guard_interrupted_release_startup()["success"] is True
    assert len(checked) == 1
    for relative in ["image/common/systemd/nginx-atlaso-data-disks.conf",
                     "image/common/systemd/atlaso-require-data-disks.conf"]:
        unit = (HELPER_PATH.parents[2] / relative).read_text(encoding="utf-8")
        assert "ExecStartPre=+/opt/atlaso/bin/atlaso-helper appliance-update guard-release --real" in unit


@pytest.mark.parametrize("raises", [False, True])
@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_startup_migration_restores_original_on_nginx_validation_failure(tmp_path, monkeypatch, raises, ending):
    """A failed or interrupted validator blocks startup and restores exact bytes."""
    helper = load_helper_module()
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", tmp_path / "backups")
    main = tmp_path / "nginx.conf"
    source = "# retained operator header\nhttp {\n" + STOCK_SERVER + "\n}\n"
    original = source.replace("\n", ending).encode("utf-8")
    main.write_bytes(original)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main)

    def validate():
        """Reject the migrated configuration after publication."""
        if raises:
            raise OSError("validator unavailable")
        return subprocess.CompletedProcess(["nginx", "-t"], 1, "", "invalid")

    monkeypatch.setattr(helper, "_nginx_test_command", validate)
    assert helper._prepare_stock_nginx_listener_startup()["success"] is False
    assert main.read_bytes() == original


@pytest.mark.parametrize("status", ["transaction_pending", "restart_pending", "rollback_pending", "activation_committed"])
def test_provisional_upgrade_keeps_nginx_bootable_and_original_bytes(tmp_path, monkeypatch, status):
    """Recovery can cold-start nginx while retaining original configuration evidence."""
    helper = load_helper_module()
    monkeypatch.setattr(helper, "ATLASO_UPDATE_BACKUP_DIR", tmp_path / "backups")
    main = tmp_path / "nginx.conf"
    source = "http {\n" + STOCK_SERVER + "\n}\n"
    main.write_text(source, encoding="utf-8")
    finalizer = tmp_path / "finalizer.json"
    original = main.read_bytes()
    finalizer.write_text(json.dumps({"status": status}), encoding="utf-8")
    management = tmp_path / "management.conf"
    management.write_text("server {\n  listen 80 default_server;\n}\n", encoding="utf-8")
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main)
    monkeypatch.setattr(helper, "NGINX_MANAGEMENT_SITE_PATH", management)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_FINALIZER_PATH", finalizer)
    monkeypatch.setattr(helper, "ATLASO_UPDATE_MAINTENANCE_PATH", tmp_path / "maintenance")
    monkeypatch.setattr(helper, "_guard_appliance_update_status_startup", lambda: {"success": True})
    monkeypatch.setattr(helper, "_nginx_test_command", lambda: subprocess.CompletedProcess(["nginx", "-t"], 0, "", ""))
    assert helper._guard_interrupted_release_startup()["success"] is True
    assert main.read_text(encoding="utf-8") == "http {\n\n}\n"
    backups = list((tmp_path / "backups/nginx-stock-listeners").glob("*.conf"))
    assert len(backups) == 1 and backups[0].read_bytes() == original
    evidence = json.loads(backups[0].with_suffix(".json").read_text(encoding="utf-8"))
    assert evidence["target"] == str(main)
    assert (tmp_path / "maintenance").is_file()
    assert "return 503" in management.read_text(encoding="utf-8")
    assert helper._guard_interrupted_release_startup()["success"] is True
    assert backups[0].read_bytes() == original


def test_concurrent_startup_waits_then_rechecks_completed_migration(tmp_path, monkeypatch):
    """A second service waits for its peer and observes its completed cleanup."""
    helper = load_helper_module()
    main = tmp_path / "nginx.conf"
    main.write_text("http {\n" + STOCK_SERVER + "\n}\n", encoding="utf-8")
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main)
    attempts = []
    sleeps = []

    def flock(_descriptor, flags):
        """Model the peer completing migration while this guard waits."""
        attempts.append(flags)
        if len(attempts) == 1:
            main.write_text("http {\n\n}\n", encoding="utf-8")
            raise BlockingIOError("peer guard holds lock")

    def unexpected_validation():
        """A completed peer migration must not be overwritten or revalidated."""
        raise AssertionError("peer already migrated this configuration")

    monkeypatch.setattr(helper, "fcntl", SimpleNamespace(flock=flock, LOCK_EX=2, LOCK_NB=4))
    monkeypatch.setattr(helper.time, "sleep", sleeps.append)
    monkeypatch.setattr(helper, "_nginx_test_command", unexpected_validation)
    assert helper._prepare_stock_nginx_listener_startup()["success"] is True
    assert attempts == [6, 6]
    assert sleeps == [0.05]
    assert main.read_text(encoding="utf-8") == "http {\n\n}\n"


def test_startup_lock_wait_is_bounded_and_preserves_configuration(tmp_path, monkeypatch):
    """A stuck peer blocks admission without changing the main configuration."""
    helper = load_helper_module()
    main = tmp_path / "nginx.conf"
    source = ("http {\n" + STOCK_SERVER + "\n}\n").encode("utf-8")
    main.write_bytes(source)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main)

    def busy(_descriptor, _flags):
        """Keep the peer lock held past the bounded acquisition deadline."""
        raise BlockingIOError("peer guard holds lock")

    ticks = iter([0, 46])
    monkeypatch.setattr(helper, "fcntl", SimpleNamespace(flock=busy, LOCK_EX=2, LOCK_NB=4))
    monkeypatch.setattr(helper.time, "monotonic", lambda: next(ticks))
    assert helper._prepare_stock_nginx_listener_startup()["success"] is False
    assert main.read_bytes() == source


def test_backup_failure_blocks_migration_before_main_write(tmp_path, monkeypatch):
    """Original configuration must be durable before a recovery repair starts."""
    helper = load_helper_module()
    main = tmp_path / "nginx.conf"
    original = ("http {\n" + STOCK_SERVER + "\n}\n").encode("utf-8")
    main.write_bytes(original)
    monkeypatch.setattr(helper, "NGINX_MAIN_CONFIG_PATH", main)

    def unavailable(_original, _cleaned):
        """Refuse a missing recovery-evidence capability."""
        raise OSError("backup unavailable")

    monkeypatch.setattr(helper, "_backup_stock_nginx_listener", unavailable)
    assert helper._prepare_stock_nginx_listener_startup()["success"] is False
    assert main.read_bytes() == original
