"""Tests for narrowly removing the stock Photon nginx welcome server."""

import importlib.machinery
import importlib.util
from pathlib import Path

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
