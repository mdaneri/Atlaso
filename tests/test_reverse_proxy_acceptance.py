"""Verify native proxy fixture behavior and focused lifecycle admission."""

import http.client
import importlib.util
import io
import json
import os
import shutil
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_module(name, filename):
    """Load an admitted lifecycle source without writing bytecode.

    Args:
        name: Unique module registry name.
        filename: Checked-in interop filename.
    """
    path = Path(__file__).parents[1] / "scripts" / "interop" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_focused_mode_secrets_and_plan():
    """Admit the focused password envelope without unrelated VCF credentials."""
    lifecycle = load_module("proxy_lifecycle_test", "lifecycle_test.py")
    args = lifecycle.parse_args(["--reverse-proxy-only", "--reverse-proxy-upstream-host", "192.0.2.2"])
    lifecycle.load_lifecycle_secrets(args, io.StringIO(json.dumps({"password": "fixture", "appliance_ssh_password": "fixture", "ssh_password": "fixture"})))
    plan = lifecycle.lifecycle_plan(args)
    assert plan["reverse_proxy_only"]
    assert not plan["client_checks_enabled"]
    assert "dnsmasq" in plan["apply_units"]
    with pytest.raises(SystemExit):
        lifecycle.parse_args(["--reverse-proxy-only", "--time-source-only"])


def test_fixture_challenge_and_bounded_echo():
    """Serve the real fixture socket and preserve the application's challenge."""
    module = load_module("proxy_acceptance_test", "reverse_proxy_acceptance.py")
    server = module.FixtureServer(("127.0.0.1", 0), module.FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("GET", "/value?q=1", headers={"X-Forwarded-Proto": "https"})
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["path"] == "/value?q=1"
        connection.close()
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        connection.request("GET", "/auth")
        response = connection.getresponse()
        assert response.status == 401
        assert response.getheader("WWW-Authenticate")
        assert response.read() == b""
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.skipif(os.name != "nt" or not shutil.which("node"), reason="Windows Node job boundary")
def test_browser_failure_terminates_its_owned_job(tmp_path):
    """Launch the actual stdin-gated Node consumer and prove failure cleanup.

    Args:
        tmp_path: Test-owned lifecycle result root.
    """
    module = load_module("proxy_browser_test", "reverse_proxy_browser.py")
    client = SimpleNamespace(base_url="http://invalid.example.test", cookie_jar=[])
    args = SimpleNamespace(result_dir=str(tmp_path), reverse_proxy_screenshot_dir=str(tmp_path / "screenshots"),
                           reverse_proxy_screenshot_node=shutil.which("node"), reverse_proxy_screenshot_packages="unused",
                           reverse_proxy_screenshot_browser="unused")
    with pytest.raises(RuntimeError, match="^Reverse-proxy browser capture failed\\.$"):
        module.capture_ui(client, args)
    assert list((tmp_path / "screenshots").iterdir()) == []
