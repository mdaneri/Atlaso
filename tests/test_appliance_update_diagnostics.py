"""Safe typed diagnostics for PowerShell-backed Appliance Update operations."""

import base64
import importlib.machinery
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def helper():
    """Load the appliance helper as a test-local Python module."""
    path = Path(__file__).resolve().parents[1] / "scripts/appliance/atlaso-helper"
    loader = importlib.machinery.SourceFileLoader("update_diagnostics_helper", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def decode_command_script(helper, command: list[str]) -> str:
    """Decode the generated UTF-16LE PowerShell command for stage assertions.

    Args:
        helper: Loaded appliance helper module.
        command: Command arguments containing an encoded PowerShell script.
    """
    encoded = command[-1]
    return base64.b64decode(encoded).decode("utf-16-le")


def test_diagnostic_marker_is_strictly_projected_and_malformed_data_is_generic(helper, monkeypatch):
    """Never copy marker-injected exception or URL text into typed diagnostics.

    Args:
        helper: Loaded appliance helper module.
        monkeypatch: Pytest monkeypatch fixture.
    """
    def run(command, *, env=None):
        """Return malformed marker data as if from the command runner.

        Args:
            command: Command arguments passed to the runner.
            env: Optional environment supplied to the runner.
        """
        return subprocess.CompletedProcess(
            command,
            1,
            "ATLASO_UPDATE_DIAGNOSTIC:{\"stage\":\"unknown\",\"reason\":\"http_failed\","
            "\"http_status\":999,\"exception\":\"https://user:secret@example.invalid/token\"}\n",
            "ATLASO_UPDATE_DIAGNOSTIC:{malformed secret=private}\n",
        )

    monkeypatch.setattr(helper, "_run", run)
    result = helper._command_payload(
        ["pwsh", "stub"], update_diagnostic_stage="repository_probe"
    )
    diagnostic = result["update_diagnostic"]
    assert diagnostic["stage"] == "repository_probe"
    assert diagnostic["reason"] == "helper_failed"
    assert diagnostic["http_status"] is None
    assert 0 <= diagnostic["elapsed_ms"] <= 86_400_000
    assert "secret" not in json.dumps(diagnostic)
    assert "ATLASO_UPDATE_DIAGNOSTIC" not in result["stdout"] + result["stderr"]


@pytest.mark.parametrize(
    ("reason", "status"),
    [
        ("proxy_auth_required", 407),
        ("http_denied", 403),
        ("http_failed", 503),
        ("dns_failed", None),
        ("connection_refused", None),
        ("timed_out", None),
        ("tls_failed", None),
    ],
)
def test_valid_marker_accepts_only_fixed_reason_and_bounded_status(helper, reason, status):
    """Project only the fixed diagnostic schema and bounded HTTP status.

    Args:
        helper: Loaded appliance helper module.
        reason: Expected fixed diagnostic reason.
        status: Expected HTTP status, or ``None`` when absent.
    """
    marker = json.dumps(
        {"stage": "repository_probe", "reason": reason, "http_status": status},
        separators=(",", ":"),
    )
    stage, actual_reason, actual_status, stdout, stderr = helper._parse_update_diagnostic_marker(
        "ordinary output\n",
        helper.UPDATE_DIAGNOSTIC_MARKER + marker + "\n",
        fallback_stage="repository_registration",
        success=False,
    )
    assert (stage, actual_reason, actual_status) == ("repository_probe", reason, status)
    assert stdout == "ordinary output"
    assert stderr == ""


@pytest.mark.parametrize(
    ("reason", "status"),
    [
        ("proxy_auth_required", 403),
        ("http_denied", 407),
        ("http_failed", 200),
        ("none", 503),
        ("dns_failed", 503),
    ],
)
def test_inconsistent_http_marker_falls_back_to_generic_failure(helper, reason, status):
    """Reject reason/status combinations the typed event schema cannot represent.

    Args:
        helper: Loaded appliance helper module.
        reason: Diagnostic reason paired with a deliberately inconsistent status.
        status: HTTP status that conflicts with the reason.
    """
    marker = json.dumps(
        {"stage": "repository_probe", "reason": reason, "http_status": status},
        separators=(",", ":"),
    )
    stage, actual_reason, actual_status, _stdout, _stderr = helper._parse_update_diagnostic_marker(
        "",
        helper.UPDATE_DIAGNOSTIC_MARKER + marker,
        fallback_stage="repository_registration",
        success=False,
    )
    assert (stage, actual_reason, actual_status) == (
        "repository_registration",
        "helper_failed",
        None,
    )


def test_repository_sync_marks_registration_and_probe_stages(helper):
    """Put explicit stage transitions before repository mutation and probing.

    Args:
        helper: Loaded appliance helper module.
    """
    script = helper._powershell_update_diagnostic_script(
        helper._powershell_repository_sync_script(
            "TestRepo", "https://packages.example.invalid/feed", "Untrusted"
        ),
        "repository_registration",
    )
    assert script.index("$atlasoUpdateStage = 'repository_registration'") < script.index(
        "Register-PSRepository"
    )
    assert script.index("$atlasoUpdateStage = 'repository_probe'") < script.index(
        "Find-Module"
    )
    assert "$_ .Exception" not in script
    assert "$atlasoException.Message" not in script


def test_check_and_install_scripts_mark_each_meaningful_stage(helper, monkeypatch):
    """Keep module discovery, installation, import, and CEIP stages distinct.

    Args:
        helper: Loaded appliance helper module.
        monkeypatch: Pytest monkeypatch fixture.
    """
    captured: list[str] = []

    def capture(command, **_kwargs):
        """Capture generated commands and return a successful stub result.

        Args:
            command: Command arguments passed to the helper runner.
            **_kwargs: Additional runner keyword arguments.
        """
        if "-EncodedCommand" in command:
            captured.append(decode_command_script(helper, command))
        return {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": '{"Name":"VCF.PowerCLI","AvailableVersion":"1.0","InstalledVersions":[]}',
            "stderr": "",
            "update_diagnostic": {
                "stage": "module_discovery",
                "reason": "none",
                "http_status": None,
                "elapsed_ms": 0,
            },
        }

    monkeypatch.setattr(helper, "_command_path", lambda _name: "pwsh")
    monkeypatch.setattr(helper, "_privileged_powershell_environment", lambda: {})
    monkeypatch.setattr(helper, "_command_payload", capture)
    monkeypatch.setattr(helper, "_unsynchronized_update_sources", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        helper,
        "_enabled_sources",
        lambda *_args, **_kwargs: [{"name": "TestRepo", "url": "https://packages.example.invalid/feed"}],
    )
    payload = {
        "selected_streams": ["powershell_modules"],
        "sources": {"powershell_repository_name": "TestRepo"},
        "powershell_modules": [
            {
                "name": "VCF.PowerCLI",
                "repository_name": "TestRepo",
                "target_version": "1.0",
                "policy": "pinned",
            }
        ],
        "policy": {"vmware_ceip_enabled": True},
    }
    helper._check_appliance_update(payload)
    check_script = captured[0]
    assert check_script.index("$atlasoUpdateStage = 'repository_probe'") < check_script.index(
        "Get-PSRepository"
    )
    assert check_script.index("$atlasoUpdateStage = 'module_discovery'") < check_script.index(
        "Get-Module"
    )
    assert check_script.rindex("$atlasoUpdateStage = 'repository_probe'") < check_script.index(
        "Find-Module"
    )

    helper._apply_powershell_modules(payload)
    install_script = captured[1]
    stages = [
        "$atlasoUpdateStage = 'module_install'",
        "$atlasoUpdateStage = 'module_discovery'",
        "$atlasoUpdateStage = 'module_import'",
        "$atlasoUpdateStage = 'ceip_configuration'",
    ]
    positions = [install_script.index(stage) for stage in stages]
    assert positions == sorted(positions)


@pytest.mark.parametrize(
    ("returncode", "reason", "expected_status", "sync_status"),
    [
        (0, "none", None, "succeeded"),
        (1, "dns_failed", None, "failed"),
        (1, "helper_failed", None, "failed"),
    ],
)
def test_sync_uses_powershell_result_without_python_dns_preflight(
    helper, monkeypatch, tmp_path, returncode, reason, expected_status, sync_status
):
    """Trust the PowerShell client result and never preflight with Python DNS.

    Args:
        helper: Loaded appliance helper module.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Isolated directory for source-state files.
        returncode: Stubbed PowerShell client exit code.
        reason: Typed diagnostic reason returned by the client.
        expected_status: Expected HTTP status, or ``None`` when absent.
        sync_status: Expected synchronization outcome.
    """
    source_state = tmp_path / "source-state.json"
    monkeypatch.setattr(helper, "UPDATE_SOURCE_STATE_PATH", source_state)
    monkeypatch.setattr(helper, "MANAGED_PHOTON_REPO_PATH", tmp_path / "managed-photon.repo")
    monkeypatch.setattr(helper, "_command_path", lambda name: "pwsh" if name == "pwsh" else None)
    monkeypatch.setattr(helper, "_privileged_powershell_environment", lambda: {"PATH": str(tmp_path)})

    def fail_lookup(*_args, **_kwargs):
        """Fail if the sync path attempts Python-side DNS resolution.

        Args:
            *_args: Positional resolver arguments.
            **_kwargs: Keyword resolver arguments.
        """
        raise AssertionError("Python DNS preflight must not run")

    monkeypatch.setattr(helper.socket, "getaddrinfo", fail_lookup)
    marker = json.dumps(
        {"stage": "repository_probe", "reason": reason, "http_status": expected_status},
        separators=(",", ":"),
    )

    def run(command, *, env=None):
        """Return the configured PowerShell client result.

        Args:
            command: Command arguments passed to the runner.
            env: Optional environment supplied to the runner.
        """
        return subprocess.CompletedProcess(
            command,
            returncode,
            "",
            helper.UPDATE_DIAGNOSTIC_MARKER + marker + "\n",
        )

    monkeypatch.setattr(helper, "_run", run)
    result = helper._sync_appliance_update_sources(
        {
            "source_definitions": [
                {
                    "id": "repo1",
                    "kind": "powershell",
                    "name": "TestRepo",
                    "url": "https://packages.example.invalid/feed",
                    "enabled": True,
                    "settings": {},
                }
            ]
        }
    )
    command = result["commands"][0]
    assert result["status"] == sync_status
    assert result["source_results"] == [
        {"id": "repo1", "kind": "powershell", "name": "TestRepo", "success": returncode == 0}
    ]
    diagnostic = command["update_diagnostic"]
    assert diagnostic["stage"] == "repository_probe"
    assert diagnostic["reason"] == reason
    assert diagnostic["http_status"] is None
    assert 0 <= diagnostic["elapsed_ms"] <= 86_400_000


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is not installed")
@pytest.mark.parametrize(
    ("exception_expression", "reason", "status"),
    [
        (
            "[System.Exception]::new('outer SECRET_BAIT', [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::HostNotFound))",
            "dns_failed",
            None,
        ),
        (
            "[System.Exception]::new('outer SECRET_BAIT', [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::ConnectionRefused))",
            "connection_refused",
            None,
        ),
        (
            "[System.Exception]::new('outer SECRET_BAIT', [System.Security.Authentication.AuthenticationException]::new('inner SECRET_BAIT'))",
            "tls_failed",
            None,
        ),
        (
            "[System.Net.Http.HttpRequestException]::new('SECRET_BAIT', [System.Exception]::new('inner SECRET_BAIT'), [System.Net.HttpStatusCode]::ProxyAuthenticationRequired)",
            "proxy_auth_required",
            407,
        ),
        (
            "[System.Net.Http.HttpRequestException]::new('SECRET_BAIT', [System.Exception]::new('inner SECRET_BAIT'), [System.Net.HttpStatusCode]::Forbidden)",
            "http_denied",
            403,
        ),
        (
            "[System.Net.Http.HttpRequestException]::new('SECRET_BAIT', [System.Exception]::new('inner SECRET_BAIT'), [System.Net.HttpStatusCode]::ServiceUnavailable)",
            "http_failed",
            503,
        ),
        (
            "[System.Exception]::new('outer SECRET_BAIT', [System.TimeoutException]::new('inner SECRET_BAIT'))",
            "timed_out",
            None,
        ),
        ("[System.Exception]::new('SECRET_BAIT')", "helper_failed", None),
    ],
)
def test_local_pwsh_exception_emits_only_typed_diagnostic(helper, exception_expression, reason, status):
    """Run local failing scripts with inner exceptions, secret bait, and no network.

    Args:
        helper: Loaded appliance helper module.
        exception_expression: PowerShell expression that throws the test exception.
        reason: Expected fixed diagnostic reason.
        status: Expected HTTP status, or ``None`` when absent.
    """
    pwsh = shutil.which("pwsh")
    assert pwsh is not None
    wrapped = helper._powershell_update_diagnostic_script(
        f"$atlasoUpdateStage = 'repository_probe'; throw {exception_expression}",
        "repository_registration",
    )
    result = helper._command_payload(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", helper._powershell_encoded_command(wrapped)],
        update_diagnostic_stage="repository_registration",
    )
    assert result["success"] is False
    assert result["update_diagnostic"]["stage"] == "repository_probe"
    assert result["update_diagnostic"]["reason"] == reason
    assert result["update_diagnostic"]["http_status"] == status
    assert "SECRET_BAIT" not in json.dumps(result["update_diagnostic"])
    assert "ATLASO_UPDATE_DIAGNOSTIC" not in result["stdout"] + result["stderr"]


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is not installed")
def test_local_pwsh_success_preserves_existing_json_stdout(helper):
    """Keep a successful module result parseable while consuming the safe marker.

    Args:
        helper: Loaded appliance helper module.
    """
    pwsh = shutil.which("pwsh")
    assert pwsh is not None
    wrapped = helper._powershell_update_diagnostic_script(
        "[pscustomobject]@{Name='Example.Module';Version='1.2.3'} | ConvertTo-Json -Compress",
        "module_discovery",
    )
    result = helper._command_payload(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", helper._powershell_encoded_command(wrapped)],
        update_diagnostic_stage="module_discovery",
    )
    assert result["success"] is True
    assert json.loads(result["stdout"]) == {"Name": "Example.Module", "Version": "1.2.3"}
    assert result["update_diagnostic"]["stage"] == "module_discovery"
    assert result["update_diagnostic"]["reason"] == "none"
    assert result["update_diagnostic"]["http_status"] is None
