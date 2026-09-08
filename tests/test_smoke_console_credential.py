"""Verify isolated 1Password handoff and redacted failure behavior without real secrets."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from scripts.virtualization import smoke_console_credential as console


class FakePlugin:
    """Model only the supported 1Password Environment tool contract."""

    def __init__(self) -> None:
        """Keep unrelated concealed defaults alongside per-run test variables."""
        self.variables: dict[str, dict[str, Any]] = {
            "DEFAULT_ADMIN_PASSWORD": {"value": "fixture-default", "concealed": True}
        }
        self.environment = "fixture-environment"
        self.available = True
        self.writes = 0

    def tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Simulate metadata admission and concealed variable creation.

        Args:
            name: Supported 1Password tool name to invoke.
            arguments: Tool arguments, which may contain a concealed credential.
        """
        if not self.available:
            raise RuntimeError("fixture-sensitive-provider-error")
        if name == "authenticate":
            return {"account_id": "fixture-account"}
        if name == "list_environments":
            return {
                "environments": [{"name": "Atlaso", "environmentId": self.environment}]
            }
        if name == "list_variables":
            return {"variableNames": list(self.variables)}
        if name == "append_variables":
            self.writes += 1
            for variable in arguments["variables"]:
                assert variable["name"] not in self.variables
                self.variables[variable["name"]] = variable
            return {}
        raise AssertionError(name)


@pytest.fixture
def plugin(monkeypatch: pytest.MonkeyPatch) -> FakePlugin:
    """Pin the test Environment independently of production account configuration.

    Args:
        monkeypatch: Pytest fixture restoring the isolated configuration and provider replacements.
    """
    monkeypatch.setattr(
        console,
        "ENVIRONMENT_DIGEST",
        hashlib.sha256(b"fixture-environment").hexdigest(),
    )
    return FakePlugin()


def test_parallel_run_names_and_values_are_isolated(plugin: FakePlugin) -> None:
    """Independent runs cannot overwrite defaults or share their generated credential.

    Args:
        plugin: Isolated plugin session used for Environment admission and publication.
    """
    first = console.publish(plugin, plugin.environment, "a" * 32)
    second = console.publish(plugin, plugin.environment, "b" * 32)
    assert first != second
    assert len(first) >= 40
    assert plugin.variables["DEFAULT_ADMIN_PASSWORD"]["value"] == "fixture-default"
    for run in ("A", "B"):
        assert plugin.variables["ATLASO_SMOKE_CONSOLE_" + run * 32]["concealed"] is True


def test_duplicate_run_refuses_before_another_write(plugin: FakePlugin) -> None:
    """A repeated identity preserves its existing secret instead of appending a duplicate.

    Args:
        plugin: Isolated plugin session used for Environment admission and publication.
    """
    console.publish(plugin, plugin.environment, "a" * 32)
    with pytest.raises(ValueError, match="already exists"):
        console.publish(plugin, plugin.environment, "a" * 32)
    assert plugin.writes == 1


@pytest.mark.parametrize(
    "environment,run", [("wrong", "a" * 32), ("fixture-environment", "../bad")]
)
def test_invalid_identity_precedes_provider_writes(
    plugin: FakePlugin, environment: str, run: str
) -> None:
    """Neither an unexpected Environment nor a malformed run may receive credentials.

    Args:
        plugin: Isolated plugin session used for Environment admission and publication.
        environment: Candidate Environment identifier used to exercise admission refusal.
        run: Candidate run identifier used to exercise admission refusal.
    """
    with pytest.raises(ValueError):
        console.publish(plugin, environment, run)
    assert plugin.writes == 0


def test_environment_readback_must_match(plugin: FakePlugin) -> None:
    """A changed Environment listing cannot silently select a similarly named target.

    Args:
        plugin: Isolated plugin session used for Environment admission and publication.
    """
    plugin.environment = "wrong-environment"
    with pytest.raises(ValueError, match="unavailable"):
        console.publish(plugin, "fixture-environment", "a" * 32)
    assert plugin.writes == 0


def test_unavailable_plugin_precedes_publication(plugin: FakePlugin) -> None:
    """Missing authentication does not fall back to defaults or plaintext transport.

    Args:
        plugin: Isolated plugin session used for Environment admission and publication.
    """
    plugin.available = False
    with pytest.raises(RuntimeError):
        console.publish(plugin, plugin.environment, "a" * 32)
    assert plugin.writes == 0


def test_cli_failure_does_not_print_provider_detail(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys
) -> None:
    """The command boundary suppresses arbitrary provider exception material.

    Args:
        monkeypatch: Pytest fixture restoring the isolated configuration and provider replacements.
        tmp_path: Invocation-owned temporary directory for the protected output fixture.
        capsys: Pytest capture fixture used to check provider-detail redaction.
    """

    def unavailable(_executable: str) -> None:
        """Fail like a secret-bearing SDK exception before returning a session.

        Args:
            _executable: Ignored executable argument accepted by the failing provider fixture.
        """
        raise RuntimeError("fixture-sensitive-provider-error")

    monkeypatch.setattr(console, "Plugin", unavailable)
    monkeypatch.setattr(
        "sys.argv",
        [
            "console",
            "--plugin",
            "fixture",
            "--environment-id",
            "fixture",
            "--run-id",
            "a" * 32,
            "--output",
            str(tmp_path / "bundle"),
        ],
    )
    assert console.main() == 1
    assert "fixture-sensitive-provider-error" not in capsys.readouterr().out
    assert not (tmp_path / "bundle").exists()
