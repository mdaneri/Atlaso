"""Keep privileged diagnostic collection restricted to fixed observational sources."""

import json
from types import SimpleNamespace

from tests.test_appliance_helper import load_helper_module


def test_helper_rejects_commands_paths_and_unbounded_windows(monkeypatch):
    """Test helper rejects commands paths and unbounded windows.

    Args:
        monkeypatch: Fixture restoring patched dependencies after the test.
    """
    helper = load_helper_module()
    called = []
    monkeypatch.setattr(helper.subprocess, "run", lambda *args, **kwargs: called.append(args))
    for args in (["/etc/shadow"], ["journal-atlaso", "2026-01-01", "2026-01-02", "500"],
                 ["firewall-nftables", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z", "500"],
                 ["journal-atlaso", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "999999"]):
        assert helper.main(["atlaso-helper", "diagnostics", "source", *args]) == 2
    assert not called


def test_helper_invokes_only_installed_isolated_collector(monkeypatch, capsys):
    """Test helper invokes only installed isolated collector.

    Args:
        monkeypatch: Fixture restoring patched dependencies after the test.
        capsys: Fixture capturing public stdout and stderr.
    """
    helper = load_helper_module()
    captured = []

    def run(args, **kwargs):
        """Run.

        Args:
            args: Fixed command arguments or synthetic helper invocation.
            **kwargs: Captured subprocess options for contract verification.
        """
        captured.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"source": "firewall-nftables", "evidence": {"policies": {"INPUT": "DROP"}}}).encode())

    monkeypatch.setattr(helper.subprocess, "run", run)
    assert helper.main(["atlaso-helper", "diagnostics", "source", "firewall-nftables", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "500"]) == 0
    args, kwargs = captured[0]
    assert args[:4] == ["/opt/atlaso/.venv/bin/python", "-I", "-m", "atlaso.diagnostics"]
    assert kwargs["timeout"] == 8
    assert kwargs["stderr"] == helper.subprocess.DEVNULL
    assert json.loads(capsys.readouterr().out)["evidence"]["policies"]["INPUT"] == "DROP"
