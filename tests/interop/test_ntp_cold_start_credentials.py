"""Keep web and root credentials separate inside the bounded native consumer."""

import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_native as fixture  # noqa: E402 - Local interop entrypoint.


@pytest.mark.parametrize("user", ["admin", "root"])
def test_main_retains_the_separate_ssh_envelope_field(tmp_path, monkeypatch, capsys, user):
    """Both protected envelope values reach run without entering public output.

    Args:
        tmp_path: Temporary directory for the synthetic native plan.
        monkeypatch: Patcher for argv, stdin, and native-consumer entry points.
        capsys: Capture fixture used to verify public output stays sanitized.
        user: Appliance SSH user selected in the plan, either admin or root.
    """
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"appliance_user": user}))
    monkeypatch.setattr(sys, "argv", ["native", "--plan", str(plan_path), "--output", str(tmp_path)])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({
        "password": "synthetic-web-credential", "appliance_ssh_password": "synthetic-root-credential",
    }) + "\n"))
    monkeypatch.setattr(fixture, "admit_plan", lambda _: {})
    captured = {}

    def execute(plan, output, password, *, appliance_password=None):
        """Capture the values passed from main to the bounded runner.

        Args:
            plan: Admitted plan containing the selected appliance user.
            output: Output directory selected by the command line.
            password: Web administrator credential from the protected envelope.
            appliance_password: Separate appliance SSH credential, when supplied.
        """
        captured.update(user=plan["appliance_user"], web=password, ssh=appliance_password)
        return {"success": True}

    monkeypatch.setattr(fixture, "run", execute)
    assert fixture.main() == 0
    assert captured == {"user": user, "web": "synthetic-web-credential", "ssh": "synthetic-root-credential"}
    output = capsys.readouterr().out
    assert "synthetic" not in output and json.loads(output)["success"] is True


def test_missing_root_credential_refuses_before_any_journal_or_authentication(tmp_path, monkeypatch):
    """Explicit root selection cannot fall back to the web credential.

    Args:
        tmp_path: Temporary evidence directory that must remain empty on refusal.
        monkeypatch: Patcher used to bypass admission while preserving the refusal path.
    """
    monkeypatch.setattr(fixture, "admit_plan", lambda _: {})
    with pytest.raises(fixture.Refusal, match="protected_ssh_credential_missing"):
        fixture.run({"appliance_user": "root"}, tmp_path, "synthetic-web-credential")
    assert list(tmp_path.iterdir()) == []
