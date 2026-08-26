"""Test the repository PowerShell analyzer contract."""

from pathlib import Path


def test_password_suppression_gate_uses_the_powershell_ast() -> None:
    """Require broad password-rule suppressions to be parsed, including named arguments."""
    checker = Path("scripts/check_powershell_analysis.ps1").read_text(encoding="utf-8")

    assert "[System.Management.Automation.Language.AttributeAst]" in checker
    assert ".PositionalArguments" in checker
    assert "SuppressMessage(Attribute)?$" in checker
    assert "PSAvoidUsingPlainTextForPassword" in checker
    assert "broadSuppressionPattern" not in checker
