"""Exercise normal creator launch modes without a provider or credential access."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/windows/vmware/create-atlaso-test-vm.ps1"
pytestmark = pytest.mark.skipif(not shutil.which("pwsh"), reason="PowerShell runtime required")


def run_fixture(tmp_path, body):
    """Extract only the reviewed functions and run bounded, public native stubs.

    Args:
        tmp_path: Originally owned pytest output directory.
        body: Test invocation and assertions collected as JSON.
    """
    source = "'" + str(SOURCE).replace("'", "''") + "'"
    script = tmp_path / "headless.ps1"
    script.write_text(r"""
$ErrorActionPreference='Stop'
$sourcePath=@SOURCE@
$ast=[Management.Automation.Language.Parser]::ParseFile($sourcePath,[ref]$null,[ref]$null)
foreach($name in @('Complete-AtlasoDevelopmentCaSuccessfulImport','Invoke-PendingAtlasoDevelopmentCaCleanup')) {
    $functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
    if($functions.Count -ne 1){throw 'Missing or ambiguous function'}
    Set-Item -Path ('Function:\'+$name) -Value ($functions[0].Body.GetScriptBlock())
}
$events=[Collections.Generic.List[string]]::new()
$modes=[Collections.Generic.List[string]]::new()
$guard=0
function Assert-AtlasoTestVmCheckoutSource {param($Context)
    $script:guard++;$events.Add('source')
    if($script:guard -eq $refuseGuard){throw 'Source guard refused'}
}
function Set-AtlasoDevelopmentCaCleanupMarkerPhase {param($MarkerPath,$ExpectedPhase,$Phase)
    $events.Add('phase:'+$Phase)
}
function Stop-AtlasoTestVmForRollback {param($VmxPath,$VmrunPath,$TimeoutSeconds,$Mode)
    if($Mode -cne 'soft'){throw 'Unexpected hard stop'};$events.Add('stop')
}
function Clear-AtlasoWorkstationDevelopmentRootCaPrivateKey {param($VmxPath) $events.Add('scrub')}
function Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub {param($VmxPath,$VmrunPath,$TimeoutSeconds) $events.Add('readback')}
function Remove-AtlasoDevelopmentCaCleanupMarker {param($MarkerPath) $events.Add('retire')}
function Invoke-AtlasoBoundedProcess {param($FilePath,$ArgumentList,$TimeoutSeconds,$Action)
    $index=[Array]::IndexOf($ArgumentList,'-Mode')
    if($index -lt 0){throw 'Launch mode missing'}
    $modes.Add($ArgumentList[$index+1]);$events.Add('launch')
}
""".replace("@SOURCE@", source) + body, encoding="utf-8")
    result = subprocess.run([shutil.which("pwsh"), "-NoProfile", "-NonInteractive", "-File", str(script)],
                            capture_output=True, text=True, check=False, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("mode,refuse_guard", [(None, 0), ("nogui", 0), ("nogui", 1), ("nogui", 2)])
def test_headless_restart_preserves_source_stop_scrub_and_readback(tmp_path, mode, refuse_guard):
    """Changing launch mode cannot skip signer custody or a fresh source refusal.

    Args:
        tmp_path: Originally owned pytest output directory.
        mode: Default GUI compatibility or explicit headless operation.
        refuse_guard: Refuse before stop or immediately before restart.
    """
    option = "" if mode is None else f"-StartMode '{mode}'"
    evidence = run_fixture(tmp_path, f"$refuseGuard={refuse_guard};" + r"""
$marker=[pscustomobject]@{Schema=3;Phase='staged';VmxPath='fixture.vmx';MarkerPath='fixture.json'}
$context=[pscustomobject]@{Enabled=$true;VmxPath='fixture.vmx'}
$failure=''
try { Complete-AtlasoDevelopmentCaSuccessfulImport -Marker $marker -VmrunPath 'unused' -TimeoutSeconds 5 -OwnershipContext $context @OPTION@ }
catch {$failure=$_.Exception.Message}
@{events=@($events);modes=@($modes);failure=$failure;phase=$marker.Phase}|ConvertTo-Json -Compress
""".replace("@OPTION@", option))
    events = evidence["events"]
    if refuse_guard:
        assert evidence["failure"] == "Source guard refused"
        assert evidence["modes"] == []
        assert "retire" not in events
        if refuse_guard == 1:
            assert events == ["source"]
        else:
            assert events.count("source") == 2
            assert events.index("stop") < events.index("scrub")
            assert evidence["phase"] == "import-proven-stopped-vmx-scrubbed"
    else:
        assert evidence["failure"] == ""
        assert evidence["modes"] == [mode or "gui"]
        assert events.count("source") == 2
        assert events.index("stop") < events.index("scrub") < events.index("launch")
        assert events.index("launch") < events.index("readback") < events.index("retire")


@pytest.mark.parametrize("mode", ["gui", "nogui"])
def test_pending_import_recovery_forwards_launch_mode(tmp_path, mode):
    """A resumed import retains the selected mode at the existing completion gate.

    Args:
        tmp_path: Originally owned pytest output directory.
        mode: Supported launch mode carried through pending-marker recovery.
    """
    evidence = run_fixture(tmp_path, r"""
$refuseGuard=0
$markers=Join-Path $PSScriptRoot 'markers';$null=New-Item -ItemType Directory -Path $markers
[IO.File]::WriteAllText((Join-Path $markers 'pending.json'),'public marker fixture')
function Assert-AtlasoStrictDescendantPath {param($ParentPath,$ChildPath,$FailureMessage)}
function Read-AtlasoDevelopmentCaCleanupMarker {param($MarkerPath,$MarkerRoot)
    [pscustomobject]@{Phase='import-proven-stopped-vmx-scrubbed';VmxPath='fixture.vmx';MarkerPath=$MarkerPath}
}
function Complete-AtlasoDevelopmentCaSuccessfulImport {param($Marker,$VmrunPath,$TimeoutSeconds,$OwnershipContext,$StartMode)
    $modes.Add($StartMode)
}
Invoke-PendingAtlasoDevelopmentCaCleanup -VmrunPath 'unused' -TimeoutSeconds 5 -MarkerRoot $markers -StartMode '@MODE@'
@{modes=@($modes)}|ConvertTo-Json -Compress
""".replace("@MODE@", mode))
    assert evidence["modes"] == [mode]


@pytest.mark.parametrize("headless", [False, True])
def test_initial_launch_uses_requested_mode(tmp_path, headless):
    """Evaluate the real initial-launch command without invoking a VM or SDK.

    Args:
        tmp_path: Originally owned pytest output directory.
        headless: Whether the creator's public switch selects a background start.
    """
    evidence = run_fixture(tmp_path, "$refuseGuard=0;$Headless=$" + str(headless).lower() + r""";
$targetVmx='fixture.vmx';$resolvedVmrunPath='unused';$TimeoutSeconds=5
$command=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Invoke-AtlasoBoundedProcess' -and $node.Extent.Text.Contains("-Action 'Start the normal test VM after development-signer staging'")},$true))
if($command.Count -ne 1){throw 'Initial launch missing or ambiguous'}
$launch=[Management.Automation.Language.Parser]::ParseInput($command[0].Extent.Text,$sourcePath,[ref]$null,[ref]$null)
. ($launch.GetScriptBlock())
@{modes=@($modes)}|ConvertTo-Json -Compress
""")
    assert evidence["modes"] == ["nogui" if headless else "gui"]
