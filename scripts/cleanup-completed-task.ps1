<#
.SYNOPSIS
Preview or execute ownership-checked completed-task cleanup with a live controller.
.DESCRIPTION
Run from the primary checkout. Preview is the default and emits only JSON lines.
The controller answers fresh requests on stdin using supported Codex tools.
Execution revalidates every transition and never bypasses tool policy.
.PARAMETER Handoff
Absolute path to the durable schema-1 cleanup-ready handoff.
.PARAMETER Evidence
Absolute durable evidence directory under the configured worktree root, outside the target.
.PARAMETER Config
Absolute path to the supported Codex config.toml containing desktop.git-worktree-root.
.PARAMETER Execute
Perform eligible transitions. Omit for a read-only preview.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Handoff,
    [Parameter(Mandatory = $true)][string]$Evidence,
    [Parameter(Mandatory = $true)][string]$Config,
    [switch]$Execute
)
$ErrorActionPreference = 'Stop'
$bootstrap = @'
import runpy, sys, types
package = types.ModuleType("scripts")
package.__path__ = [sys.argv.pop(1)]
sys.modules["scripts"] = package
runpy.run_module("scripts.completed_task_cleanup", run_name="__main__")
'@
$arguments = @('-I', '-S', '-B', '-c', $bootstrap, $PSScriptRoot, '--handoff', $Handoff,
    '--evidence', $Evidence, '--config', $Config)
if ($Execute) { $arguments += '--execute' }
& python @arguments
exit $LASTEXITCODE
