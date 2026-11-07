<#
.SYNOPSIS
Verify exclusive deployment-root creation and original receipt publication without a VM.
.PARAMETER RepositoryRoot
Task checkout containing the candidate deployment owner and native filesystem primitives.
.PARAMETER OutputRoot
Absent ordinary test-results child receiving this originally owned validation resource.
.PARAMETER PullRequestNumber
Positive PR owning the current task's focused validation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][string]$OutputRoot,
    [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$PullRequestNumber
)
$ErrorActionPreference = 'Stop'
$helpers = Join-Path $RepositoryRoot 'scripts/windows/vmware'
Import-Module (Join-Path $helpers 'Atlaso.WorkstationCleanup.psm1') -Force
. (Join-Path $helpers 'Atlaso.LifecycleOwnership.ps1')
$durableRoot = Get-AtlasoLifecycleDurableRoot
$ownerPath = Join-Path $helpers 'deploy-certificate-iso-wheel.ps1'
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ownerPath, [ref]$null, [ref]$errors)
$functions = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'New-CertificateIsoDeploymentOutput'
}, $false))
if ($errors.Count -or $functions.Count -ne 1) { throw 'The deployment output owner is missing or ambiguous.' }
. ([scriptblock]::Create($functions[0].Extent.Text))
$source = ([string](& git -C $RepositoryRoot rev-parse --verify HEAD)).Trim()
if ($LASTEXITCODE -ne 0 -or $source -cnotmatch '^[0-9a-f]{40}$') { throw 'The validation source is unavailable.' }
$arguments = @{ DurableRoot = $durableRoot; Worktree = $RepositoryRoot; OutputRoot = $OutputRoot
    TaskId = $env:CODEX_THREAD_ID; SourceCommit = $source; PullRequestNumber = $PullRequestNumber }
$output = New-CertificateIsoDeploymentOutput @arguments
try {
    $receipt = Get-Content -LiteralPath $output.Ownership.path -Raw | ConvertFrom-Json
    $identity = [Atlaso.WorkstationFileIdentity]::Get($OutputRoot)
    $expectedIdentity = '{0:X8}:{1:X8}{2:X8}' -f [uint32]$receipt.root_identity[0], [uint32]$receipt.root_identity[1], [uint32]$receipt.root_identity[2]
    if ($identity -cne $expectedIdentity -or $receipt.source_commit -cne $source -or
        $receipt.task_id -cne $env:CODEX_THREAD_ID -or $receipt.repository -cne 'mdaneri/Atlaso' -or
        $receipt.pr -ne $PullRequestNumber -or $receipt.path -ine $OutputRoot -or
        @(Get-ChildItem -LiteralPath $OutputRoot -Force).Count -ne 0 -or
        (Get-FileHash -LiteralPath $output.Ownership.path -Algorithm SHA256).Hash -ine $output.Ownership.sha256) {
        throw 'The output was used before its original identity was independently readable.'
    }
    $receiptDirectory = Join-Path $durableRoot '.task-ownership'
    $originalReceipts = @(Get-ChildItem -LiteralPath $receiptDirectory -Filter 'atlaso-lifecycle-original-*.json' -File).Count
    $refused = $false
    try { $unexpected = New-CertificateIsoDeploymentOutput @arguments; $unexpected.Pin.Dispose() }
    catch { $refused = $true }
    if (-not $refused -or @(Get-ChildItem -LiteralPath $receiptDirectory -Filter 'atlaso-lifecycle-original-*.json' -File).Count -ne $originalReceipts) {
        throw 'An existing directory was adopted or produced replacement ownership.'
    }
    [IO.File]::WriteAllText((Join-Path $OutputRoot 'verified-after-original-receipt.txt'), 'Created after receipt verification.')
    [pscustomobject]@{ Status = 'passed'; OriginalOwnership = $output.Ownership
        OriginalIdentity = $identity; ExistingDirectoryRefused = $true }
} finally { $output.Pin.Dispose() }
