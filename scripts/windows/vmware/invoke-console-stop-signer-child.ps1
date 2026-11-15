<#
.SYNOPSIS
Admit a separately contained console-stop signer child and refuse the unavailable backend.
.DESCRIPTION
Source-only prerequisite. No key selector, SDK access, signing, acknowledgement,
transport, console input or native acceptance is implemented. Exit 78 is reached
only after the complete original child handoff has been admitted.
.PARAMETER VmxPath
Exact original normal test VMX; no VM operation is performed.
.PARAMETER OwnershipReceiptPath
Original normal VM creation receipt independently retained by the parent.
.PARAMETER OwnershipReceiptSha256
Independently retained original creation receipt digest.
.PARAMETER PullRequestNumber
Original same-repository task pull request.
.PARAMETER RequestPath
Original immutable signing request published before child creation.
.PARAMETER RequestSha256
Independently retained request digest from the original live parent.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VmxPath,
    [Parameter(Mandatory)][string]$OwnershipReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$OwnershipReceiptSha256,
    [Parameter(Mandatory)][ValidateRange(1,2147483647)][int]$PullRequestNumber,
    [Parameter(Mandatory)][string]$RequestPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RequestSha256
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.SourceSnapshot.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.TestVmOwnership.ps1')
. (Join-Path $PSScriptRoot 'Atlaso.ConsoleCredentialTransaction.ps1')
$context=$null; $transaction=$null; $request=$null
try {
    $worktree=(Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
    $commit=([string](& git -C $worktree rev-parse HEAD)).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Signer source lookup failed.' }
    $branch=([string](& git -C $worktree branch --show-current)).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Signer branch lookup failed.' }
    $context=New-AtlasoTestVmOwnershipContext -Worktree $worktree -VmxPath $VmxPath `
        -OutputDirectory ([IO.Path]::GetDirectoryName($VmxPath)) -Name ([IO.Path]::GetFileNameWithoutExtension($VmxPath)) `
        -SourceCommit $commit -SourceBranch $branch -PullRequestNumber $PullRequestNumber `
        -OwnershipReceiptPath $OwnershipReceiptPath -OwnershipReceiptSha256 $OwnershipReceiptSha256
    if (-not $context.Enabled) { throw 'Signer requires original normal task ownership.' }
    Assert-AtlasoTestVmCheckoutSource -Context $context
    $null=Assert-AtlasoTestVmOriginalOwnership -Context $context
    $request=Read-AtlasoConsoleTransactionRecord -Context $context -Path $RequestPath -Sha256 $RequestSha256 `
        -Keys @('schema','phase','binding','observed_utc','details')
    $b=$request.Value.binding; $d=$request.Value.details
    if ($b -isnot [Collections.IDictionary] -or $d -isnot [Collections.IDictionary]) { throw 'Signer request object required.' }
    $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'invoke-installation-iso-test.ps1'),[ref]$null,[ref]$errors)
    if ($errors.Count) { throw 'Shared console provider verifier source refused.' }
    foreach ($name in @('Initialize-InstallationConsolePeerVerifier','Get-InstallationVncPeer')) {
        $functions=@($ast.FindAll({param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
        },$true))
        if ($functions.Count -ne 1) { throw 'Shared console verifier declaration refused.' }
        . ([scriptblock]::Create($functions[0].Extent.Text))
    }
    $transaction=Open-AtlasoConsoleCredentialTransaction -Context $context -PlanPath $d.plan_receipt_path `
        -PlanSha256 $d.plan_receipt_sha256 -ProtocolVersion 2 -Options @{
            Account=$b.account; Port=$b.port; ScreenPath=$b.screen_path; ScreenSha256=$b.screen_sha256
            FieldRectangle=$b.field_rectangle; PythonPath=$b.python_path; RuntimeSha256=$b.runtime_sha256; RuntimeFileCount=$b.runtime_file_count}
    Assert-AtlasoConsoleStopSignerChild -Transaction $transaction -RequestPath $RequestPath -RequestSha256 $RequestSha256 -EntryPoint $PSCommandPath
}
catch {
    # Fixed public refusal only. Never print exception values from a future backend.
    [Console]::Error.WriteLine('Console-stop signer child admission refused.')
    exit 77
}
finally {
    Close-AtlasoConsoleCredentialTransaction -Transaction $transaction
    if ($request) { foreach ($pin in $request.Pins) { $pin.Dispose() } }
    if ($context -and $context.PSObject.Properties['CheckoutSourcePin'] -and $context.CheckoutSourcePin) { $context.CheckoutSourcePin.Dispose() }
}
[Console]::Error.WriteLine('Console-stop signing backend is unavailable.')
exit 78
