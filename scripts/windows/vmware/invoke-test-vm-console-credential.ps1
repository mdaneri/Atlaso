<#
.SYNOPSIS
Submit one concealed credential to an observed field on a receipt-owned normal test VM.
.DESCRIPTION
Uses the existing bounded SDK, original VM ownership admission, pinned VNC runtime,
provider-process proof and complete-frame comparison. It makes no network-readiness
or certificate-address-control claim and never prints console bytes or credentials.
.PARAMETER VmxPath
Exact VMX from the original normal-test-VM creation receipt.
.PARAMETER OwnershipReceiptPath
Immutable original clone receipt preserved at creation.
.PARAMETER OwnershipReceiptSha256
Independently retained creation-time receipt digest.
.PARAMETER PullRequestNumber
Owning same-repository pull request.
.PARAMETER Account
Existing Atlaso Environment account to submit at its observed concealed field.
.PARAMETER Port
Existing VNC listener belonging exclusively to this VM on IPv4 loopback.
.PARAMETER ScreenPath
Task-owned public screenshot of the observed empty concealed field.
.PARAMETER ScreenSha256
Independently retained screenshot SHA-256.
.PARAMETER FieldRectangle
Single concealed input-row rectangle excluded from full-frame comparison.
.PARAMETER PythonPath
Task-owned isolated interpreter containing the reviewed optional VNC client.
.PARAMETER RuntimeSha256
Independently retained deterministic site-packages inventory digest.
.PARAMETER RuntimeFileCount
Original number of files in that client inventory.
.PARAMETER Child
Internal bounded-child selector.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][string]$VmxPath,
    [Parameter(Mandatory)][string]$OwnershipReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$OwnershipReceiptSha256,
    [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$PullRequestNumber,
    [ValidateSet('admin', 'root')][string]$Account = 'root',
    [Parameter(Mandatory)][ValidateRange(1024, 65535)][int]$Port,
    [Parameter(Mandatory)][string]$ScreenPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ScreenSha256,
    [Parameter(Mandatory)][ValidatePattern('^\d{1,4},\d{1,4},\d{1,4},\d{1,4}$')][string]$FieldRectangle,
    [Parameter(Mandatory)][string]$PythonPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$RuntimeSha256,
    [Parameter(Mandatory)][ValidateRange(1, 14000)][int]$RuntimeFileCount,
    [switch]$Child
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
if (-not $PSCmdlet.ShouldProcess($VmxPath, 'Submit one concealed account value to the original VM console')) { return }
if (-not $Child) {
    $arguments = @('-NoProfile', '-NonInteractive', '-File', $PSCommandPath, '-Child',
        '-VmxPath', $VmxPath, '-OwnershipReceiptPath', $OwnershipReceiptPath,
        '-OwnershipReceiptSha256', $OwnershipReceiptSha256, '-PullRequestNumber', [string]$PullRequestNumber,
        '-Account', $Account, '-Port', [string]$Port, '-ScreenPath', $ScreenPath,
        '-ScreenSha256', $ScreenSha256, '-FieldRectangle', $FieldRectangle,
        '-PythonPath', $PythonPath, '-RuntimeSha256', $RuntimeSha256,
        '-RuntimeFileCount', [string]$RuntimeFileCount)
    Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments `
        -TimeoutSeconds 420 -Action 'Receipt-bound normal VM console credential'
    return
}

$worktree = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.SourceSnapshot.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.TestVmOwnership.ps1')
$commit = ([string](& git -C $worktree rev-parse HEAD)).Trim()
$branch = ([string](& git -C $worktree branch --show-current)).Trim()
$context = New-AtlasoTestVmOwnershipContext -Worktree $worktree -VmxPath $VmxPath `
    -OutputDirectory ([IO.Path]::GetDirectoryName($VmxPath)) -Name ([IO.Path]::GetFileNameWithoutExtension($VmxPath)) `
    -SourceCommit $commit -SourceBranch $branch -PullRequestNumber $PullRequestNumber `
    -OwnershipReceiptPath $OwnershipReceiptPath -OwnershipReceiptSha256 $OwnershipReceiptSha256
if (-not $context.Enabled) { throw 'Console credentials require original task ownership admission.' }
$runtime = $null
$inspectorSource = $null
$framePin = $null
$frameDirectoryPin = $null
$pair = $null
$consumer = $null
try {
    Assert-AtlasoTestVmCheckoutSource -Context $context
    $null = Assert-AtlasoTestVmOriginalOwnership -Context $context
    # Reuse only these declarations from the commit-verified installer consumer;
    # never dot-source its entry point or enter its different VM admission path.
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot 'invoke-installation-iso-test.ps1'), [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Shared console adapter source could not be parsed.' }
    foreach ($name in @('Initialize-InstallationConsolePeerVerifier', 'Get-InstallationVncPeer', 'Send-InstallationConsoleSecret')) {
        $functions = @($ast.FindAll({ param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
        }, $true))
        if ($functions.Count -ne 1) { throw 'Shared console adapter declaration is missing or ambiguous.' }
        . ([scriptblock]::Create($functions[0].Extent.Text))
    }
    $peer = Get-InstallationVncPeer -VmxPath $VmxPath -Port $Port
    $ownedPrefix = $worktree.TrimEnd('\', '/') + '\'
    foreach ($path in @($PythonPath, $ScreenPath)) {
        if (-not [IO.Path]::IsPathFullyQualified($path) -or
            -not [IO.Path]::GetFullPath($path).StartsWith($ownedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Console client and public frame must remain in the task checkout.'
        }
        & git -C $worktree check-ignore -q -- $path
        if ($LASTEXITCODE -ne 0) { throw 'Console client and frame must be ignored task resources.' }
    }
    Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
    $selector = Resolve-AtlasoOnePasswordEnvironmentId -RepositoryRoot $worktree
    $token = Resolve-AtlasoOnePasswordServiceAccountTokenFile -RepositoryRoot $worktree `
        -TokenFile (Join-Path $worktree '.atlaso-local/onepassword-service-account-token.dpapi')
    $pair = Get-AtlasoOnePasswordCredentialPair -RepositoryRoot $worktree -EnvironmentId $selector `
        -OnePasswordServiceAccountTokenFile $token -TimeoutSeconds 300 -ConsumerDescription 'normal test VM concealed console field'
    $venv = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($PythonPath))
    $evidenceRoot = [IO.Path]::GetDirectoryName($venv)
    $inspectorSource = New-AtlasoCertificateInspectorSnapshot -RepositoryRoot $worktree -EvidenceRoot $evidenceRoot `
        -SourceCommit $commit -TaskId $context.TaskId -Purpose installation-vnc
    $runtime = Protect-AtlasoCertificatePythonRuntime -PythonPath $PythonPath -EvidenceRoot $evidenceRoot `
        -RequiredModules @('vncdotool', 'twisted', 'PIL')
    Assert-AtlasoCertificatePythonImportPaths -Runtime $runtime
    $null = Assert-AtlasoSourceSnapshot -Root (Join-Path $venv 'Lib/site-packages') `
        -ExpectedSha256 $RuntimeSha256 -ExpectedFileCount $RuntimeFileCount
    $frameDirectoryPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($ScreenPath))
    $framePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($ScreenPath, $true)
    if ((Get-Item -LiteralPath $ScreenPath).Length -gt 8MB -or
        (Get-FileHash -LiteralPath $ScreenPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ScreenSha256) {
        throw 'Observed console frame differs from its admitted digest or bound.'
    }
    $clientArguments = New-AtlasoCertificatePythonArguments -Runtime $runtime `
        -ScriptPath (Join-Path $inspectorSource.Root 'scripts/installation/vnc_console.py') -ScriptArguments @(
            '--port', [string]$Port, '--expected-screen', $ScreenPath,
            '--expected-screen-sha256', $ScreenSha256, '--field-rectangle', $FieldRectangle)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $runtime.Executable
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($argument in $clientArguments) { $start.ArgumentList.Add($argument) }
    $consumer = [Diagnostics.Process]::Start($start)
    $errors = $consumer.StandardError.ReadToEndAsync()
    $ready = $consumer.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(30000) -or $ready.Result -cne 'ATLASO-VNC-CREDENTIAL-READY') {
        throw 'Private console client did not establish its fixed guarded connection.'
    }
    Assert-AtlasoTestVmCheckoutSource -Context $context
    $null = Assert-AtlasoTestVmOriginalOwnership -Context $context
    if ((Get-InstallationVncPeer -VmxPath $VmxPath -Port $Port) -ne $peer) {
        throw 'Receipt-bound console provider changed before credential submission.'
    }
    $secret = if ($Account -ceq 'admin') { $pair.AdminPassword } else { $pair.RootPassword }
    Send-InstallationConsoleSecret -Pipe $consumer.StandardInput.BaseStream -Value $secret -JsonRequest
    $consumer.StandardInput.Close()
    $sent = $consumer.StandardOutput.ReadLineAsync()
    if (-not $sent.Wait(30000) -or $sent.Result -cne 'ATLASO-VNC-CREDENTIAL-SENT' -or
        -not $consumer.WaitForExit(30000) -or $consumer.ExitCode -ne 0 -or
        -not $errors.Wait(5000) -or $errors.Result.Length -ne 0) {
        throw 'Guarded credential operation failed; private diagnostics were withheld.'
    }
    Write-Host "Concealed $Account field submitted to the original task VM."
}
finally {
    if ($consumer) {
        if (-not $consumer.HasExited) {
            $consumer.Kill($true)
            if (-not $consumer.WaitForExit(5000)) { throw 'Console credential child termination is unproven.' }
        }
        $consumer.Dispose()
    }
    if ($pair) { $pair.AdminPassword.Dispose(); $pair.RootPassword.Dispose() }
    if ($framePin) { $framePin.Dispose() }
    if ($frameDirectoryPin) { $frameDirectoryPin.Dispose() }
    if ($runtime) { foreach ($pin in $runtime.Pins) { $pin.Dispose() } }
    if ($inspectorSource) {
        try { Unprotect-AtlasoSourceSnapshot -Root $inspectorSource.Root }
        finally { foreach ($pin in $inspectorSource.Pins) { $pin.Dispose() } }
    }
    if ($context.PSObject.Properties['CheckoutSourcePin'] -and $context.CheckoutSourcePin) {
        $context.CheckoutSourcePin.Dispose()
    }
}
