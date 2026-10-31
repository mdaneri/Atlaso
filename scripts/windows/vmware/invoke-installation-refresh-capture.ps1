<#
.SYNOPSIS
Capture a complete Photon closure through the canonical receipt-bound builder.
.PARAMETER Plan
Original immutable plan.json selected by the refresh job owner.
.PARAMETER StateDirectory
Original durable state directory outside all disposable roots.
.PARAMETER Cleanup
Release only the successful canonical capture builder after independent verification.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Plan,
    [Parameter(Mandatory)][string]$StateDirectory,
    [switch]$Cleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareBuilderIdentity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.InstallationRefreshReceipt.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')

<#
.SYNOPSIS
Publish an original capture resource binding before the builder can consume it.
.PARAMETER Path
Absent durable output record.
.PARAMETER Record
Non-secret original task, source and resource data.
#>
function Write-RefreshCaptureRecord {
    param([string]$Path, [System.Collections.IDictionary]$Record)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 10 -Compress) + "`n")
    if ($bytes.Length -gt 65536) { throw 'Capture record exceeds its bound.' }
    $stage = Join-Path ([IO.Path]::GetDirectoryName($Path)) ('.capture-' + [guid]::NewGuid().ToString('N') + '.pending')
    $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($stage)
    try {
        $writer.Write($bytes, 0, $bytes.Length)
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, $Path, $false)
    }
    finally { $writer.Dispose() }
}

$worktree = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..')).TrimEnd('\', '/')
$planPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Plan, $true)
$capturePin = $null
$creationPins = $null
$job = $null
$statePin = $null
try {
    if ((Get-Item -LiteralPath $Plan).Length -gt 65536) { throw 'Capture plan exceeds its bound.' }
    $planValue = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json -AsHashtable
    $directory = Assert-AtlasoInstallationRefreshReceiptDirectory -ReceiptDirectory $StateDirectory `
        -Worktree $worktree -OutputDirectory ([string]$planValue.output_root)
    $statePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($directory.Path, $true)
    if ([IO.Path]::GetFullPath($Plan) -cne (Join-Path $directory.Path 'plan.json') -or
        $planValue.task_id -cne [string]$env:CODEX_THREAD_ID) { throw 'Capture plan and actual task differ.' }
    $phaseName = if ($Cleanup) { 'cleanup' } else { 'capture' }
    $child = Get-Content -LiteralPath (Join-Path $directory.Path ($phaseName + '-child.json')) -Raw | ConvertFrom-Json
    $job = Open-AtlasoBoundedProcessJob -ProcessJobName ([string]$child.job_name)
    if (-not $job -or -not $job.ContainsProcess((Get-Process -Id $PID))) { throw 'Capture adapter requires the original outer refresh job.' }
    $outputRoot = [string]$planValue.output_root
    $rootRecord = Get-Content -LiteralPath (Join-Path $directory.Path 'output-native-original.json') -Raw | ConvertFrom-Json
    if ($rootRecord.plan_sha256 -cne $child.plan_sha256 -or $rootRecord.path -cne $outputRoot -or
        [Atlaso.WorkstationFileIdentity]::Get($outputRoot) -cne $rootRecord.native_identity) {
        throw 'Original task output root changed; capture refused.'
    }
    $branch = ([string](& git -C $worktree branch --show-current)).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Canonical builder branch is unavailable.' }
    $identity = New-AtlasoVmwareBuilderIdentity -PullRequestNumber ([int]$planValue.pull_request_number) `
        -CollisionSuffix ([string]$planValue.operation_id) -Repository 'mdaneri/Atlaso' `
        -SourceBranch $branch -SourceCommit ([string]$planValue.installer_commit)
    $builderOutput = Join-Path $outputRoot $identity.Name
    if ($Cleanup) {
        # The parent original artifact-root receipt predates every Packer child.
        # The canonical sibling manifest binds that child to this exact source;
        # live identity/provider checks remain owned by the root-scoped remover.
        $manifestPath = Get-AtlasoVmwareBuilderIdentityManifestPath -OutputDirectory $builderOutput
        $null = Assert-AtlasoVmwareBuilderIdentityManifest -Path $manifestPath -OutputDirectory $builderOutput -Identity $identity
        $null = Assert-AtlasoVmwareBuilderVmx -VmxPath (Join-Path $builderOutput ($identity.Name + '.vmx')) `
            -OutputDirectory $builderOutput -Identity $identity
        $vmrun = Join-Path $env:ProgramFiles 'VMware/VMware Workstation/vmrun.exe'
        Remove-AtlasoWorkstationArtifactRoot -VmrunPath $vmrun -ArtifactParentRoot $outputRoot `
            -RemovalRoot $builderOutput -Confirm:$false
        if (Test-Path -LiteralPath $builderOutput) { throw 'Capture builder removal did not establish absence.' }
        return
    }
    foreach ($name in @('onepassword-environment-id', 'onepassword-service-account-token.dpapi')) {
        if (-not (Test-Path -LiteralPath (Join-Path $worktree ('.atlaso-local/' + $name)) -PathType Leaf)) {
            throw 'Task-local supported 1Password configuration is required before capture; no fallback authentication selected.'
        }
    }
    if ($null -ne $planValue.capture_receipt -or (Test-Path -LiteralPath $builderOutput)) {
        throw 'Fresh capture requires absent input and builder destinations; no output replacement is permitted.'
    }
    $captureRoot = Join-Path ([IO.Path]::GetDirectoryName($directory.Path)) ('iso-inputs-' + $planValue.operation_id)
    if ($captureRoot -ceq $directory.Path) { throw 'Capture root cannot contain original durable evidence.' }
    if (Test-Path -LiteralPath $captureRoot) { throw 'Original capture destination already exists; never replay it.' }
    $creationIdentity = [pscustomobject]@{ Value = '' }
    $callback = {
        param($CreatedPath, $OriginalIdentity)
        $creationIdentity.Value = $OriginalIdentity
        Write-RefreshCaptureRecord -Path (Join-Path $directory.Path 'capture-root-original.json') -Record ([ordered]@{
            schema = 1; task_id = $planValue.task_id; source_commit = $planValue.installer_commit
            repository = 'mdaneri/Atlaso'; path = $CreatedPath; native_identity = $OriginalIdentity
            plan_sha256 = $child.plan_sha256; created_utc = [DateTimeOffset]::UtcNow.ToString('o')
            retention = 'Immutable capture archives; reuse requires current complete admission; no ownership transfer'
            cleanup_tool = 'Remove-AtlasoWorkstationArtifactRoot'
        })
    }.GetNewClosure()
    $creationPins = [Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath($captureRoot, $callback)
    $creationPins.Dispose()
    $creationPins = $null
    $capturePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($captureRoot, $true)
    if ([Atlaso.WorkstationFileIdentity]::Get($captureRoot) -cne $creationIdentity.Value) { throw 'Original capture root changed before use.' }
    & (Join-Path $PSScriptRoot 'build-photon-image.ps1') -PullRequestNumber ([int]$planValue.pull_request_number) `
        -CollisionSuffix ([string]$planValue.operation_id) -CaptureInstallationRpms `
        -InstallationCaptureDirectory $captureRoot -InstallationCaptureRootIdentity $creationIdentity.Value `
        -OutputDirectory $builderOutput -BuildStateRoot (Join-Path $outputRoot 'build-state') `
        -IsoUrl ([string]$planValue.source_iso) -Headless -ImageBuildTimeoutSeconds 21000 -PackerOnError abort
    if (-not $?) { throw 'Canonical capture builder failed; retain its original resources.' }
}
finally {
    if ($creationPins) { $creationPins.Dispose() }
    if ($capturePin) { $capturePin.Dispose() }
    if ($job) { $job.Dispose() }
    if ($statePin) { $statePin.Dispose() }
    $planPin.Dispose()
}
