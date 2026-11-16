<#
.SYNOPSIS
Import one validated local Atlaso OVA into a new task-owned Workstation directory.
.DESCRIPTION
Run this with fresh host admission from the trusted-host acceptance procedure.
Use WhatIf to check the source and destination without launching VMware.
.PARAMETER ValidationReceipt
Absolute path to the independently retained local OVA validation receipt.
.PARAMETER ValidationReceiptSha256
Original SHA-256 of the validation receipt.
.PARAMETER SourceCommit
Exact reviewed commit of the task checkout.
.PARAMETER SourceBranch
Exact task branch of the checkout.
.PARAMETER PullRequestNumber
Pull request that owns the new VM.
.PARAMETER Name
Canonical VM and output directory name beneath the checkout's existing test-results directory.
.PARAMETER OvfToolPath
Absolute path to the admitted VMware ovftool.exe.
.PARAMETER OvfToolSha256
Independently observed SHA-256 of the admitted provider executable.
.PARAMETER PythonPath
Absolute path to the prepared Python runtime for read-only inspection.
.PARAMETER TimeoutSeconds
Maximum lifetime in seconds of the original provider job.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ValidationReceipt,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ValidationReceiptSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$SourceBranch,
    [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$PullRequestNumber,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{1,79}$')][string]$Name,
    [Parameter(Mandatory)][string]$OvfToolPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$OvfToolSha256,
    [Parameter(Mandatory)][string]$PythonPath,
    [ValidateRange(1, 7200)][int]$TimeoutSeconds = 900
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwarePayload.psm1')
. (Join-Path $PSScriptRoot 'Atlaso.TestVmOwnership.ps1')
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')

<#
.SYNOPSIS
Add pins for an absolute ordinary file and its ancestors before opening it.
.PARAMETER Path
Absolute original file path.
.PARAMETER Pins
Handles retained through the complete import.
#>
function Add-AtlasoOvaFilePin {
    param([string]$Path, [Collections.Generic.List[IDisposable]]$Pins)
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or [IO.Path]::GetFullPath($Path) -cne $Path) {
        throw 'The import requires canonical absolute file paths.'
    }
    $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($Path), $true))
    $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Path, $true))
}

<#
.SYNOPSIS
Persist one phase with the original import's common identity.
.PARAMETER Context
Original task and checkout identity.
.PARAMETER Kind
Import phase used to select the durable receipt path.
.PARAMETER Fields
Phase-specific observations and original receipt references.
#>
function Publish-AtlasoOvaImportPhase {
    param([psobject]$Context, [string]$Kind, [Collections.IDictionary]$Fields)
    $record = [ordered]@{
        schema = 1; phase = $Kind; task_id = $Context.TaskId; repository = $Context.Repository
        source_commit = $Context.SourceCommit; worktree = $Context.Worktree; invocation_id = $Context.InvocationId
        pull_request_number = $Context.PullRequestNumber; output_directory = $Context.OutputDirectory
        vmx_path = $Context.VmxPath; utc = [DateTimeOffset]::UtcNow.ToString('O')
    }
    foreach ($key in $Fields.Keys) { $record.Add($key, $Fields[$key]) }
    Publish-AtlasoTestVmOwnershipRecord -Context $Context -Kind $Kind -Record $record
}

<#
.SYNOPSIS
Convert the inspector's Windows file identity tuple to the native receipt representation.
.PARAMETER Identity
Volume serial and high and low file index values.
#>
function Format-AtlasoOvaFileIdentity {
    param([uint32[]]$Identity)
    if ($Identity.Count -ne 3) { throw 'The OVA inspector returned an invalid file identity.' }
    '{0:X8}:{1:X8}{2:X8}' -f $Identity[0], $Identity[1], $Identity[2]
}

<#
.SYNOPSIS
Refuse implicit OVF Tool option files without reading their contents.
.PARAMETER ConfigPaths
Default option file paths for the controller's Windows profile and native working directory.
#>
function Assert-AtlasoOvaDefaultConfigAbsent {
    param([string[]]$ConfigPaths)
    foreach ($path in $ConfigPaths) {
        try {
            $null = [IO.File]::GetAttributes($path)
        }
        catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] {
            continue
        }
        throw 'OVF Tool has a default option file. The local import requires explicit command-line options.'
    }
}

$worktree = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$output = Join-Path $worktree "test-results/$Name"
$vmx = Join-Path $output "$Name.vmx"
$context = New-AtlasoTestVmOwnershipContext -Worktree $worktree -OutputDirectory $output -VmxPath $vmx -Name $Name `
    -SourceCommit $SourceCommit -SourceBranch $SourceBranch -PullRequestNumber $PullRequestNumber
if (-not $context.Enabled -or -not $context.ActiveTaskId) { throw 'An active Codex task must own the import.' }
$context | Add-Member InvocationId ([guid]::NewGuid().ToString('N'))

$pins = [Collections.Generic.List[IDisposable]]::new()
$state = @{
    Process = $null; RootPid = $null; RootStartUtc = $null
    Directory = $null; DirectoryPin = $null; Identity = $null; Terminal = $null; Outcome = $null
}
try {
    Assert-AtlasoTestVmCheckoutSource -Context $context
    Add-AtlasoOvaFilePin -Path $ValidationReceipt -Pins $pins
    Add-AtlasoOvaFilePin -Path $OvfToolPath -Pins $pins
    Add-AtlasoOvaFilePin -Path $PythonPath -Pins $pins
    if ([IO.Path]::GetFileName($OvfToolPath) -ine 'ovftool.exe' -or
        (Get-FileHash -LiteralPath $OvfToolPath).Hash -ine $OvfToolSha256) {
        throw 'The admitted OVF Tool executable changed.'
    }
    if ((Get-Item -LiteralPath $ValidationReceipt).Length -gt 262144 -or
        (Get-FileHash -LiteralPath $ValidationReceipt).Hash -ine $ValidationReceiptSha256) {
        throw 'The original validation receipt changed.'
    }
    $receipt = Get-Content -LiteralPath $ValidationReceipt -Raw | ConvertFrom-Json -AsHashtable
    $archive = [string]$receipt.source
    $validation = $receipt.validation
    if ($receipt.actual_exit -cne 0 -or $receipt.import_performed -cne $false -or
        $validation.kind -cne 'atlaso-validated-local-ova' -or
        $validation.schema_version -cne 1 -or $validation.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        $validation.ova_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [IO.Path]::GetFileName($archive) -cne $validation.ova -or [IO.Path]::GetExtension($archive) -ine '.ova' -or
        -not (Test-AtlasoTestVmStrictDescendantPath -ParentPath $worktree -ChildPath $archive)) {
        throw 'The original receipt does not select a validated task-owned OVA.'
    }
    Add-AtlasoOvaFilePin -Path $archive -Pins $pins
    if ((Get-Item -LiteralPath $archive).Length -ne $validation.archive_bytes -or
        (Get-FileHash -LiteralPath $archive).Hash -ine $validation.ova_sha256 -or
        [Atlaso.WorkstationFileIdentity]::Get($archive) -cne (Format-AtlasoOvaFileIdentity $receipt.original_identity)) {
        throw 'The admitted OVA identity or bytes changed.'
    }

    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($output), $true))
    if (Test-Path -LiteralPath $output) { throw 'The import destination must be absent.' }
    $workingDirectory = [Environment]::CurrentDirectory
    if ($workingDirectory -ine $worktree) { throw 'Start the import controller from its task checkout.' }
    $appData = [Environment]::GetFolderPath('ApplicationData')
    if (-not [IO.Path]::IsPathFullyQualified($appData)) { throw 'The Windows roaming profile path is unavailable.' }
    $configPaths = @((Join-Path $appData 'VMware/ovftool.cfg'), (Join-Path $workingDirectory 'ovftool.cfg'))
    Assert-AtlasoOvaDefaultConfigAbsent -ConfigPaths $configPaths
    if (-not $PSCmdlet.ShouldProcess($output, 'Import the original local Atlaso OVA with power off')) { return }
    Assert-AtlasoTestVmCheckoutSource -Context $context
    $arguments = @('--sourceType=OVA', '--targetType=VMX', '--diskMode=monolithicSparse', '--machineOutput', "--name=$Name", $archive, $vmx)
    $jobName = 'Local\Atlaso-TestVm-OvaImport-' + $context.InvocationId
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $intent = Publish-AtlasoOvaImportPhase -Context $context -Kind 'ova-import-intent' -Fields ([ordered]@{
        validation_receipt = @{ path = $ValidationReceipt; sha256 = $ValidationReceiptSha256 }
        archive_path = $archive; archive_identity = $receipt.original_identity; archive_sha256 = $validation.ova_sha256
        archive_source_commit = $validation.source_commit; archive_bytes = $validation.archive_bytes
        provider_path = $OvfToolPath; provider_sha256 = $OvfToolSha256; arguments = $arguments
        job_name = $jobName; deadline_utc = $deadline.ToString('O'); working_directory = $workingDirectory
        absent_default_config_paths = $configPaths
    })

    $publishOwnership = {
        param($Job)
        $root = $Job.RootProcess
        $state.RootPid = $root.Id
        $state.RootStartUtc = $root.StartTime.ToUniversalTime().ToString('O')
        $controller = Get-Process -Id $PID
        try {
            $state.Process = Publish-AtlasoOvaImportPhase -Context $context -Kind 'ova-import-process' -Fields ([ordered]@{
                intent = $intent; job_name = $jobName; boot_identity = Get-AtlasoWindowsBootIdentity
                controller_pid = $PID; controller_start_utc = $controller.StartTime.ToUniversalTime().ToString('O')
                root_pid = $state.RootPid; root_start_utc = $state.RootStartUtc
            })
        }
        finally { $controller.Dispose() }
        $publishDirectory = [Action[string, string]]{
            param($CreatedPath, $OriginalIdentity)
            if ($CreatedPath -ine $output) { throw 'Unexpected OVA import directory.' }
            $state.Directory = Publish-AtlasoOvaImportPhase -Context $context -Kind 'ova-import-directory' -Fields ([ordered]@{
                intent = $intent; process = $state.Process; directory_identity = $OriginalIdentity
            })
            $state.Identity = $OriginalIdentity
        }
        # Retain incomplete imports and permit a second read-only inspection handle.
        $state.DirectoryPin = [Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath($output, $publishDirectory, $false)
        if ($state.DirectoryPin.GetRetainedCreatedIdentity($output) -cne $state.Identity) {
            throw 'The original import directory changed before launch.'
        }
        Assert-AtlasoTestVmCheckoutSource -Context $context
        Assert-AtlasoOvaDefaultConfigAbsent -ConfigPaths $configPaths
    }
    $publishTerminal = {
        param($Terminal)
        $state.Terminal = Publish-AtlasoOvaImportPhase -Context $context -Kind 'ova-import-terminal' -Fields ([ordered]@{
            intent = $intent; process = $state.Process; directory = $state.Directory; terminal = $Terminal
        })
        $state.Outcome = $Terminal
    }
    Invoke-AtlasoBoundedStreamingProcess -FilePath $OvfToolPath -ArgumentList $arguments -Action 'Local Atlaso OVA import' `
        -TimeoutSeconds $TimeoutSeconds -DeadlineUtc $deadline -ProcessJobName $jobName -DiscardOutput `
        -ProcessOwnershipPublisher $publishOwnership -ProcessQuiescencePublisher $publishTerminal
    if (-not $state.Terminal -or $state.Outcome.Outcome -cne 'succeeded' -or -not $state.Outcome.WholeJobEmpty -or
        $state.Outcome.RootExitCode -ne 0 -or $state.Outcome.ProcessJobName -cne $jobName -or
        $state.Outcome.RootProcessId -ne $state.RootPid -or $state.Outcome.RootStartTimeUtc -cne $state.RootStartUtc -or
        $state.Outcome.DeadlineUtc -cne $deadline.ToUniversalTime().ToString('O') -or
        $state.DirectoryPin.GetRetainedCreatedIdentity($output) -cne $state.Identity) {
        throw 'The original OVA import did not establish success and quiescence.'
    }

    Assert-AtlasoOvaDefaultConfigAbsent -ConfigPaths $configPaths
    Add-AtlasoOvaFilePin -Path $vmx -Pins $pins
    Assert-AtlasoTemplatePoweredOff -VmxPath $vmx
    $inspector = @'
import sys
sys.path.insert(0, sys.argv.pop(1))
from scripts.virtualization.inspect_workstation_ova_disks import main
raise SystemExit(main())
'@
    $inspectionArguments = @('-I', '-S', '-B', '-c', $inspector, $worktree, $vmx)
    $discovery = Invoke-AtlasoBoundedProcess -FilePath $PythonPath -Action 'Imported OVA disk discovery' -TimeoutSeconds 60 `
        -ArgumentList $inspectionArguments | ConvertFrom-Json -AsHashtable
    foreach ($disk in $discovery.disks) {
        $path = Join-Path $output $disk.file
        Add-AtlasoOvaFilePin -Path $path -Pins $pins
        if ([Atlaso.WorkstationFileIdentity]::Get($path) -cne (Format-AtlasoOvaFileIdentity $disk.identity)) {
            throw 'An imported disk changed after inspection.'
        }
    }
    # Verify the descriptors again with the controller retaining all four pins.
    $inspection = Invoke-AtlasoBoundedProcess -FilePath $PythonPath -Action 'Imported OVA disk inspection' -TimeoutSeconds 60 `
        -ArgumentList $inspectionArguments | ConvertFrom-Json -AsHashtable
    if (($discovery | ConvertTo-Json -Depth 8 -Compress) -cne ($inspection | ConvertTo-Json -Depth 8 -Compress)) {
        throw 'The imported disk observations changed while the controller acquired its pins.'
    }
    if ([Atlaso.WorkstationFileIdentity]::Get($vmx) -cne (Format-AtlasoOvaFileIdentity $inspection.vmx_identity) -or
        (Get-FileHash -LiteralPath $vmx).Hash -ine $inspection.vmx_sha256) {
        throw 'The imported VMX changed after inspection.'
    }
    Assert-AtlasoTestVmCheckoutSource -Context $context
    Publish-AtlasoOvaImportPhase -Context $context -Kind 'ova-import-original' -Fields ([ordered]@{
        intent = $intent; process = $state.Process; directory = $state.Directory; terminal = $state.Terminal
        directory_identity = $state.Identity; powered_off = $true; disk_inspection = $inspection
    })
}
finally {
    if ($state.DirectoryPin) { $state.DirectoryPin.Dispose() }
    for ($index = $pins.Count - 1; $index -ge 0; $index--) { $pins[$index].Dispose() }
    if ($context.PSObject.Properties['CheckoutSourcePin']) { $context.CheckoutSourcePin.Dispose() }
}
