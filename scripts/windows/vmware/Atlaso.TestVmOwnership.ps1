<#
.SYNOPSIS
Create durable ownership records for normal VMware test VMs.
.DESCRIPTION
Records the task and source intent before test-VM creation, then publishes the
original output-directory and VMX identities from the clone-created callback.
#>

<#
.SYNOPSIS
Resolve and admit one task-owned normal test-VM checkout.
.PARAMETER Worktree
Exact source checkout containing the test-VM wrapper.
.PARAMETER OwnershipRoot
Optional existing permitted durable root containing the checkout for an explicit human CLI run.
.PARAMETER OwnershipTaskId
Exact task identity for an explicit human CLI run.
.PARAMETER OutputDirectory
Canonical test-VM output directory.
.PARAMETER VmxPath
Canonical VMX path inside the output directory.
.PARAMETER Name
Canonical Workstation VM name.
.PARAMETER SourceCommit
Exact admitted source checkout commit.
.PARAMETER SourceBranch
Exact checked-out source branch.
.PARAMETER PullRequestNumber
Owning pull request, or zero for a local test VM.
.PARAMETER LocalBuilder
Whether the identity is local/test rather than pull-request-owned.
#>
function New-AtlasoTestVmOwnershipContext {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [string]$OwnershipRoot = '',
        [string]$OwnershipTaskId = '',
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{1,127}$')][string]$Name,
        [string]$SourceCommit = '',
        [string]$SourceBranch = '',
        [ValidateRange(0, 2147483647)][int]$PullRequestNumber = 0,
        [switch]$LocalBuilder
    )

    $agentTaskId = [string]$env:CODEX_THREAD_ID
    $manualRootSupplied = -not [string]::IsNullOrWhiteSpace($OwnershipRoot)
    $manualTaskSupplied = -not [string]::IsNullOrWhiteSpace($OwnershipTaskId)
    if ($manualRootSupplied -xor $manualTaskSupplied) {
        throw 'Pass both -OwnershipRoot and -OwnershipTaskId to opt in to human CLI ownership receipts.'
    }
    $agentMode = -not [string]::IsNullOrWhiteSpace($agentTaskId)
    if ($agentMode -and ($manualRootSupplied -or $manualTaskSupplied)) {
        throw 'Agent ownership receipts use the active Codex task and configured worktree root; explicit human selectors are not accepted.'
    }
    if (-not $manualRootSupplied -and -not $agentMode) {
        return [pscustomobject]@{ Enabled = $false }
    }

    if ([bool]$LocalBuilder -eq ($PullRequestNumber -gt 0)) {
        throw 'Test-VM ownership must bind exactly one local or pull-request identity.'
    }
    if ($SourceCommit -notmatch '^[0-9a-f]{40}$' -or [string]::IsNullOrWhiteSpace($SourceBranch)) {
        throw 'Ownership receipts require one exact checked-out source branch and commit.'
    }
    $worktreePath = [System.IO.Path]::GetFullPath($Worktree).TrimEnd('\', '/')
    $outputPath = [System.IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
    $vmxFullPath = [System.IO.Path]::GetFullPath($VmxPath)
    $worktreePrefix = $worktreePath + [System.IO.Path]::DirectorySeparatorChar
    if (-not $outputPath.StartsWith($worktreePrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $vmxFullPath.Equals((Join-Path $outputPath "$Name.vmx"), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Test-VM ownership paths must use the canonical output directory and VMX beneath the task checkout.'
    }

    $taskId = if ($manualRootSupplied) { $OwnershipTaskId } else { $agentTaskId }
    if ($taskId -notmatch '^[A-Za-z0-9_-]{1,128}$') {
        throw 'The exact task identity is missing or malformed.'
    }

    $configuredRoot = ''
    if ($manualRootSupplied) {
        if (-not [System.IO.Path]::IsPathFullyQualified($OwnershipRoot)) {
            throw 'Human test-VM ownership requires -OwnershipRoot to name an existing permitted durable root containing the source checkout.'
        }
        $configuredRoot = [System.IO.Path]::GetFullPath($OwnershipRoot).TrimEnd('\', '/')
        if ($configuredRoot -eq [System.IO.Path]::GetPathRoot($configuredRoot).TrimEnd('\', '/')) {
            throw 'The permitted human ownership root cannot be a volume root.'
        }
        $evidencePath = Join-Path $configuredRoot '.task-ownership'
    }
    else {
        if (-not (Get-Command Get-AtlasoLifecycleDurableRoot -ErrorAction SilentlyContinue)) {
            . (Join-Path $PSScriptRoot 'Atlaso.LifecycleOwnership.ps1')
        }
        $configuredRoot = [System.IO.Path]::GetFullPath((Get-AtlasoLifecycleDurableRoot)).TrimEnd('\', '/')
        $evidencePath = Join-Path $configuredRoot '.task-ownership'
    }
    if (-not (Test-Path -LiteralPath $evidencePath -PathType Container)) {
        throw 'The durable test-VM ownership evidence directory must already exist.'
    }

    $evidenceFullPath = [System.IO.Path]::GetFullPath($evidencePath).TrimEnd('\', '/')
    $configuredPrefix = $configuredRoot + [System.IO.Path]::DirectorySeparatorChar
    $evidencePrefix = $evidenceFullPath + [System.IO.Path]::DirectorySeparatorChar
    $outputPrefix = $outputPath + [System.IO.Path]::DirectorySeparatorChar
    if (-not $worktreePath.StartsWith($configuredPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The source worktree must be contained by the explicitly permitted ownership root.'
    }
    if ($evidenceFullPath.StartsWith($worktreePath + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
        $worktreePath.StartsWith($evidencePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The durable test-VM ownership evidence directory must remain outside the task worktree.'
    }
    if ($evidenceFullPath.Equals($outputPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        $evidenceFullPath.StartsWith($outputPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        $outputPath.StartsWith($evidencePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The durable test-VM ownership evidence directory must be outside the VM removal root.'
    }

    $configuredRootPin = $null
    $rootPin = $null
    try {
        $configuredRootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($configuredRoot, $true)
        $rootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($evidenceFullPath, $true)
        $gitTop = ([string](& git -C $worktreePath rev-parse --show-toplevel 2>$null)).Trim()
        $normalizedGitTop = if ($gitTop) { [System.IO.Path]::GetFullPath($gitTop).TrimEnd('\', '/') } else { '' }
        if ($LASTEXITCODE -ne 0 -or -not $gitTop -or
            -not $normalizedGitTop.Equals($worktreePath, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'The task checkout does not resolve to one exact Git worktree root.'
        }
        $observedCommit = ([string](& git -C $worktreePath rev-parse HEAD 2>$null)).Trim()
        $observedBranch = ([string](& git -C $worktreePath branch --show-current 2>$null)).Trim()
        $status = @(& git -C $worktreePath status --porcelain --untracked-files=all 2>$null)
        if ($LASTEXITCODE -ne 0 -or $observedCommit -cne $SourceCommit -or
            $observedBranch -cne $SourceBranch -or $status.Count -ne 0) {
            throw 'Ownership receipts require the exact clean checked-out source branch and commit.'
        }
        $remoteUrl = ([string](& git -C $worktreePath config --get remote.origin.url 2>$null)).Trim()
        $remoteReadFailed = $LASTEXITCODE -ne 0
        $isAtlasoRemote = $remoteUrl -match '^(?:https://(?:[^/@]+@)?github\.com/|ssh://(?:[^/@]+@)?github\.com/|git@github\.com:)mdaneri/Atlaso(?:\.git)?$'
        if ($remoteReadFailed -or -not $isAtlasoRemote) {
            throw 'Ownership receipts require the canonical same-repository Atlaso checkout.'
        }

        $worktreeRecords = [string]::Join("`n", @(& git -C $worktreePath worktree list --porcelain 2>$null))
        if ($LASTEXITCODE -ne 0) { throw 'Could not verify the registered Git worktree.' }
        $registered = $false
        foreach ($record in ($worktreeRecords -split "`n`n")) {
            $worktreeLine = @($record -split "`n" | Where-Object { $_.StartsWith('worktree ') }) | Select-Object -First 1
            if ($worktreeLine) {
                $registeredPath = [System.IO.Path]::GetFullPath($worktreeLine.Substring(9)).TrimEnd('\', '/')
                if ($registeredPath.Equals($worktreePath, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $registered = $true
                    break
                }
            }
        }
        if (-not $registered) { throw 'The task checkout is not an independently registered Git worktree.' }

        if (-not $evidenceFullPath.StartsWith($configuredPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'The ownership evidence directory must remain beneath the permitted task root.'
        }
    }
    finally {
        if ($rootPin) { $rootPin.Dispose() }
        if ($configuredRootPin) { $configuredRootPin.Dispose() }
    }

    return [pscustomobject]@{
        Enabled             = $true
        TaskId              = $taskId
        Repository          = 'mdaneri/Atlaso'
        Worktree            = $worktreePath
        PermittedRoot       = $configuredRoot
        Branch              = $SourceBranch
        SourceCommit        = $SourceCommit
        PullRequestNumber   = $PullRequestNumber
        LocalBuilder        = [bool]$LocalBuilder
        Name                = $Name
        OutputDirectory     = $outputPath
        VmxPath             = $vmxFullPath
        EvidenceDirectory   = $evidenceFullPath
        EvidenceDirectoryId = [Atlaso.WorkstationFileIdentity]::Get($evidenceFullPath)
    }
}

<#
.SYNOPSIS
Durably publish one non-secret test-VM ownership record.
.PARAMETER Context
Admitted normal test-VM ownership context.
.PARAMETER Record
Non-secret ownership record to publish as JSON.
.PARAMETER Kind
Receipt category used in the immutable filename.
#>
function Publish-AtlasoTestVmOwnershipRecord {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Record,
        [Parameter(Mandatory = $true)][ValidateSet('intent', 'original')][string]$Kind
    )

    if (-not $Context.Enabled) { throw 'Cannot publish ownership for a disabled task context.' }
    $root = [System.IO.Path]::GetFullPath([string]$Context.EvidenceDirectory).TrimEnd('\', '/')
    $output = [System.IO.Path]::GetFullPath([string]$Context.OutputDirectory).TrimEnd('\', '/')
    $rootPrefix = $root + [System.IO.Path]::DirectorySeparatorChar
    $outputPrefix = $output + [System.IO.Path]::DirectorySeparatorChar
    if ($root.Equals($output, [System.StringComparison]::OrdinalIgnoreCase) -or
        $root.StartsWith($outputPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        $output.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The durable test-VM ownership evidence directory must be outside the VM removal root.'
    }
    $rootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($root, $true)
    $recordId = if ($Context.InvocationId -and [string]$Context.InvocationId -match '^[0-9a-f]{32}$') {
        [string]$Context.InvocationId
    } else {
        [guid]::NewGuid().ToString('N')
    }
    $stagePath = Join-Path $root ('.atlaso-test-vm-' + [guid]::NewGuid().ToString('N') + '.pending')
    $recordPath = Join-Path $root ('atlaso-test-vm-' + $Kind + '-' + $recordId + '.json')
    $writer = $null
    try {
        if ([Atlaso.WorkstationFileIdentity]::Get($root) -cne [string]$Context.EvidenceDirectoryId) {
            throw 'The durable ownership evidence directory identity changed before publication.'
        }
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 8 -Compress) + "`n")
        $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($stagePath)
        $writer.Write($bytes, 0, $bytes.Length)
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, $recordPath, $false)
        $writer.Dispose()
        $writer = $null
        $readbackPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($recordPath, $true)
        try {
            $readbackHash = (Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $expectedHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
            if ($readbackHash -cne $expectedHash) { throw 'Durable test-VM ownership receipt readback did not match the published bytes.' }
        }
        finally {
            $readbackPin.Dispose()
        }
        return [pscustomobject]@{ Path = $recordPath; Sha256 = $expectedHash }
    }
    catch {
        if ($writer) {
            $writer.Dispose()
            $writer = $null
        }
        # Keep an incomplete random stage beside the durable intent. Failed
        # native publication needs reconciliation; do not delete by pathname.
        throw
    }
    finally {
        if ($writer) { $writer.Dispose() }
        $rootPin.Dispose()
    }
}

<#
.SYNOPSIS
Publish the task-bound intent immediately before normal test-VM creation.
.PARAMETER Context
Admitted normal test-VM ownership context.
.PARAMETER SourceVmxPath
Verified source template path; it is provenance, not a cleanup target.
.PARAMETER SourceVmxIdentity
Public filesystem identity of the admitted source template.
.PARAMETER ExistingReceipt
Previously verified original receipt for an exact VM being redeployed.
#>
function New-AtlasoTestVmOwnershipIntent {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][string]$SourceVmxPath,
        [Parameter(Mandatory = $true)][string]$SourceVmxIdentity,
        [psobject]$ExistingReceipt
    )

    if (-not $Context.Enabled) { return $null }
    if ((Test-Path -LiteralPath $Context.OutputDirectory) -and $null -eq $ExistingReceipt) {
        throw 'A new test-VM ownership intent cannot adopt an existing output directory.'
    }
    if (-not (Test-Path -LiteralPath $Context.OutputDirectory) -and $null -ne $ExistingReceipt) {
        throw 'A redeployment receipt was supplied after its original output directory disappeared.'
    }
    if ($null -ne $ExistingReceipt) {
        $outputIdentity = [Atlaso.WorkstationFileIdentity]::Get([string]$Context.OutputDirectory)
        $cleanupIdentity = Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath ([string]$Context.VmxPath)
        $cleanupIdentityHash = Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value $cleanupIdentity
        if ([string]$ExistingReceipt.Record.original_identities.directory -cne $outputIdentity -or
            [string]$ExistingReceipt.Record.persistent_vm_identity_sha256 -cne $cleanupIdentityHash) {
            throw 'The verified redeployment receipt no longer matches the existing VM identities.'
        }
    }
    $sourcePath = [System.IO.Path]::GetFullPath($SourceVmxPath)
    $sourcePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($sourcePath, $true)
    try {
        if ([Atlaso.WorkstationFileIdentity]::Get($sourcePath) -cne $SourceVmxIdentity) {
            throw 'The admitted source template identity changed before intent publication.'
        }
    }
    finally {
        $sourcePin.Dispose()
    }
    $recordId = if ($Context.InvocationId -and [string]$Context.InvocationId -match '^[0-9a-f]{32}$') {
        [string]$Context.InvocationId
    } else {
        [guid]::NewGuid().ToString('N')
    }
    $Context | Add-Member -NotePropertyName InvocationId -NotePropertyValue $recordId -Force
    $intent = [ordered]@{
        schema = 1
        phase = 'clone-pending'
        task_id = [string]$Context.TaskId
        repository = [string]$Context.Repository
        source_branch = [string]$Context.Branch
        source_commit = [string]$Context.SourceCommit
        worktree = [string]$Context.Worktree
        pull_request_number = [int]$Context.PullRequestNumber
        local_builder = [bool]$Context.LocalBuilder
        canonical_name = [string]$Context.Name
        output_directory = [string]$Context.OutputDirectory
        vmx_path = [string]$Context.VmxPath
        source_template = [ordered]@{
            path = $sourcePath
            filesystem_identity = $SourceVmxIdentity
            role = 'read-only source template; not cleanup-owned'
        }
        replaces_receipt = if ($null -ne $ExistingReceipt) {
            [ordered]@{ path = [string]$ExistingReceipt.Path; sha256 = [string]$ExistingReceipt.Sha256 }
        } else { $null }
        cleanup_tool = 'scripts/windows/vmware/remove-atlaso-vm.ps1 -VmxPath <recorded-vmx> -ExpectedName <canonical-name>'
        invocation_id = $recordId
        created_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $published = Publish-AtlasoTestVmOwnershipRecord -Context $Context -Record $intent -Kind intent
    $Context | Add-Member -NotePropertyName IntentPath -NotePropertyValue $published.Path -Force
    $Context | Add-Member -NotePropertyName IntentSha256 -NotePropertyValue $published.Sha256 -Force
    $Context | Add-Member -NotePropertyName InvocationId -NotePropertyValue $recordId -Force
    return $Context
}

<#
.SYNOPSIS
Read the persistent non-secret identity from one exact VMX.
.PARAMETER VmxPath
Current VMX whose stable ownership identity must be verified.
#>
function Get-AtlasoTestVmOwnershipCleanupIdentity {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$VmxPath)

    $assignmentPattern = '^\s*guestinfo\.atlaso\.test_vm_cleanup_identity\s*='
    $valuePattern = '^\s*guestinfo\.atlaso\.test_vm_cleanup_identity\s*=\s*"(?<identity>[0-9a-f]{32})"\s*$'
    $identityLines = @(
        Get-Content -LiteralPath $VmxPath -ErrorAction Stop |
            Where-Object { $_ -match $assignmentPattern }
    )
    if ($identityLines.Count -ne 1) {
        throw 'The current VMX does not contain exactly one persistent ownership identity.'
    }
    $identityMatch = [regex]::Match([string]$identityLines[0], $valuePattern)
    if (-not $identityMatch.Success) {
        throw 'The current VMX does not contain exactly one valid persistent ownership identity.'
    }
    return $identityMatch.Groups['identity'].Value
}

<#
.SYNOPSIS
Hash one non-secret persistent VM identity for durable ownership receipts.
.PARAMETER Value
Validated persistent VM identity.
#>
function Get-AtlasoTestVmOwnershipCleanupIdentityHash {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{32}$')][string]$Value)

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Value)
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes))
}

<#
.SYNOPSIS
Record the original clone directory and VMX before their first configuration.
.PARAMETER Context
Admitted context with its previously published creation intent.
.PARAMETER DirectoryPath
Newly cloned output directory supplied by create-atlaso-vm.ps1.
.PARAMETER VmxPath
Newly cloned VMX supplied by create-atlaso-vm.ps1.
.PARAMETER CleanupIdentity
Stable non-secret VMX identity published while the original receipt is flushed.
.PARAMETER HeldVmxStream
Optional original VMX stream held by the identity writer against replacement.
#>
function Publish-AtlasoTestVmOriginalOwnership {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][string]$DirectoryPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{32}$')][string]$CleanupIdentity,
        [System.IO.FileStream]$HeldVmxStream
    )

    if (-not $Context.Enabled -or -not $Context.IntentPath -or -not $Context.IntentSha256) {
        throw 'The clone callback has no previously published task ownership intent.'
    }
    $resolvedDirectory = [System.IO.Path]::GetFullPath($DirectoryPath).TrimEnd('\', '/')
    $resolvedVmx = [System.IO.Path]::GetFullPath($VmxPath)
    if (-not $resolvedDirectory.Equals([string]$Context.OutputDirectory, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $resolvedVmx.Equals([string]$Context.VmxPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $resolvedVmx -PathType Leaf)) {
        throw 'Clone-created paths do not match the pre-published canonical task intent.'
    }
    $intentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile([string]$Context.IntentPath, $true)
    $directoryPin = $null
    $vmxPin = $null
    try {
        $intentHash = (Get-FileHash -LiteralPath $Context.IntentPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($intentHash -cne [string]$Context.IntentSha256) { throw 'The task ownership intent changed after publication.' }
        $intentData = Get-Content -LiteralPath $Context.IntentPath -Raw | ConvertFrom-Json
        if ([string]$intentData.task_id -cne [string]$Context.TaskId -or
            [string]$intentData.output_directory -cne [string]$Context.OutputDirectory -or
            [string]$intentData.vmx_path -cne [string]$Context.VmxPath -or
            [string]$intentData.invocation_id -cne [string]$Context.InvocationId) {
            throw 'The task ownership intent does not match the clone callback context.'
        }

        $directoryPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($resolvedDirectory, $true)
        if ($null -ne $HeldVmxStream) {
            # The identity writer denies other writers and deletion. A second
            # read pin would deny its already-open write access on Windows.
            if (-not $HeldVmxStream.CanRead -or -not $HeldVmxStream.CanWrite -or
                -not [System.IO.Path]::GetFullPath($HeldVmxStream.Name).Equals(
                    $resolvedVmx, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw 'The original VMX stream does not match the clone callback.'
            }
        }
        else {
            $vmxPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($resolvedVmx, $true)
        }
        $directoryIdentity = [Atlaso.WorkstationFileIdentity]::Get($resolvedDirectory)
        $vmxIdentity = [Atlaso.WorkstationFileIdentity]::Get($resolvedVmx)
        $observedCleanupIdentity = Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath $resolvedVmx
        if ($observedCleanupIdentity -cne $CleanupIdentity) {
            throw 'The original VMX does not contain its exact persistent ownership identity.'
        }
        $cleanupIdentityHash = Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value $CleanupIdentity
        $receipt = [ordered]@{
            schema = 1
            phase = 'original-clone-created'
            task_id = [string]$Context.TaskId
            repository = [string]$Context.Repository
            source_branch = [string]$Context.Branch
            source_commit = [string]$Context.SourceCommit
            worktree = [string]$Context.Worktree
            pull_request_number = [int]$Context.PullRequestNumber
            local_builder = [bool]$Context.LocalBuilder
            canonical_name = [string]$Context.Name
            output_directory = $resolvedDirectory
            vmx_path = $resolvedVmx
            source_template = $intentData.source_template
            original_identities = [ordered]@{
                directory = $directoryIdentity
                vmx = $vmxIdentity
            }
            persistent_vm_identity_sha256 = $cleanupIdentityHash
            intent_path = [string]$Context.IntentPath
            intent_sha256 = [string]$Context.IntentSha256
            cleanup_tool = 'scripts/windows/vmware/remove-atlaso-vm.ps1 -VmxPath <recorded-vmx> -ExpectedName <canonical-name>'
            created_utc = [DateTimeOffset]::UtcNow.ToString('o')
        }
        $published = Publish-AtlasoTestVmOwnershipRecord -Context $Context -Record $receipt -Kind original
        if ([Atlaso.WorkstationFileIdentity]::Get($resolvedDirectory) -cne $directoryIdentity -or
            [Atlaso.WorkstationFileIdentity]::Get($resolvedVmx) -cne $vmxIdentity) {
            throw 'The original clone identities changed while publishing their ownership receipt.'
        }
        $Context | Add-Member -NotePropertyName ReceiptPath -NotePropertyValue $published.Path -Force
        $Context | Add-Member -NotePropertyName ReceiptSha256 -NotePropertyValue $published.Sha256 -Force
        return $Context
    }
    finally {
        if ($vmxPin) { $vmxPin.Dispose() }
        if ($directoryPin) { $directoryPin.Dispose() }
        $intentPin.Dispose()
    }
}

<#
.SYNOPSIS
Verify an existing test VM has a matching original creation receipt.
.PARAMETER Context
Admitted task context for the expected canonical VM.
#>
function Assert-AtlasoTestVmOriginalOwnership {
    [CmdletBinding()]
    [OutputType([psobject])]
    param([Parameter(Mandatory = $true)][psobject]$Context)

    if (-not $Context.Enabled) { return $null }
    if (-not (Test-Path -LiteralPath $Context.OutputDirectory -PathType Container) -or
        -not (Test-Path -LiteralPath $Context.VmxPath -PathType Leaf)) {
        throw 'Existing test-VM ownership can be verified only for the exact existing output directory and VMX.'
    }
    $directoryIdentity = [Atlaso.WorkstationFileIdentity]::Get([string]$Context.OutputDirectory)
    $cleanupIdentity = Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath ([string]$Context.VmxPath)
    $cleanupIdentityHash = Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value $cleanupIdentity
    $matchingPathRecords = [System.Collections.Generic.List[object]]::new()
    $matchingIdentityRecords = [System.Collections.Generic.List[object]]::new()
    $evidencePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([string]$Context.EvidenceDirectory, $true)
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $Context.EvidenceDirectory -Filter 'atlaso-test-vm-original-*.json' -File)) {
            $filePin = $null
            try {
            if ($file.Length -gt 65536) { continue }
            $filePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($file.FullName, $true)
            $candidate = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            if ($candidate.schema -ne 1 -or [string]$candidate.phase -cne 'original-clone-created') {
                continue
            }
            if ([string]$candidate.output_directory -ceq [string]$Context.OutputDirectory) {
                $matchingPathRecords.Add([pscustomobject]@{ Path = $file.FullName; Record = $candidate })
                if ([string]$candidate.task_id -ceq [string]$Context.TaskId -and
                    [string]$candidate.repository -ceq [string]$Context.Repository -and
                    [string]$candidate.worktree -ceq [string]$Context.Worktree -and
                    [string]$candidate.source_branch -ceq [string]$Context.Branch -and
                    [string]$candidate.canonical_name -ceq [string]$Context.Name -and
                    [string]$candidate.vmx_path -ceq [string]$Context.VmxPath -and
                    [int]$candidate.pull_request_number -eq [int]$Context.PullRequestNumber -and
                    [bool]$candidate.local_builder -eq [bool]$Context.LocalBuilder -and
                    [string]$candidate.original_identities.directory -ceq $directoryIdentity -and
                    [string]$candidate.persistent_vm_identity_sha256 -ceq $cleanupIdentityHash -and
                    [string]$candidate.original_identities.vmx -match '^[0-9A-F]{8}:[0-9A-F]{16}$') {
                    $matchingIdentityRecords.Add([pscustomobject]@{ Path = $file.FullName; Record = $candidate })
                }
            }
            }
            catch {
                continue
            }
            finally {
                if ($filePin) { $filePin.Dispose() }
            }
        }
    }
    finally {
        $evidencePin.Dispose()
    }
    if ($matchingPathRecords.Count -eq 0 -or $matchingIdentityRecords.Count -ne 1) {
        throw 'The existing test VM does not match its original task ownership receipt; preserving it.'
    }
    $exact = $matchingIdentityRecords[0]
    $receiptPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile([string]$exact.Path, $true)
    try {
        $sha256 = (Get-FileHash -LiteralPath $exact.Path -Algorithm SHA256).Hash.ToLowerInvariant()
        $intentPath = [System.IO.Path]::GetFullPath([string]$exact.Record.intent_path)
        $evidencePrefix = [System.IO.Path]::GetFullPath([string]$Context.EvidenceDirectory).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        if (-not $intentPath.StartsWith($evidencePrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $intentPath -PathType Leaf)) {
            throw 'The original test-VM receipt has no in-scope creation intent.'
        }
        $intentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($intentPath, $true)
        try {
            $intentHash = (Get-FileHash -LiteralPath $intentPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($intentHash -cne [string]$exact.Record.intent_sha256) {
                throw 'The original test-VM receipt references a changed creation intent.'
            }
            $intent = Get-Content -LiteralPath $intentPath -Raw | ConvertFrom-Json
            if ($intent.schema -ne 1 -or [string]$intent.phase -cne 'clone-pending' -or
                [string]$intent.task_id -cne [string]$Context.TaskId -or
                [string]$intent.repository -cne [string]$Context.Repository -or
                [string]$intent.worktree -cne [string]$Context.Worktree -or
                [string]$intent.source_branch -cne [string]$exact.Record.source_branch -or
                [string]$intent.source_commit -cne [string]$exact.Record.source_commit -or
                [string]$intent.canonical_name -cne [string]$Context.Name -or
                [string]$intent.output_directory -cne [string]$Context.OutputDirectory -or
                [string]$intent.vmx_path -cne [string]$Context.VmxPath -or
                [int]$intent.pull_request_number -ne [int]$Context.PullRequestNumber -or
                [bool]$intent.local_builder -ne [bool]$Context.LocalBuilder) {
                throw 'The original test-VM receipt does not match its bound creation intent.'
            }
            if ([string]$exact.Record.source_commit -notmatch '^[0-9a-f]{40}$' -or
                [string]$Context.SourceCommit -notmatch '^[0-9a-f]{40}$') {
                throw 'The original test-VM receipt does not contain an exact source commit.'
            }
            & git -C ([string]$Context.Worktree) merge-base --is-ancestor `
                ([string]$exact.Record.source_commit) `
                ([string]$Context.SourceCommit) 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw 'The original test-VM creation source is not an ancestor of the active task source; preserving the VM.'
            }
        }
        finally {
            $intentPin.Dispose()
        }
    }
    finally {
        $receiptPin.Dispose()
    }
    return [pscustomobject]@{ Path = $exact.Path; Sha256 = $sha256; Record = $exact.Record }
}
