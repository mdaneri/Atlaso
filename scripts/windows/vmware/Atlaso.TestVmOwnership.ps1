<#
.SYNOPSIS
Create durable ownership records for normal VMware test VMs.
.DESCRIPTION
Records preserve task/source intent before creation and publish original VM identities afterward.
#>

<#
.SYNOPSIS
Test whether one canonical path is strictly beneath another.
.PARAMETER ParentPath
Canonical parent path.
.PARAMETER ChildPath
Candidate descendant path.
#>
function Test-AtlasoTestVmStrictDescendantPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$ParentPath,
        [Parameter(Mandatory = $true)][string]$ChildPath
    )

    $parent = [System.IO.Path]::GetFullPath($ParentPath).TrimEnd('\', '/')
    $child = [System.IO.Path]::GetFullPath($ChildPath).TrimEnd('\', '/')
    if ($parent -eq $child) { return $false }
    $prefix = $parent + [System.IO.Path]::DirectorySeparatorChar
    return $child.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

<#
.SYNOPSIS
Validate the canonical installation-ISO VM name for its task identity.
.PARAMETER Name
VM display name to validate.
.PARAMETER SourceCommit
Exact source commit used by a local VM identity.
.PARAMETER PullRequestNumber
Owning pull request number, or zero for a local VM.
.PARAMETER LocalBuilder
Select a local VM identity instead of a pull-request identity.
#>
function Test-AtlasoTestVmCanonicalInstallationIsoName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$SourceCommit,
        [Parameter(Mandatory = $true)][int]$PullRequestNumber,
        [Parameter(Mandatory = $true)][bool]$LocalBuilder
    )

    if (-not (Get-Command New-AtlasoVmwareTestIdentity -CommandType Function -ErrorAction SilentlyContinue)) {
        return $false
    }
    try {
        if ($LocalBuilder) {
            if ($PullRequestNumber -ne 0 -or $SourceCommit -cnotmatch '^[0-9a-f]{40}$') { return $false }
            $identity = New-AtlasoVmwareTestIdentity -LocalBuilder -SourceCommit $SourceCommit -Purpose installation-iso
        }
        else {
            if ($PullRequestNumber -le 0) { return $false }
            $identity = New-AtlasoVmwareTestIdentity -PullRequestNumber $PullRequestNumber -Purpose installation-iso
        }
        if ($Name -ceq $identity.Name) { return $true }
        if (-not $Name.StartsWith($identity.Name + '-', [System.StringComparison]::Ordinal)) { return $false }
        $suffix = $Name.Substring($identity.Name.Length + 1)
        $withSuffix = if ($LocalBuilder) {
            New-AtlasoVmwareTestIdentity -LocalBuilder -SourceCommit $SourceCommit `
                -Purpose installation-iso -CollisionSuffix $suffix
        }
        else {
            New-AtlasoVmwareTestIdentity -PullRequestNumber $PullRequestNumber `
                -Purpose installation-iso -CollisionSuffix $suffix
        }
        return $Name -ceq $withSuffix.Name
    }
    catch { return $false }
}

<#
.SYNOPSIS
Preserve ordinary output containment or require a paired external-root receipt.
.PARAMETER Worktree
Exact source checkout.
.PARAMETER OutputDirectory
Canonical VM output directory.
.PARAMETER Name
Canonical VM display name.
.PARAMETER SourceCommit
Exact checked-out source commit.
.PARAMETER PullRequestNumber
Owning pull request number, or zero for a local VM.
.PARAMETER LocalBuilder
Select a local VM identity instead of a pull-request identity.
.PARAMETER ReceiptPath
Original validation-root receipt path, if external output is requested.
.PARAMETER ReceiptSha256
Independently preserved creation-time digest for ReceiptPath.
#>
function Assert-AtlasoTestVmValidationRootSelector {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$Worktree,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$SourceCommit,
        [Parameter(Mandatory = $true)][int]$PullRequestNumber,
        [Parameter(Mandatory = $true)][bool]$LocalBuilder,
        [string]$ReceiptPath = '',
        [string]$ReceiptSha256 = ''
    )

    $hasPath = -not [string]::IsNullOrWhiteSpace($ReceiptPath)
    $hasDigest = -not [string]::IsNullOrWhiteSpace($ReceiptSha256)
    if ($hasPath -xor $hasDigest) {
        throw 'External installation VM admission requires the original validation-root receipt and its independently preserved SHA-256.'
    }
    if (-not $hasPath) {
        if (-not (Test-AtlasoTestVmStrictDescendantPath -ParentPath $Worktree -ChildPath $OutputDirectory)) {
            throw 'Ordinary test-VM output must remain beneath the task checkout.'
        }
        return $false
    }
    if ($ReceiptSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
        -not (Test-AtlasoTestVmCanonicalInstallationIsoName -Name $Name -SourceCommit $SourceCommit `
            -PullRequestNumber $PullRequestNumber -LocalBuilder:$LocalBuilder)) {
        throw 'External validation-root admission requires its original receipt digest and a canonical installation-ISO VM identity.'
    }
    return $true
}

<#
.SYNOPSIS
Validate a preserved external validation-root creation record.
.PARAMETER Context
Admitted task identity, checkout, and durable evidence context.
.PARAMETER Record
Parsed original validation-root creation receipt.
.PARAMETER ReceiptPath
Canonical path of the original receipt inside task evidence.
.PARAMETER ReceiptSha256
Independently preserved creation-time digest.
.PARAMETER ObservedRootIdentity
Native identity of the pinned validation root.
#>
function Assert-AtlasoTestVmValidationRootReceiptRecord {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][psobject]$Record,
        [Parameter(Mandatory = $true)][string]$ReceiptPath,
        [Parameter(Mandatory = $true)][string]$ReceiptSha256,
        [Parameter(Mandatory = $true)][string]$ObservedRootIdentity
    )

    $requiredProperties = @(
        'schema', 'phase', 'kind', 'task_id', 'repository', 'source_branch', 'source_commit',
        'worktree', 'worktree_directory_identity', 'pull_request_number', 'local_builder',
        'path', 'directory_identity', 'created_utc', 'cleanup_tool'
    )
    $actualProperties = @($Record.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $expectedProperties = @($requiredProperties | Sort-Object)
    if (@(Compare-Object -ReferenceObject $expectedProperties -DifferenceObject $actualProperties).Count -ne 0 -or
        $Record.schema -ne 1 -or $Record.phase -cne 'installation-validation-root-created' -or
        $Record.kind -cne 'artifact' -or $Record.task_id -cne $Context.TaskId -or
        $Record.repository -cne $Context.Repository -or $Record.source_branch -cne $Context.Branch -or
        $Record.worktree -cne $Context.Worktree -or
        $Record.worktree_directory_identity -cne $Context.WorktreeDirectoryId -or
        [int]$Record.pull_request_number -ne [int]$Context.PullRequestNumber -or
        [bool]$Record.local_builder -ne [bool]$Context.LocalBuilder -or
        [string]$Record.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Record.worktree_directory_identity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
        [string]$Record.directory_identity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
        $ObservedRootIdentity -cne [string]$Record.directory_identity -or
        [string]$ReceiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Record.cleanup_tool -cne 'Remove-AtlasoWorkstationArtifactRoot -ExpectedRemovalRoot <exact originally recorded path>') {
        throw 'Validation-root creation receipt does not match the admitted task and supported ownership contract.'
    }
    $created = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse(
            [string]$Record.created_utc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$created
        ) -or $created.Offset -ne [TimeSpan]::Zero) {
        throw 'Validation-root creation receipt timestamp is malformed.'
    }
    if ([string]$Record.path -cne [System.IO.Path]::GetFullPath([string]$Record.path).TrimEnd('\', '/') -or
        -not [System.IO.Path]::IsPathFullyQualified([string]$Record.path)) {
        throw 'Validation-root creation receipt path is not canonical and absolute.'
    }
    $rootPath = [System.IO.Path]::GetFullPath([string]$Record.path).TrimEnd('\', '/')
    $volumeRoot = [System.IO.Path]::GetPathRoot($rootPath).TrimEnd('\', '/')
    if (-not $volumeRoot -or $rootPath.Equals($volumeRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Validation-root creation receipt cannot designate a volume root.'
    }
    foreach ($protectedPath in @($Context.Worktree, $Context.EvidenceDirectory)) {
        $protected = [System.IO.Path]::GetFullPath([string]$protectedPath).TrimEnd('\', '/')
        if ($rootPath.Equals($protected, [System.StringComparison]::OrdinalIgnoreCase) -or
            (Test-AtlasoTestVmStrictDescendantPath -ParentPath $rootPath -ChildPath $protected) -or
            (Test-AtlasoTestVmStrictDescendantPath -ParentPath $protected -ChildPath $rootPath)) {
            throw 'Validation-root overlaps the task source or durable ownership evidence.'
        }
    }
    if (-not (Test-AtlasoTestVmStrictDescendantPath -ParentPath $rootPath -ChildPath $Context.OutputDirectory)) {
        throw 'Installation VM output must be strictly beneath its receipted validation root.'
    }
    if (-not (Test-AtlasoTestVmCanonicalInstallationIsoName -Name $Context.Name `
            -SourceCommit $Context.SourceCommit -PullRequestNumber $Context.PullRequestNumber `
            -LocalBuilder:$Context.LocalBuilder)) {
        throw 'External validation-root receipt cannot admit a noncanonical installation-ISO VM.'
    }
    & git -C $Context.Worktree merge-base --is-ancestor ([string]$Record.source_commit) $Context.SourceCommit 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'Validation-root receipt source is not an ancestor of the admitted checkout.'
    }
    return [pscustomobject]@{
        Path = $rootPath
        DirectoryIdentity = [string]$Record.directory_identity
        ReceiptPath = [System.IO.Path]::GetFullPath($ReceiptPath)
        ReceiptSha256 = $ReceiptSha256.ToLowerInvariant()
        SourceCommit = [string]$Record.source_commit
    }
}

<#
.SYNOPSIS
Check receipt size and digest before parsing its original JSON bytes.
.PARAMETER Text
UTF-8 receipt text read through the caller's retained single-link file pin.
.PARAMETER ExpectedSha256
Independently preserved creation-time digest.
.PARAMETER ObservedSha256
Digest calculated from the pinned receipt file.
.PARAMETER Length
Byte length reported for the pinned receipt file.
#>
function Read-AtlasoTestVmValidationRootReceiptEnvelope {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$ObservedSha256,
        [Parameter(Mandatory = $true)][long]$Length
    )

    if ($Length -lt 1 -or $Length -gt 65536 -or
        $ExpectedSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
        $ObservedSha256 -ine $ExpectedSha256) {
        throw 'Validation-root receipt differs from its independently preserved creation digest.'
    }
    $document = $null
    try {
        $record = $Text | ConvertFrom-Json -ErrorAction Stop
        # Recent PowerShell versions deserialize ISO timestamps as local DateTime.
        # Preserve the original UTC string before checking its recorded offset.
        $document = [System.Text.Json.JsonDocument]::Parse($Text)
        $timestamp = $document.RootElement.GetProperty('created_utc')
        if ($timestamp.ValueKind -ne [System.Text.Json.JsonValueKind]::String) {
            throw 'The creation timestamp must be a JSON string.'
        }
        $record.created_utc = $timestamp.GetString()
        return $record
    }
    catch { throw 'Validation-root creation receipt is not valid JSON with a creation timestamp.' }
    finally { if ($document) { $document.Dispose() } }
}

<#
.SYNOPSIS
Hold external root and receipt pins for the lifetime of one VM operation.
.PARAMETER RootPath
Original external validation-root path.
.PARAMETER DirectoryIdentity
Original native identity of RootPath.
.PARAMETER ReceiptPath
Original root receipt path in task evidence.
.PARAMETER ReceiptSha256
Independently preserved root receipt digest.
.PARAMETER SourceCommit
Original source commit recorded by the root creation receipt.
.PARAMETER Pins
IDisposable containing retained native root and receipt pins.
#>
function ConvertTo-AtlasoTestVmValidationRootAdmission {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [Parameter(Mandatory = $true)][string]$DirectoryIdentity,
        [Parameter(Mandatory = $true)][string]$ReceiptPath,
        [Parameter(Mandatory = $true)][string]$ReceiptSha256,
        [Parameter(Mandatory = $true)][string]$SourceCommit,
        [Parameter(Mandatory = $true)][System.IDisposable]$Pins
    )

    $admission = [pscustomobject]@{
        RootPath = $RootPath
        DirectoryIdentity = $DirectoryIdentity
        ReceiptPath = $ReceiptPath
        ReceiptSha256 = $ReceiptSha256.ToLowerInvariant()
        SourceCommit = $SourceCommit
        Pins = $Pins
        Disposed = $false
    }
    $admission | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
        if (-not $this.Disposed) {
            $this.Pins.Dispose()
            $this.Disposed = $true
        }
    }
    return $admission
}

<#
.SYNOPSIS
Read and pin the original external validation-root creation receipt.
.PARAMETER Context
Admitted task identity, checkout, and durable evidence context.
.PARAMETER ReceiptPath
Original receipt path preserved in task ownership evidence.
.PARAMETER ReceiptSha256
Independently preserved creation-time digest.
#>
function Read-AtlasoTestVmValidationRootReceipt {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][string]$ReceiptPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ReceiptSha256
    )

    $evidencePath = [System.IO.Path]::GetFullPath([string]$Context.EvidenceDirectory).TrimEnd('\', '/')
    $receipt = [System.IO.Path]::GetFullPath($ReceiptPath)
    $normalizedReceiptSha256 = $ReceiptSha256.ToLowerInvariant()
    if (-not [System.IO.Path]::IsPathFullyQualified($ReceiptPath) -or
        $receipt -cne $ReceiptPath -or
        [System.IO.Path]::GetDirectoryName($receipt) -ine $evidencePath) {
        throw 'Validation-root receipt must be a direct child of task ownership evidence.'
    }
    $pins = [Atlaso.WorkstationFileIdentity+ReadOnlySourcePins]::new()
    try {
        # The native pin checks every ancestor without following reparse points.
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($evidencePath, $true))
        if ([Atlaso.WorkstationFileIdentity]::Get($evidencePath) -cne [string]$Context.EvidenceDirectoryId) {
            throw 'Task ownership evidence identity changed before validation-root admission.'
        }
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($receipt, $true))
        $item = Get-Item -LiteralPath $receipt -Force -ErrorAction Stop
        if ($item.Length -gt 65536 -or
            $item.Length -lt 1) { throw 'Validation-root receipt size is outside its bounded ownership format.' }
        $recordText = Get-Content -LiteralPath $receipt -Raw -ErrorAction Stop
        $recordHash = (Get-FileHash -LiteralPath $receipt -Algorithm SHA256).Hash
        $record = Read-AtlasoTestVmValidationRootReceiptEnvelope -Text $recordText `
            -ExpectedSha256 $normalizedReceiptSha256 -ObservedSha256 $recordHash -Length $item.Length
        if (-not [System.IO.Path]::IsPathFullyQualified([string]$record.path)) {
            throw 'Validation-root creation receipt path is not absolute.'
        }
        $rootPath = [System.IO.Path]::GetFullPath([string]$record.path).TrimEnd('\', '/')
        # Refuse unrelated receipt paths before consulting their filesystem metadata.
        if (-not (Test-AtlasoTestVmStrictDescendantPath -ParentPath $rootPath -ChildPath $Context.OutputDirectory) -or
            $rootPath.Equals([System.IO.Path]::GetPathRoot($rootPath).TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Validation-root receipt cannot designate a volume root or a root outside the requested VM output.'
        }
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($rootPath, $true))
        $rootIdentity = [Atlaso.WorkstationFileIdentity]::Get($rootPath)
        $validated = Assert-AtlasoTestVmValidationRootReceiptRecord -Context $Context -Record $record `
            -ReceiptPath $receipt -ReceiptSha256 $normalizedReceiptSha256 -ObservedRootIdentity $rootIdentity
        $admission = ConvertTo-AtlasoTestVmValidationRootAdmission -RootPath $validated.Path `
            -DirectoryIdentity $validated.DirectoryIdentity -ReceiptPath $validated.ReceiptPath `
            -ReceiptSha256 $validated.ReceiptSha256 -SourceCommit $validated.SourceCommit -Pins $pins
        return $admission
    }
    catch {
        $pins.Dispose()
        throw
    }
}

<#
.SYNOPSIS
Compare a VM record's root map with the admitted external-root receipt.
.PARAMETER Context
Admitted VM ownership context.
.PARAMETER Record
VM ownership record being published or read.
#>
function Assert-AtlasoTestVmValidationRootRecordBinding {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][psobject]$Record
    )

    $hasRecordBinding = $false
    $recordBinding = $null
    if ($Record -is [System.Collections.IDictionary]) {
        $hasRecordBinding = $Record.Contains('validation_root')
        if ($hasRecordBinding) { $recordBinding = $Record['validation_root'] }
    }
    else {
        $recordProperty = $Record.PSObject.Properties['validation_root']
        $hasRecordBinding = $null -ne $recordProperty
        if ($hasRecordBinding) { $recordBinding = $recordProperty.Value }
    }
    if (-not $hasRecordBinding -or $null -eq $recordBinding) {
        throw 'External installation VM ownership record lacks its original validation-root binding.'
    }
    $binding = $recordBinding
    $expectedFields = @('path', 'directory_identity', 'receipt_path', 'receipt_sha256')
    $actualFields = if ($binding -is [System.Collections.IDictionary]) {
        @($binding.Keys | ForEach-Object { [string]$_ } | Sort-Object)
    } else {
        @($binding.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    }
    $bindingPath = if ($binding -is [System.Collections.IDictionary]) { $binding['path'] } else { $binding.path }
    $bindingIdentity = if ($binding -is [System.Collections.IDictionary]) { $binding['directory_identity'] } else { $binding.directory_identity }
    $bindingReceiptPath = if ($binding -is [System.Collections.IDictionary]) { $binding['receipt_path'] } else { $binding.receipt_path }
    $bindingReceiptSha256 = if ($binding -is [System.Collections.IDictionary]) { $binding['receipt_sha256'] } else { $binding.receipt_sha256 }
    if (@(Compare-Object -ReferenceObject @($expectedFields | Sort-Object) -DifferenceObject $actualFields).Count -ne 0 -or
        [string]$bindingPath -cne [string]$Context.ValidationRootAdmission.RootPath -or
        [string]$bindingIdentity -cne [string]$Context.ValidationRootAdmission.DirectoryIdentity -or
        [string]$bindingReceiptPath -cne [string]$Context.ValidationRootAdmission.ReceiptPath -or
        [string]$bindingReceiptSha256 -cne [string]$Context.ValidationRootAdmission.ReceiptSha256) {
        throw 'VM ownership record validation-root binding differs from the original admitted receipt.'
    }
}

<#
.SYNOPSIS
Require a VM ownership record to match its admitted validation-root receipt.
.PARAMETER Context
Admitted VM ownership context.
.PARAMETER Record
VM ownership record being published or read.
#>
function Assert-AtlasoTestVmValidationRootBinding {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][psobject]$Record
    )

    $admission = if ($Context.PSObject.Properties['ValidationRootAdmission']) {
        $Context.ValidationRootAdmission
    } else { $null }
    $hasRecordBinding = $false
    $recordBinding = $null
    if ($Record -is [System.Collections.IDictionary]) {
        $hasRecordBinding = $Record.Contains('validation_root')
        if ($hasRecordBinding) { $recordBinding = $Record['validation_root'] }
    }
    else {
        $recordProperty = $Record.PSObject.Properties['validation_root']
        $hasRecordBinding = $null -ne $recordProperty
        if ($hasRecordBinding) { $recordBinding = $recordProperty.Value }
    }
    if (-not $admission) {
        if ($hasRecordBinding -and $null -ne $recordBinding) {
            throw 'Ordinary task-worktree VM records cannot claim an external validation root.'
        }
        return
    }
    if ($admission.Disposed -or [Atlaso.WorkstationFileIdentity]::Get([string]$admission.RootPath) -cne [string]$admission.DirectoryIdentity) {
        throw 'The admitted external validation root changed or its retained pins were released.'
    }
    Assert-AtlasoTestVmValidationRootRecordBinding -Context $Context -Record $Record
}

<#
.SYNOPSIS
Resolve and admit one task-owned normal test-VM checkout.
.PARAMETER Worktree
Exact source checkout containing the test-VM wrapper.
.PARAMETER OwnershipRoot
Optional existing permitted durable root containing the checkout for an explicit human CLI run.
.PARAMETER OwnershipTaskId
Exact task identity for an explicit human CLI run.
.PARAMETER OwnershipReceiptPath
Original receipt path preserved in the task resource inventory for redeployment.
.PARAMETER OwnershipReceiptSha256
Creation-time receipt digest preserved independently in the task inventory.
.PARAMETER ValidationRootReceiptPath
Original receipt path for the separately approved external installation-ISO validation root.
.PARAMETER ValidationRootReceiptSha256
Independently preserved creation-time digest for ValidationRootReceiptPath.
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
        [string]$OwnershipReceiptPath = '',
        [string]$OwnershipReceiptSha256 = '',
        [string]$ValidationRootReceiptPath = '',
        [string]$ValidationRootReceiptSha256 = '',
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
    $validationReceiptSupplied = -not [string]::IsNullOrWhiteSpace($ValidationRootReceiptPath) -or
        -not [string]::IsNullOrWhiteSpace($ValidationRootReceiptSha256)
    if ($validationReceiptSupplied -and -not ($manualRootSupplied -or $agentTaskId)) {
        throw 'External validation-root selectors require an enabled, receipt-backed task ownership context.'
    }
    if ($manualRootSupplied -xor $manualTaskSupplied) {
        throw 'Pass both -OwnershipRoot and -OwnershipTaskId to opt in to human CLI ownership receipts.'
    }
    $agentMode = -not [string]::IsNullOrWhiteSpace($agentTaskId)
    if ($agentMode -and ($manualRootSupplied -or $manualTaskSupplied)) {
        throw 'Agent ownership receipts use the active Codex task and configured worktree root; explicit human selectors are not accepted.'
    }
    if (-not $manualRootSupplied -and -not $agentMode) {
        if ($OwnershipReceiptPath -or $OwnershipReceiptSha256 -or
            $ValidationRootReceiptPath -or $ValidationRootReceiptSha256) {
            throw 'Human receipt verification requires the paired permitted ownership root and task identity.'
        }
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
    $hasValidationRootReceiptPath = Assert-AtlasoTestVmValidationRootSelector `
        -Worktree $worktreePath -OutputDirectory $outputPath -Name $Name -SourceCommit $SourceCommit `
        -PullRequestNumber $PullRequestNumber -LocalBuilder:$LocalBuilder `
        -ReceiptPath $ValidationRootReceiptPath -ReceiptSha256 $ValidationRootReceiptSha256
    if (-not $vmxFullPath.Equals((Join-Path $outputPath "$Name.vmx"), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Test-VM ownership VMX paths must use the canonical name inside the output directory.'
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
    if ([bool]$OwnershipReceiptPath -xor [bool]$OwnershipReceiptSha256) {
        throw 'Pass both the original ownership receipt path and its independently preserved creation-time SHA-256.'
    }
    if ($OwnershipReceiptPath -and
        (-not [System.IO.Path]::IsPathFullyQualified($OwnershipReceiptPath) -or
            $OwnershipReceiptSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            -not [System.IO.Path]::GetFullPath($OwnershipReceiptPath).StartsWith(
                $evidencePrefix, [System.StringComparison]::OrdinalIgnoreCase))) {
        throw 'The supplied original receipt must have an exact in-scope path and creation-time digest.'
    }
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
    $worktreePin = $null
    $outputAncestorPin = $null
    $validationRootAdmission = $null
    try {
        $configuredRootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($configuredRoot, $true)
        $rootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($evidenceFullPath, $true)
        $worktreePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($worktreePath, $true)
        $outputAncestorPin = Get-AtlasoTestVmOutputAncestorPin -OutputDirectory $outputPath
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
        $admittedEvidenceDirectoryId = [Atlaso.WorkstationFileIdentity]::Get($evidenceFullPath)
        $admittedWorktreeDirectoryId = [Atlaso.WorkstationFileIdentity]::Get($worktreePath)
        if ($hasValidationRootReceiptPath) {
            $contextForValidationRoot = [pscustomobject]@{
                TaskId = $taskId
                Repository = 'mdaneri/Atlaso'
                Worktree = $worktreePath
                WorktreeDirectoryId = $admittedWorktreeDirectoryId
                PermittedRoot = $configuredRoot
                Branch = $SourceBranch
                SourceCommit = $SourceCommit
                PullRequestNumber = $PullRequestNumber
                LocalBuilder = [bool]$LocalBuilder
                Name = $Name
                EvidenceDirectory = $evidenceFullPath
                EvidenceDirectoryId = $admittedEvidenceDirectoryId
                OutputDirectory = $outputPath
            }
            $validationRootAdmission = Read-AtlasoTestVmValidationRootReceipt `
                -Context $contextForValidationRoot `
                -ReceiptPath $ValidationRootReceiptPath `
                -ReceiptSha256 $ValidationRootReceiptSha256
        }
    }
    catch {
        if ($validationRootAdmission) { $validationRootAdmission.Dispose() }
        throw
    }
    finally {
        if ($rootPin) { $rootPin.Dispose() }
        if ($outputAncestorPin) { $outputAncestorPin.Dispose() }
        if ($worktreePin) { $worktreePin.Dispose() }
        if ($configuredRootPin) { $configuredRootPin.Dispose() }
    }

    return [pscustomobject]@{
        Enabled             = $true
        TaskId              = $taskId
        Repository          = 'mdaneri/Atlaso'
        Worktree            = $worktreePath
        WorktreeDirectoryId = $admittedWorktreeDirectoryId
        PermittedRoot       = $configuredRoot
        Branch              = $SourceBranch
        SourceCommit        = $SourceCommit
        PullRequestNumber   = $PullRequestNumber
        LocalBuilder        = [bool]$LocalBuilder
        Name                = $Name
        OutputDirectory     = $outputPath
        VmxPath             = $vmxFullPath
        EvidenceDirectory   = $evidenceFullPath
        EvidenceDirectoryId = $admittedEvidenceDirectoryId
        ReceiptPath         = $OwnershipReceiptPath
        ReceiptSha256       = $OwnershipReceiptSha256.ToLowerInvariant()
        ValidationRootAdmission = $validationRootAdmission
    }
}

<#
.SYNOPSIS
Revalidate the admitted task checkout immediately before infrastructure mutation.
.PARAMETER Context
Original task checkout, branch and exact source commit admitted before preflight.
#>
function Assert-AtlasoTestVmCheckoutSource {
    param([Parameter(Mandatory = $true)][psobject]$Context)
    if (-not $Context.Enabled) { return }
    $borrowed = $Context.PSObject.Properties['CheckoutSourcePin'] -and $Context.CheckoutSourcePin
    $sourcePin = if ($borrowed) { $Context.CheckoutSourcePin } else {
        $holder = [pscustomobject]@{
            Pins = [Collections.Generic.List[object]]::new()
            Files = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            Directories = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            Disposed = $false
        }
        $holder | Add-Member ScriptMethod Dispose {
            for ($i=$this.Pins.Count-1; $i -ge 0; $i--) { $this.Pins[$i].Dispose() }
            $this.Pins.Clear(); $this.Disposed=$true
        }
        $holder
    }
    $published = $false
    $worktreePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([string]$Context.Worktree, $true)
    try {
    if ($sourcePin.Disposed) { throw 'Verified checkout source handles were already released; mutation refused.' }
    if ($Context.PSObject.Properties['ValidationRootAdmission'] -and $Context.ValidationRootAdmission) {
        if ($Context.ValidationRootAdmission.Disposed -or
            [Atlaso.WorkstationFileIdentity]::Get([string]$Context.ValidationRootAdmission.RootPath) -cne
            [string]$Context.ValidationRootAdmission.DirectoryIdentity) {
            throw 'The original external validation-root identity or retained pins changed; mutation refused.'
        }
    }
    if (-not $Context.PSObject.Properties['WorktreeDirectoryId'] -or
        [Atlaso.WorkstationFileIdentity]::Get([string]$Context.Worktree) -cne [string]$Context.WorktreeDirectoryId) {
        throw 'The admitted task worktree filesystem identity changed; infrastructure mutation refused.'
    }
    $root = ([string](& git -C $Context.Worktree rev-parse --show-toplevel 2>$null)).Trim()
    $rootFailed = $LASTEXITCODE -ne 0
    $commit = ([string](& git -C $Context.Worktree rev-parse HEAD 2>$null)).Trim()
    $commitFailed = $LASTEXITCODE -ne 0
    $branch = ([string](& git -C $Context.Worktree branch --show-current 2>$null)).Trim()
    $branchFailed = $LASTEXITCODE -ne 0
    $status = @(& git -C $Context.Worktree -c core.fsmonitor=false -c core.ignoreStat=false status --porcelain --untracked-files=all 2>$null)
    if ($rootFailed -or $commitFailed -or $branchFailed -or $LASTEXITCODE -ne 0 -or -not $root -or
        -not ([IO.Path]::GetFullPath($root).TrimEnd('\', '/')).Equals([string]$Context.Worktree, [StringComparison]::OrdinalIgnoreCase) -or
        $commit -cne [string]$Context.SourceCommit -or $branch -cne [string]$Context.Branch -or $status.Count) {
        throw 'The admitted clean task checkout, branch or source commit changed during preflight; infrastructure mutation refused.'
    }
    & git -C $Context.Worktree diff --cached --quiet --no-ext-diff HEAD -- 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'The admitted source index changed during preflight; infrastructure mutation refused.' }
    $entries = @(& git --no-replace-objects -C $Context.Worktree -c core.quotePath=false ls-tree -r --full-tree $Context.SourceCommit 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $entries.Count) { throw 'Tracked source enumeration failed during preflight.' }
    $paths = [Collections.Generic.List[string]]::new()
    $expected = [Collections.Generic.List[string]]::new()
    $committed = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $entries) {
        $match = [regex]::Match($entry, '^(100644|100755) blob ([0-9a-f]{40})\t([^"\r\n]+)$')
        if (-not $match.Success) {
            throw 'Tracked source flags or ambiguous file admission changed during preflight; infrastructure mutation refused.'
        }
        $expected.Add($match.Groups[2].Value)
        $committed.Add($match.Groups[3].Value,($match.Groups[1].Value+' '+$match.Groups[2].Value))
        $file = [IO.Path]::GetFullPath((Join-Path $Context.Worktree $match.Groups[3].Value))
        if (-not $file.StartsWith(([string]$Context.Worktree + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Tracked source path escaped the admitted checkout.'
        }
        $directory = [IO.Path]::GetDirectoryName($file)
        if ($sourcePin.Directories.Add($directory)) {
            $sourcePin.Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($directory,$true))
        }
        if ($sourcePin.Files.Add($file)) {
            $sourcePin.Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($file,$true))
        }
        # hash-object reads file bytes independently of index stat/fsmonitor caches,
        # while applying the same checkout normalization as Git's clean filters.
        $paths.Add('"' + $match.Groups[3].Value.Replace('\', '\\').Replace('"', '\"') + '"')
    }
    $indexEntries = @(& git -C $Context.Worktree -c core.quotePath=false ls-files -v --stage 2>$null)
    if ($LASTEXITCODE -ne 0 -or $indexEntries.Count -ne $entries.Count) { throw 'The admitted source index inventory changed during preflight.' }
    foreach ($entry in $indexEntries) {
        $match = [regex]::Match($entry, '^H (100644|100755) ([0-9a-f]{40}) 0\t([^"\r\n]+)$')
        if (-not $match.Success -or -not $committed.ContainsKey($match.Groups[3].Value) -or
            $committed[$match.Groups[3].Value] -cne ($match.Groups[1].Value+' '+$match.Groups[2].Value)) {
            throw 'The admitted source index or flags changed during preflight; infrastructure mutation refused.'
        }
    }
    $actual = @($paths | & git -C $Context.Worktree hash-object --stdin-paths 2>$null)
    if ($LASTEXITCODE -ne 0 -or $actual.Count -ne $expected.Count) {
        throw 'Tracked source hashing failed during preflight; infrastructure mutation refused.'
    }
    for ($index = 0; $index -lt $expected.Count; $index++) {
        if ([string]$actual[$index] -cne $expected[$index]) {
            throw 'Tracked source bytes changed during preflight; infrastructure mutation refused.'
        }
    }
    $parsedSources = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    $loadedCommands = @(Get-Command -CommandType Function -All) + @(Get-PSCallStack | ForEach-Object { $_.InvocationInfo.MyCommand })
    foreach ($module in (Get-Module -All)) {
        if ($module.SessionState) {
            $loadedCommands += @(& $module { Microsoft.PowerShell.Management\Get-ChildItem Function: })
        }
    }
    foreach ($command in $loadedCommands) {
        if (-not $command -or -not $command.PSObject.Properties['ScriptBlock']) { continue }
        $block = $command.ScriptBlock
        if (-not $block -or -not $block.File) { continue }
        $file = [IO.Path]::GetFullPath($block.File)
        if (-not $file.StartsWith(([string]$Context.Worktree + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not $sourcePin.Files.Contains($file)) { throw 'Loaded checkout code is outside the admitted commit.' }
        if (-not $parsedSources.ContainsKey($file)) {
            $parsedSources.Add($file,[IO.File]::ReadAllText($file).Replace("`r`n","`n").TrimStart([char]0xfeff))
        }
        $parsed = $block.Ast.Extent.StartScriptPosition.GetFullScript().Replace("`r`n","`n").TrimStart([char]0xfeff)
        if ($parsed -cne $parsedSources[$file]) { throw 'Already parsed checkout code differs from the admitted source; mutation refused.' }
    }
    $Context | Add-Member CheckoutSourcePin $sourcePin -Force
    $published = $true
    }
    finally {
        $worktreePin.Dispose()
        if (-not $borrowed -and -not $published) { $sourcePin.Dispose() }
    }
}

<#
.SYNOPSIS
Pin every existing ancestor of the clone destination before provider mutation.
.PARAMETER OutputDirectory
Admitted canonical clone directory, which may not exist yet.
#>
function Get-AtlasoTestVmOutputAncestorPin {
    [CmdletBinding()]
    [OutputType([System.IDisposable])]
    param([Parameter(Mandatory = $true)][string]$OutputDirectory)

    $ancestor = [System.IO.Path]::GetFullPath($OutputDirectory)
    while (-not (Test-Path -LiteralPath $ancestor)) {
        $parent = [System.IO.Path]::GetDirectoryName($ancestor)
        if (-not $parent -or $parent -eq $ancestor) {
            throw 'The clone destination has no ordinary existing ancestor.'
        }
        $ancestor = $parent
    }
    return [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($ancestor, $true)
}

<#
.SYNOPSIS
Record a suspended clone child before preparing its directory or permitting execution.
.PARAMETER Context
Original admitted task/source intent and canonical destination.
.PARAMETER FilePath
Verified clone executable.
.PARAMETER ArgumentList
Public clone arguments passed without shell interpolation.
.PARAMETER TimeoutSeconds
Bounded clone execution deadline.
#>
function Invoke-AtlasoTestVmOwnedClone {
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][ValidateRange(1, 86400)][int]$TimeoutSeconds
    )
    if (-not $Context.Enabled -or [string]$Context.InvocationId -cnotmatch '^[0-9a-f]{32}$') {
        throw 'Owned clone execution requires the original task intent.'
    }
    if (-not (Get-Command Invoke-AtlasoBoundedStreamingProcess -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
    }
    $jobName = 'Local\Atlaso-TestVm-Clone-' + $Context.InvocationId
    $publisher = {
        param($Job)
        $controller = Get-Process -Id $PID -ErrorAction Stop
        try {
            $record = [ordered]@{
                schema = 1; kind = 'clone_process'; task_id = [string]$Context.TaskId
                repository = [string]$Context.Repository; worktree = [string]$Context.Worktree
                source_commit = [string]$Context.SourceCommit; invocation_id = [string]$Context.InvocationId
                output_directory = [string]$Context.OutputDirectory
                intent_path = [string]$Context.IntentPath; intent_sha256 = [string]$Context.IntentSha256
                BootIdentity = Get-AtlasoWindowsBootIdentity
                OwnerProcessId = $PID; OwnerProcessStartFileTimeUtc = $controller.StartTime.ToUniversalTime().ToFileTimeUtc()
                ProcessJobName = $jobName; ProcessOwnershipPhase = 'assigned'
                ChildProcessId = $Job.RootProcess.Id
                ChildProcessStartFileTimeUtc = $Job.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
            }
            $published = Publish-AtlasoTestVmOwnershipRecord -Context $Context -Record $record -Kind clone-process
            $Context | Add-Member -NotePropertyName CloneProcessReceipt -NotePropertyValue @{path=$published.Path; sha256=$published.Sha256} -Force
            Write-Host "Test VM clone process receipt: $($published.Path)"
            Write-Host "Test VM clone process receipt SHA-256: $($published.Sha256)"
            $Context | Add-Member -NotePropertyName CloneOutputPin -NotePropertyValue (New-AtlasoTestVmPreparedOutput -Context $Context) -Force
            Assert-AtlasoTestVmCheckoutSource -Context $Context
        }
        finally { $controller.Dispose() }
    }
    Invoke-AtlasoBoundedStreamingProcess -FilePath $FilePath -ArgumentList $ArgumentList `
        -TimeoutSeconds $TimeoutSeconds -Action 'Receipt-bound VMware clone' -ProcessJobName $jobName -ProcessOwnershipPublisher $publisher
}

<#
.SYNOPSIS
Prove the original clone controller and child tree quiescent before directory recovery.
.PARAMETER Context
Admitted recovery task and canonical destination.
.PARAMETER DirectoryRecord
Original independently verified directory receipt containing the pre-creation process receipt binding.
#>
function Assert-AtlasoTestVmCloneQuiescence {
    param([psobject]$Context, [psobject]$DirectoryRecord)
    if (-not $DirectoryRecord.PSObject.Properties['clone_process'] -or -not $DirectoryRecord.clone_process) {
        throw 'The original directory lacks clone process creation evidence; preserve it without retrofitting.'
    }
    $binding = $DirectoryRecord.clone_process
    $path = [IO.Path]::GetFullPath([string]$binding.path)
    $scope = [IO.Path]::GetFullPath([string]$Context.EvidenceDirectory).TrimEnd('\', '/') + '\'
    if (-not $path.StartsWith($scope, [StringComparison]::OrdinalIgnoreCase) -or [string]$binding.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Clone process receipt is outside its original evidence binding.'
    }
    $parentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($path), $true)
    $filePin = $null
    try {
        $filePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true)
        if ((Get-Item -LiteralPath $path).Length -gt 65536 -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine [string]$binding.sha256) {
            throw 'Original clone process receipt changed; preserve the prepared directory.'
        }
        $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($record.schema -ne 1 -or $record.kind -cne 'clone_process' -or
            [string]$record.task_id -cne [string]$Context.TaskId -or [string]$record.repository -cne [string]$Context.Repository -or
            [string]$record.worktree -cne [string]$Context.Worktree -or [string]$record.output_directory -cne [string]$Context.OutputDirectory -or
            [string]$record.source_commit -cne [string]$DirectoryRecord.source_commit -or
            [string]$record.invocation_id -cne [string]$DirectoryRecord.invocation_id -or
            [string]$record.intent_path -cne [string]$DirectoryRecord.intent_path -or
            [string]$record.intent_sha256 -cne [string]$DirectoryRecord.intent_sha256 -or
            [string]$record.ProcessJobName -cne ('Local\Atlaso-TestVm-Clone-' + $record.invocation_id)) {
            throw 'Original clone process receipt does not match the preparation intent.'
        }
        if (-not (Get-Command Complete-AtlasoSameBootBoundedProcessRecovery -ErrorAction SilentlyContinue)) {
            . (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
        }
        $boot = Get-AtlasoWindowsBootIdentityState -BootIdentity $record.BootIdentity
        if ($boot -eq 'current') {
            Complete-AtlasoSameBootBoundedProcessRecovery -Marker $record `
                -JobNamePattern '^Local\\Atlaso-TestVm-Clone-[0-9a-f]{32}$' -ProcessDescription 'test-VM clone'
        }
        elseif ($boot -ne 'prior') { throw 'Clone boot identity cannot establish quiescence.' }
    }
    finally {
        if ($filePin) { $filePin.Dispose() }
        $parentPin.Dispose()
    }
}

<#
.SYNOPSIS
Exclusively create and receipt missing destination components while retaining their native handles.
.PARAMETER Context
Task context containing the previously published clone intent.
#>
function New-AtlasoTestVmPreparedOutput {
    [CmdletBinding()]
    [OutputType([System.IDisposable])]
    param([Parameter(Mandatory = $true)][psobject]$Context)

    if (-not $Context.Enabled -or -not $Context.IntentPath -or -not $Context.IntentSha256) {
        throw 'Destination creation requires the published task intent.'
    }
    if ($Context.PSObject.Properties['RestoredDirectoryReceiptPath'] -and $Context.RestoredDirectoryReceiptPath) {
        Assert-AtlasoTestVmRestoredDirectory -Context $Context -AllowReset:([bool]$Context.RestoredDataReset) | Out-Null
        return $Context.RestoredOutputPin
    }
    $intentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile([string]$Context.IntentPath, $true)
    try {
        if ((Get-FileHash -LiteralPath $Context.IntentPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            [string]$Context.IntentSha256) { throw 'The clone intent changed before directory creation.' }
        $publish = [System.Action[string, string]]{
            param($CreatedPath, $OriginalIdentity)
            $record = [ordered]@{
                schema = 1; task_id = [string]$Context.TaskId; repository = [string]$Context.Repository
                source_commit = [string]$Context.SourceCommit; worktree = [string]$Context.Worktree
                invocation_id = [string]$Context.InvocationId; path = $CreatedPath; original_identity = $OriginalIdentity
                intent_path = [string]$Context.IntentPath; intent_sha256 = [string]$Context.IntentSha256
                kind = 'prepared_directory'; created_utc = [DateTimeOffset]::UtcNow.ToString('o')
                clone_process = if ($Context.PSObject.Properties['CloneProcessReceipt']) { $Context.CloneProcessReceipt } else { $null }
                cleanup_tool = 'scripts/windows/vmware/create-atlaso-test-vm.ps1 -RecoverPreparedDirectory -PreparedDirectoryReceiptPath <original-path> -PreparedDirectoryReceiptSha256 <creation-digest>'
                retention = 'Canonical incomplete output is recoverable only with the independently preserved preparation selectors; preserve ancestor records.'
            }
            $publicationContext = $Context.PSObject.Copy()
            $publicationContext.InvocationId = [guid]::NewGuid().ToString('N')
            $published = Publish-AtlasoTestVmOwnershipRecord -Context $publicationContext -Record $record -Kind directory
            Write-Host "Test VM prepared directory receipt: $($published.Path)"
            Write-Host "Test VM prepared directory receipt SHA-256: $($published.Sha256)"
            if ($CreatedPath.Equals([string]$Context.OutputDirectory, [StringComparison]::OrdinalIgnoreCase)) {
                $Context | Add-Member -NotePropertyName PreparedOutputIdentity -NotePropertyValue $OriginalIdentity -Force
                $Context | Add-Member -NotePropertyName PreparedReceiptPath -NotePropertyValue $published.Path -Force
                $Context | Add-Member -NotePropertyName PreparedReceiptSha256 -NotePropertyValue $published.Sha256 -Force
            }
        }
        return [Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath(
            [string]$Context.OutputDirectory, $publish)
    }
    finally { $intentPin.Dispose() }
}

<#
.SYNOPSIS
Reject creation options before a cleanup-only prepared-directory recovery.
.PARAMETER BoundParameters
Explicit parameters supplied to the normal test-VM wrapper.
#>
function Assert-AtlasoPreparedRecoveryParameters {
    param([System.Collections.IDictionary]$BoundParameters)
    $allowed = @('RecoverPreparedDirectory', 'PreparedDirectoryReceiptPath', 'PreparedDirectoryReceiptSha256',
        'OwnershipRoot', 'OwnershipTaskId', 'OutputDirectory', 'PullRequestNumber', 'LocalBuilder', 'Purpose',
        'CollisionSuffix', 'VmrunPath', 'WhatIf', 'Confirm', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction',
        'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable')
    foreach ($parameterName in $BoundParameters.Keys) {
        if ($parameterName -notin $allowed) {
            throw "Prepared recovery is cleanup-only; creation parameter -$parameterName cannot be combined with it."
        }
    }
}

<#
.SYNOPSIS
Recover one receipt-bound pre-clone directory without adopting a completed VM.
.PARAMETER Context
Admitted clean task checkout and canonical destination context.
.PARAMETER ReceiptPath
Creation receipt path independently preserved when the directory was prepared.
.PARAMETER ReceiptSha256
Original creation receipt digest preserved independently in the task inventory.
.PARAMETER VmrunPath
Verified provider executable used by the owning root-scoped cleanup tool.
#>
function Remove-AtlasoTestVmPreparedOutput {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][psobject]$Context,
        [Parameter(Mandatory = $true)][string]$ReceiptPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ReceiptSha256,
        [Parameter(Mandatory = $true)][string]$VmrunPath
    )
    if (-not $Context.Enabled) { throw 'Prepared-directory recovery requires task ownership.' }
    $receipt = [IO.Path]::GetFullPath($ReceiptPath)
    $scope = [IO.Path]::GetFullPath([string]$Context.EvidenceDirectory).TrimEnd('\', '/') + '\'
    if (-not $receipt.StartsWith($scope, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The prepared-directory receipt is outside the admitted durable evidence scope.'
    }
    $evidencePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($receipt), $true)
    $receiptPin = $null
    $intentPin = $null
    $intentDirectoryPin = $null
    $directoryPin = $null
    try {
        $receiptPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($receipt, $true)
        if ((Get-Item -LiteralPath $receipt).Length -gt 65536 -or
            (Get-FileHash -LiteralPath $receipt -Algorithm SHA256).Hash -ine $ReceiptSha256) {
            throw 'The prepared-directory receipt differs from its independently preserved creation digest.'
        }
        $record = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
        if ($record.schema -ne 1 -or $record.kind -cne 'prepared_directory' -or
            [string]$record.task_id -cne [string]$Context.TaskId -or
            [string]$record.repository -cne [string]$Context.Repository -or
            [string]$record.worktree -cne [string]$Context.Worktree -or
            [string]$record.path -cne [string]$Context.OutputDirectory -or
            [string]$record.original_identity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
            [string]$record.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            [string]$record.invocation_id -cnotmatch '^[0-9a-f]{32}$' -or
            [string]$record.intent_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Prepared-directory recovery does not match the original task and canonical destination.'
        }
        $intentPath = [IO.Path]::GetFullPath([string]$record.intent_path)
        if (-not $intentPath.StartsWith($scope, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The original preparation intent is outside the durable evidence scope.'
        }
        $intentDirectoryPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($intentPath), $true)
        $intentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($intentPath, $true)
        if ((Get-Item -LiteralPath $intentPath).Length -gt 65536 -or
            (Get-FileHash -LiteralPath $intentPath -Algorithm SHA256).Hash -ine [string]$record.intent_sha256) {
            throw 'The original preparation intent changed.'
        }
        $intent = Get-Content -LiteralPath $intentPath -Raw | ConvertFrom-Json
        if ($intent.schema -ne 1 -or $intent.phase -cne 'clone-pending' -or
            [string]$intent.task_id -cne [string]$Context.TaskId -or
            [string]$intent.repository -cne [string]$Context.Repository -or
            [string]$intent.worktree -cne [string]$Context.Worktree -or
            [string]$intent.source_branch -cne [string]$Context.Branch -or
            [string]$intent.output_directory -cne [string]$Context.OutputDirectory -or
            [string]$intent.vmx_path -cne [string]$Context.VmxPath -or
            [string]$intent.canonical_name -cne [string]$Context.Name -or
            [int]$intent.pull_request_number -ne [int]$Context.PullRequestNumber -or
            [bool]$intent.local_builder -ne [bool]$Context.LocalBuilder -or
            [string]$intent.source_commit -cne [string]$record.source_commit -or
            [string]$intent.invocation_id -cne [string]$record.invocation_id) {
            throw 'The original preparation intent is not bound to this canonical task destination.'
        }
        if ([string]$record.source_commit -cne [string]$Context.SourceCommit) {
            & git -C $Context.Worktree merge-base --is-ancestor ([string]$record.source_commit) ([string]$Context.SourceCommit) 2>$null
            if ($LASTEXITCODE) { throw 'The preparation source is not an ancestor of the admitted source.' }
        }
        $directoryPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([string]$Context.OutputDirectory, $true)
        if ([Atlaso.WorkstationFileIdentity]::Get([string]$Context.OutputDirectory) -cne [string]$record.original_identity) {
            throw 'The prepared directory was replaced; preserve it.'
        }
        # A VMX needs its original VM receipt. Pre-clone recovery must never
        # manufacture that receipt or become an alternate VM deletion path.
        if ($PSCmdlet.ShouldProcess([string]$Context.OutputDirectory, 'Remove receipt-bound incomplete clone directory')) {
            Assert-AtlasoTestVmCloneQuiescence -Context $Context -DirectoryRecord $record
            $directoryPin.Dispose()
            $directoryPin = $null
            Remove-AtlasoWorkstationVmArtifacts -VmrunPath $VmrunPath -VmxPaths @() -RemovalRoot $Context.OutputDirectory -ExpectedPreparedDirectoryIdentity $record.original_identity -Confirm:$false
        }
    }
    finally {
        if ($directoryPin) { $directoryPin.Dispose() }
        if ($intentPin) { $intentPin.Dispose() }
        if ($intentDirectoryPin) { $intentDirectoryPin.Dispose() }
        if ($receiptPin) { $receiptPin.Dispose() }
        $evidencePin.Dispose()
    }
}

<#
.SYNOPSIS
Revalidate and pin the recorded source template through cloning.
.PARAMETER SourceVmxPath
Admitted read-only appliance template path.
.PARAMETER SourceVmxIdentity
Original template identity preserved in the creation intent.
.PARAMETER ExpectedSourceCommit
Exact local-builder source commit, or empty for an admitted reusable PR template.
#>
function Get-AtlasoTestVmCloneSourcePin {
    [CmdletBinding()]
    [OutputType([System.IDisposable])]
    param(
        [Parameter(Mandatory = $true)][string]$SourceVmxPath,
        [Parameter(Mandatory = $true)][string]$SourceVmxIdentity,
        [AllowEmptyString()][string]$ExpectedSourceCommit = ''
    )

    $pin = [Atlaso.WorkstationFileIdentity+ReadOnlySourcePins]::new()
    try {
        # Pin the namespace before opening the VMX and its local payload disks.
        # Acquire every disk pin before hashing; a successful provenance check
        # then describes exactly the bytes retained through the provider clone.
        $pin.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($SourceVmxPath)), $true))
        $pin.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($SourceVmxPath, $true))
        if ([Atlaso.WorkstationFileIdentity]::Get($SourceVmxPath) -cne $SourceVmxIdentity) {
            throw 'The recorded appliance template changed before cloning.'
        }
        $pin.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile([IO.Path]::ChangeExtension($SourceVmxPath, 'provenance.json'), $true))
        foreach ($payload in @(Get-AtlasoVmwarePayloadLayout -VmxPath $SourceVmxPath -RequireExactlyTwoVmdks)) {
            $pin.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($payload.File.FullName, $true))
        }
        Assert-AtlasoVmwarePayloadProvenance `
            -VmxPath $SourceVmxPath `
            -ExpectedSourceCommit $ExpectedSourceCommit | Out-Null
        return $pin
    }
    catch {
        $pin.Dispose()
        throw
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
        [Parameter(Mandatory = $true)][ValidateSet('intent', 'original', 'directory', 'clone-process', 'ca-marker', 'restored-directory', 'installation-baseline', 'installation-boot', 'installation-resume', 'installation-interruption')][string]$Kind
    )

    if (-not $Context.Enabled) { throw 'Cannot publish ownership for a disabled task context.' }
    if ($Context.PSObject.Properties['ValidationRootAdmission'] -and $Context.ValidationRootAdmission) {
        $rootBinding = [ordered]@{
            path = [string]$Context.ValidationRootAdmission.RootPath
            directory_identity = [string]$Context.ValidationRootAdmission.DirectoryIdentity
            receipt_path = [string]$Context.ValidationRootAdmission.ReceiptPath
            receipt_sha256 = [string]$Context.ValidationRootAdmission.ReceiptSha256
        }
        if ($Record.Contains('validation_root') -and $null -ne $Record['validation_root']) {
            Assert-AtlasoTestVmValidationRootBinding -Context $Context -Record $Record
        }
        else {
            $Record['validation_root'] = $rootBinding
        }
    }
    Assert-AtlasoTestVmValidationRootBinding -Context $Context -Record $Record
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
    $restored=$Context.PSObject.Properties['RestoredDirectoryReceiptPath'] -and $Context.RestoredDirectoryReceiptPath
    if ($restored) { Assert-AtlasoTestVmRestoredDirectory -Context $Context | Out-Null }
    if ((Test-Path -LiteralPath $Context.OutputDirectory) -and $null -eq $ExistingReceipt -and -not $restored) {
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
        cleanup_tool = 'scripts/windows/vmware/remove-atlaso-vm.ps1 -VmxPath <recorded-vmx> -ExpectedName <canonical-name> -ExpectedRootIdentity <original-directory-identity> -ExpectedPersistentVmIdentitySha256 <recorded-persistent-identity-sha256>'
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

        if ($Context.PSObject.Properties['CloneOutputPin'] -and $Context.CloneOutputPin) {
            # The creator already excludes replacement. Reuse its exact retained
            # handle rather than opening a pin that denies its DELETE access.
            $retainedIdentity = $Context.CloneOutputPin.GetRetainedCreatedIdentity($resolvedDirectory)
            if ($retainedIdentity -cne [string]$Context.PreparedOutputIdentity) {
                throw 'The retained original creation handle no longer matches its preparation receipt.'
            }
        }
        else { $directoryPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($resolvedDirectory, $true) }
        if ($Context.PreparedOutputIdentity -and
            [Atlaso.WorkstationFileIdentity]::Get($resolvedDirectory) -cne [string]$Context.PreparedOutputIdentity) {
            throw 'The original clone directory differs from its exclusive creation identity.'
        }
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
            restored_directory = if ($Context.PSObject.Properties['RestoredDirectoryReceiptPath'] -and $Context.RestoredDirectoryReceiptPath) {
                @{path=$Context.RestoredDirectoryReceiptPath;sha256=$Context.RestoredDirectoryReceiptSha256}
            } else {$null}
            persistent_vm_identity_sha256 = $cleanupIdentityHash
            intent_path = [string]$Context.IntentPath
            intent_sha256 = [string]$Context.IntentSha256
            cleanup_tool = 'scripts/windows/vmware/remove-atlaso-vm.ps1 -VmxPath <recorded-vmx> -ExpectedName <canonical-name> -ExpectedRootIdentity <original-directory-identity> -ExpectedPersistentVmIdentitySha256 <recorded-persistent-identity-sha256>'
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
Read an independently selected immutable task record without requiring its live VM.
.PARAMETER Context
Admitted task and durable evidence root.
.PARAMETER Path
Original receipt path preserved by its caller.
.PARAMETER Sha256
Original publication digest independently preserved by its caller.
.PARAMETER Phase
Exact expected record phase.
#>
function Read-AtlasoTestVmSealedRecord {
    param([psobject]$Context, [string]$Path, [string]$Sha256, [string]$Phase)
    if (-not $Path -or $Sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Original recovery receipt selectors are required.' }
    $root = [IO.Path]::GetFullPath([string]$Context.EvidenceDirectory).TrimEnd('\', '/')
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Recovery receipt is outside durable evidence.' }
    $rootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($root, $true)
    $filePin = $null
    try {
        if ([Atlaso.WorkstationFileIdentity]::Get($root) -cne [string]$Context.EvidenceDirectoryId) { throw 'Recovery evidence root changed.' }
        $filePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($resolved, $true)
        if ((Get-Item -LiteralPath $resolved).Length -gt 65536 -or
            (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256) { throw 'Original recovery receipt changed.' }
        $record = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
        if ($record.schema -ne 1 -or $record.phase -cne $Phase -or
            $record.task_id -cne $Context.TaskId -or $record.repository -cne $Context.Repository -or
            $record.worktree -cne $Context.Worktree -or $record.source_branch -cne $Context.Branch -or
            $record.output_directory -cne $Context.OutputDirectory -or $record.vmx_path -cne $Context.VmxPath -or
            $record.canonical_name -cne $Context.Name -or $record.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            [int]$record.pull_request_number -ne [int]$Context.PullRequestNumber -or
            [bool]$record.local_builder -ne [bool]$Context.LocalBuilder) { throw 'Recovery receipt does not match the original task and VM.' }
        & git -C $Context.Worktree merge-base --is-ancestor $record.source_commit $Context.SourceCommit 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Recovery receipt source ancestry changed.' }
        Assert-AtlasoTestVmValidationRootBinding -Context $Context -Record $record
        return $record
    }
    finally { if ($filePin) { $filePin.Dispose() }; $rootPin.Dispose() }
}

<#
.SYNOPSIS
Validate original marker and VM receipts before restoring a removed VM's data.
.PARAMETER Context
Task context with independently preserved original and marker receipt selectors.
.PARAMETER Marker
Validated stopped or removed marker with original disk identities.
#>
function Assert-AtlasoTestVmRemovedMarkerOwnership {
    param([psobject]$Context, [psobject]$Marker)
    $vm = Read-AtlasoTestVmSealedRecord -Context $Context -Path $Context.ReceiptPath -Sha256 $Context.ReceiptSha256 -Phase 'original-clone-created'
    $intent = Read-AtlasoTestVmSealedRecord -Context $Context -Path $vm.intent_path -Sha256 $vm.intent_sha256 -Phase 'clone-pending'
    if ($intent.source_commit -cne $vm.source_commit) { throw 'Original VM intent binding changed.' }
    $proof = Read-AtlasoTestVmSealedRecord -Context $Context -Path $Context.CleanupRecoveryReceiptPath -Sha256 $Context.CleanupRecoveryReceiptSha256 -Phase 'ca-marker-original'
    if ($proof.original_receipt_path -cne $Context.ReceiptPath -or $proof.original_receipt_sha256 -cne $Context.ReceiptSha256 -or
        $proof.original_directory_identity -cne $vm.original_identities.directory -or
        $proof.persistent_vm_identity_sha256 -cne $vm.persistent_vm_identity_sha256 -or
        $proof.marker_path -cne $Marker.MarkerPath -or $proof.host_boot_identity -cne $Marker.HostBootIdentity -or
        $proof.marker_projection -cne (Get-AtlasoTestVmMarkerProjection -Marker $Marker)) { throw 'Original marker removal binding changed.' }
    if (-not $Marker.ArtifactsRemoved -or $Marker.Phase -notin @('stopped-vmx-scrubbed', 'removal-child-active', 'retired')) { throw 'Marker lacks stopped removal evidence.' }
    if ($Marker.Phase -eq 'removal-child-active' -and (Get-AtlasoHostBootIdentity) -ceq $Marker.HostBootIdentity) { throw 'Removal child quiescence is not proven.' }
    return $vm
}

<#
.SYNOPSIS
Create the original restored-data root and publish its binding before moving disks.
.PARAMETER Context
Original task, VM and independently preserved marker receipt selectors.
.PARAMETER DataDiskStates
Original disk component paths, identities and admitted quarantine paths.
#>
function New-AtlasoTestVmRestoredDirectory {
    param([psobject]$Context, [object[]]$DataDiskStates)
    $proof = Read-AtlasoTestVmSealedRecord -Context $Context -Path $Context.CleanupRecoveryReceiptPath -Sha256 $Context.CleanupRecoveryReceiptSha256 -Phase 'ca-marker-original'
    $projection = $proof.marker_projection | ConvertFrom-Json
    if ($proof.original_receipt_path -cne $Context.ReceiptPath -or $proof.original_receipt_sha256 -cne $Context.ReceiptSha256 -or
        @($projection.DataDisks).Count -ne $DataDiskStates.Count) { throw 'Restoration lacks its original VM and disk binding.' }
    foreach ($disk in $DataDiskStates) {
        $match = @($projection.DataDisks | Where-Object { $_.Path -ceq $disk.Path -and $_.RelativePath -ceq $disk.RelativePath -and $_.Identity -ceq $disk.Identity })
        if ($match.Count -ne 1 -or -not $disk.QuarantinePath -or
            [IO.Path]::GetDirectoryName([string]$disk.Path) -cne $Context.OutputDirectory -or
            [IO.Path]::GetFileName([string]$disk.Path) -cne $disk.RelativePath -or
            [Atlaso.WorkstationFileIdentity]::Get([string]$disk.QuarantinePath) -cne $disk.Identity) { throw 'Original quarantined disk identity changed.' }
    }
    $publish = [Action[string,string]]{
        param($CreatedPath, $OriginalIdentity)
        $record = [ordered]@{schema=1;phase='restored-data-created';task_id=$Context.TaskId;repository=$Context.Repository;
            worktree=$Context.Worktree;source_branch=$Context.Branch;source_commit=$Context.SourceCommit;
            output_directory=$Context.OutputDirectory;vmx_path=$Context.VmxPath;canonical_name=$Context.Name;
            pull_request_number=$Context.PullRequestNumber;local_builder=$Context.LocalBuilder;
            path=$CreatedPath;original_identity=$OriginalIdentity;disks=@($projection.DataDisks);
            original_receipt_path=$Context.ReceiptPath;original_receipt_sha256=$Context.ReceiptSha256;
            marker_receipt_path=$Context.CleanupRecoveryReceiptPath;marker_receipt_sha256=$Context.CleanupRecoveryReceiptSha256}
        $publicationContext=$Context.PSObject.Copy()
        $publicationContext | Add-Member InvocationId ([guid]::NewGuid().ToString('N')) -Force
        $published=Publish-AtlasoTestVmOwnershipRecord -Context $publicationContext -Record $record -Kind restored-directory
        Write-Host "Test VM restored directory receipt: $($published.Path)"
        Write-Host "Test VM restored directory receipt SHA-256: $($published.Sha256)"
        if ($CreatedPath -ceq $Context.OutputDirectory) {
            $Context | Add-Member RestoredDirectoryReceiptPath $published.Path -Force
            $Context | Add-Member RestoredDirectoryReceiptSha256 $published.Sha256 -Force
        }
    }
    $created=[Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath([string]$Context.OutputDirectory,$publish)
    $created.Dispose()
    # Creation pins exclude writes on the entire ancestor chain. Transfer to an
    # ordinary mutation-compatible admission pin, rechecking the original ID
    # before any disk move; a replacement in the gap refuses all restoration.
    Assert-AtlasoTestVmRestoredDirectory -Context $Context -AllowQuarantine | Out-Null
    return $Context.RestoredOutputPin
}

<#
.SYNOPSIS
Admit only the originally receipted disk-only restored root for a creation retry.
.PARAMETER Context
Current task and independently preserved restored-directory receipt selectors.
.PARAMETER AllowReset
Permit an empty root only after this invocation removed the admitted disks by captured handles.
.PARAMETER AllowQuarantine
Permit partial restoration with original components still in their admitted quarantine.
#>
function Assert-AtlasoTestVmRestoredDirectory {
    param([psobject]$Context, [switch]$AllowReset, [switch]$AllowQuarantine)
    $record=Read-AtlasoTestVmSealedRecord -Context $Context -Path $Context.RestoredDirectoryReceiptPath -Sha256 $Context.RestoredDirectoryReceiptSha256 -Phase 'restored-data-created'
    $vm=Read-AtlasoTestVmSealedRecord -Context $Context -Path $record.original_receipt_path -Sha256 $record.original_receipt_sha256 -Phase 'original-clone-created'
    $intent=Read-AtlasoTestVmSealedRecord -Context $Context -Path $vm.intent_path -Sha256 $vm.intent_sha256 -Phase 'clone-pending'
    if($intent.source_commit -cne $vm.source_commit){throw 'Restored directory original intent changed.'}
    $proof=Read-AtlasoTestVmSealedRecord -Context $Context -Path $record.marker_receipt_path -Sha256 $record.marker_receipt_sha256 -Phase 'ca-marker-original'
    $projection=$proof.marker_projection | ConvertFrom-Json
    if ($record.path -cne $Context.OutputDirectory -or $proof.original_receipt_path -cne $record.original_receipt_path -or
        $proof.original_receipt_sha256 -cne $record.original_receipt_sha256 -or
        $proof.original_directory_identity -cne $vm.original_identities.directory -or
        (@($projection.DataDisks) | ConvertTo-Json -Depth 5 -Compress) -cne (@($record.disks) | ConvertTo-Json -Depth 5 -Compress)) { throw 'Restored directory original binding changed.' }
    $borrowed=$Context.PSObject.Properties['RestoredOutputPin'] -and $Context.RestoredOutputPin
    $pin=if ($borrowed) { $Context.RestoredOutputPin } else {
        $native=[Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([string]$Context.OutputDirectory,$true)
        $holder=[pscustomobject]@{Native=$native;Path=$Context.OutputDirectory;Identity=$record.original_identity;Disposed=$false;FilePins=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)}
        $holder | Add-Member ScriptMethod ReleaseFiles {foreach($held in $this.FilePins.Values){$held.Dispose()};$this.FilePins.Clear()}
        $holder | Add-Member ScriptMethod Dispose { $this.ReleaseFiles();$this.Native.Dispose();$this.Disposed=$true }
        $holder | Add-Member ScriptMethod GetRetainedCreatedIdentity {param($path)
            if ($this.Disposed -or $path -cne $this.Path -or [Atlaso.WorkstationFileIdentity]::Get($path) -cne $this.Identity) {throw 'Original restored root pin changed.'};return $this.Identity }
        $holder
    }
    try {
        if ($pin.GetRetainedCreatedIdentity([string]$Context.OutputDirectory) -cne $record.original_identity -or
            (Test-Path -LiteralPath $Context.VmxPath)) { throw 'Restored directory was replaced or acquired a VMX.' }
        $files=@(Get-ChildItem -LiteralPath $Context.OutputDirectory -File -Recurse -Force)
        if (@(Get-ChildItem -LiteralPath $Context.OutputDirectory -Directory -Force).Count) {throw 'Restored root contains unproven directories.'}
        if ($AllowReset -and $files.Count) { throw 'Reset restored root contains unexpected files.' }
        foreach ($file in $files) {
            $disk=@($record.disks | Where-Object { $_.Path -ceq $file.FullName })
            if ($disk.Count -ne 1 -or [Atlaso.WorkstationFileIdentity]::Get($file.FullName) -cne $disk[0].Identity) { throw 'Restored directory contains an unproven file.' }
            if (-not $pin.FilePins.ContainsKey($file.FullName)) {$pin.FilePins.Add($file.FullName,[Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($file.FullName,$true))}
            if([Atlaso.WorkstationFileIdentity]::Get($file.FullName) -cne $disk[0].Identity){throw 'Restored disk changed while its admission pin was acquired.'}
        }
        if (-not $AllowReset) { foreach ($disk in $record.disks) {
            if (Test-Path -LiteralPath $disk.Path -PathType Leaf) {continue}
            $quarantine=Join-Path $projection.QuarantineDirectory $disk.RelativePath
            if (-not $AllowQuarantine -or [Atlaso.WorkstationFileIdentity]::Get($quarantine) -cne $disk.Identity) { throw 'Original restored disk is missing.' }
        } }
        $Context | Add-Member RestoredOutputPin $pin -Force
        $Context | Add-Member PreparedOutputIdentity $record.original_identity -Force
        $Context | Add-Member RestoredDataReset ([bool]$AllowReset) -Force
        return $record
    }
    catch { if (-not $borrowed) {$pin.Dispose()};throw }
}

<#
.SYNOPSIS
Serialize immutable marker identity and preserved data bindings.
.PARAMETER Marker
Creation payload or validated marker, excluding mutable phase.
#>
function Get-AtlasoTestVmMarkerProjection {
    param([psobject]$Marker)
    if ($Marker.PSObject.Properties['OriginalProjection']) { return [string]$Marker.OriginalProjection }
    return ([ordered]@{Name=$Marker.Name; VmxPath=$Marker.VmxPath; OutputDirectory=$Marker.OutputDirectory;
        QuarantineDirectory=$Marker.QuarantineDirectory; CleanupIdentityHash=$Marker.CleanupIdentityHash;
        DataDisks=@($Marker.DataDisks)} | ConvertTo-Json -Depth 6 -Compress)
}

<#
.SYNOPSIS
Validate cloned payload disks alongside only the originally restored data components.
.PARAMETER Context
Owned clone context retaining the restored root and original disk admission pins.
.PARAMETER VmxPath
Fresh original-receipted clone whose two payload roles must remain valid.
#>
function Assert-AtlasoTestVmRestoredClonePayload {
    param([psobject]$Context, [string]$VmxPath)
    $record=Read-AtlasoTestVmSealedRecord -Context $Context -Path $Context.RestoredDirectoryReceiptPath -Sha256 $Context.RestoredDirectoryReceiptSha256 -Phase 'restored-data-created'
    $fresh=Assert-AtlasoTestVmOriginalOwnership -Context $Context
    if ($VmxPath -cne $Context.VmxPath -or $fresh.Record.original_identities.directory -cne $record.original_identity -or
        $fresh.Record.restored_directory.path -cne $Context.RestoredDirectoryReceiptPath -or
        $fresh.Record.restored_directory.sha256 -cne $Context.RestoredDirectoryReceiptSha256 -or
        -not $Context.CloneOutputPin -or $Context.CloneOutputPin.GetRetainedCreatedIdentity($Context.OutputDirectory) -cne $record.original_identity) {
        throw 'Cloned payload does not retain its original restored root binding.'
    }
    $layout=@(Get-AtlasoVmwarePayloadLayout -VmxPath $VmxPath)
    $expected=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($payload in $layout){$null=$expected.Add($payload.File.FullName)}
    foreach($disk in $record.disks){
        if($Context.RestoredDataReset){continue}
        if([Atlaso.WorkstationFileIdentity]::Get($disk.Path) -cne $disk.Identity -or -not $expected.Add($disk.Path)) {
            throw 'Restored data component changed or overlaps a cloned payload.'
        }
    }
    $actual=@(Get-ChildItem -LiteralPath $Context.OutputDirectory -Filter '*.vmdk' -File -Force)
    if($actual.Count -ne $expected.Count -or @($actual | Where-Object {-not $expected.Contains($_.FullName)}).Count){
        throw 'Cloned output contains unproven VMDK components.'
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
    if (-not $Context.ReceiptPath -or [string]$Context.ReceiptSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Existing VM admission requires the receipt path and creation-time digest preserved in the task inventory.'
    }
    $recordedReceiptPath = [System.IO.Path]::GetFullPath([string]$Context.ReceiptPath)
    $receiptRootPrefix = [System.IO.Path]::GetFullPath([string]$Context.EvidenceDirectory).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if (-not $recordedReceiptPath.StartsWith($receiptRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'The recorded original receipt is outside the durable ownership scope.'
    }
    if (-not (Test-Path -LiteralPath $Context.OutputDirectory -PathType Container) -or
        -not (Test-Path -LiteralPath $Context.VmxPath -PathType Leaf)) {
        throw 'Existing test-VM ownership can be verified only for the exact existing output directory and VMX.'
    }
    $directoryIdentity = [Atlaso.WorkstationFileIdentity]::Get([string]$Context.OutputDirectory)
    $cleanupIdentity = Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath ([string]$Context.VmxPath)
    $cleanupIdentityHash = Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value $cleanupIdentity
    $matchingPathRecords = [System.Collections.Generic.List[object]]::new()
    $matchingIdentityRecords = [System.Collections.Generic.List[object]]::new()
    $evidencePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath(
        [System.IO.Path]::GetDirectoryName($recordedReceiptPath), $true)
    try {
        foreach ($file in @(Get-Item -LiteralPath $recordedReceiptPath -ErrorAction Stop)) {
            $filePin = $null
            try {
            if ($file.Length -gt 65536) { continue }
            $filePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($file.FullName, $true)
            if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                [string]$Context.ReceiptSha256) {
                throw 'The original receipt differs from its preserved creation-time digest.'
            }
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
        if ($sha256 -cne [string]$Context.ReceiptSha256) {
            throw 'The original receipt changed after its creation-time digest was verified.'
        }
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
