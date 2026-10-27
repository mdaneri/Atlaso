<#
.SYNOPSIS
Test receipt-bound admission for the external installation ISO VM root.
.DESCRIPTION
Extracts pure ownership validators from the production module and exercises them
with in-memory public records. It does not create roots, receipts, or VMs.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$ownershipPath = Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.TestVmOwnership.ps1'
$tokens = $null
$parseErrors = $null
$ownershipAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $ownershipPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count) {
    throw "Validation-root ownership module has PowerShell parse errors: $($parseErrors[0].Message)"
}

<#
.SYNOPSIS
Return one named function from the parsed ownership module.
.PARAMETER SourceAst
Parsed PowerShell source AST containing the function.
.PARAMETER Name
Exact function name to extract.
#>
function Get-ValidationRootFunctionText {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.Language.Ast]$SourceAst,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $definitions = @($SourceAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
        }, $true))
    if ($definitions.Count -ne 1) { throw "Expected one function definition: $Name" }
    return $definitions[0].Extent.Text
}

<#
.SYNOPSIS
Fail a focused ownership contract assertion.
.PARAMETER Condition
Whether the asserted condition passed.
.PARAMETER Message
Failure description.
#>
function Assert-ValidationRootCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) { throw $Message }
}

$functionNames = @(
    'Test-AtlasoTestVmStrictDescendantPath',
    'Test-AtlasoTestVmCanonicalInstallationIsoName',
    'Assert-AtlasoTestVmValidationRootSelector',
    'Assert-AtlasoTestVmValidationRootReceiptRecord',
    'Read-AtlasoTestVmValidationRootReceiptEnvelope',
    'Read-AtlasoTestVmValidationRootReceipt',
    'ConvertTo-AtlasoTestVmValidationRootAdmission',
    'Assert-AtlasoTestVmValidationRootRecordBinding',
    'Assert-AtlasoTestVmValidationRootBinding'
)
foreach ($name in $functionNames) {
    . ([scriptblock]::Create((Get-ValidationRootFunctionText -SourceAst $ownershipAst -Name $name)))
}
Import-Module (Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.VmwareTestIdentity.psm1') -Force
Import-Module (Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationCleanup.psm1') -Force

$readerDefinition = @($ownershipAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Read-AtlasoTestVmValidationRootReceipt'
    }, $true))[0]
# Exercise the production reader's imported command boundary. A module's private
# helpers are unavailable here even when pure-validator tests can extract them.
$readerCommands = @($readerDefinition.Body.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { $_.GetCommandName() } | Sort-Object -Unique)
foreach ($commandName in $readerCommands) {
    if ($commandName -and -not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
        throw "Production validation-root reader dependency is unavailable after its normal imports: $commandName"
    }
}
$pinAssignments = @($readerDefinition.Body.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -ceq 'pins' -and
        $node.Right.Extent.Text.Contains('ReadOnlySourcePins')
    }, $true))
if ($pinAssignments.Count -ne 1) { throw 'Expected one production read-only source-pin constructor in the receipt reader.' }
$pinConstructor = [scriptblock]::Create('$pins = ' + $pinAssignments[0].Right.Extent.Text)
. $pinConstructor
Assert-ValidationRootCondition ($pins -is [IDisposable]) `
    'The production receipt reader must construct the existing native read-only source pin collection.'
$pins.Dispose()

$script:ValidationRootGitExitCode = 0
<#
.SYNOPSIS
Return the controlled source-ancestry status without invoking Git.
#>
function git {
    $global:LASTEXITCODE = $script:ValidationRootGitExitCode
}

$worktree = 'E:\.codex\worktree\issue542-offline-iso\Atlaso'
$evidence = 'E:\.codex\worktree\.evidence\issue542-01a1694b'
$rootPath = 'C:\AtlasoBuilds\issue542\vm-validation'
$vmName = 'Atlaso-PR-1036-installation-iso-inspection-a'
$output = [IO.Path]::Combine($rootPath, $vmName)
$sourceCommit = 'b' * 40
$rootSourceCommit = 'a' * 40
$rootIdentity = '12345678:1234567890ABCDEF'
$receiptPath = [IO.Path]::Combine($evidence, 'installation-validation-root.json')
$receiptSha256 = 'd' * 64
$context = [pscustomobject]@{
    TaskId = 'task-542'
    Repository = 'mdaneri/Atlaso'
    Worktree = $worktree
    WorktreeDirectoryId = 'ABCDEF12:1234567890ABCDEF'
    PermittedRoot = 'E:\.codex\worktree'
    Branch = 'enhancement/542-offline-iso'
    SourceCommit = $sourceCommit
    PullRequestNumber = 1036
    LocalBuilder = $false
    Name = $vmName
    EvidenceDirectory = $evidence
    EvidenceDirectoryId = 'ABCDEF12:1234567890ABCDE0'
    OutputDirectory = $output
}

# These are in-memory Windows paths; their drives need not exist on a CI host.
$legacyOutput = [IO.Path]::Combine($worktree, 'test-results\Atlaso-PR-1036-installation-iso-legacy')
$legacy = Assert-AtlasoTestVmValidationRootSelector -Worktree $worktree `
    -OutputDirectory $legacyOutput -Name 'Atlaso-PR-1036-test-vm' `
    -SourceCommit $sourceCommit -PullRequestNumber 1036 -LocalBuilder:$false
Assert-ValidationRootCondition (-not $legacy) 'Legacy task-worktree output must not require an external-root receipt.'
Assert-ValidationRootCondition (Test-AtlasoTestVmStrictDescendantPath -ParentPath $worktree -ChildPath $legacyOutput) `
    'The legacy fixture must remain beneath its task checkout.'

foreach ($missing in @(
        @{ ReceiptPath = $receiptPath; ReceiptSha256 = '' },
        @{ ReceiptPath = ''; ReceiptSha256 = $receiptSha256 }
    )) {
    $rejected = $false
    try {
        $null = Assert-AtlasoTestVmValidationRootSelector -Worktree $worktree -OutputDirectory $output `
            -Name $vmName -SourceCommit $sourceCommit -PullRequestNumber 1036 -LocalBuilder:$false `
            -ReceiptPath $missing.ReceiptPath -ReceiptSha256 $missing.ReceiptSha256
    }
    catch { $rejected = $true }
    Assert-ValidationRootCondition $rejected 'External-root receipt selectors must be supplied as a pair.'
}

$externalSelected = Assert-AtlasoTestVmValidationRootSelector -Worktree $worktree `
    -OutputDirectory $output -Name $vmName -SourceCommit $sourceCommit `
    -PullRequestNumber 1036 -LocalBuilder:$false -ReceiptPath $receiptPath -ReceiptSha256 $receiptSha256
Assert-ValidationRootCondition $externalSelected 'A canonical installation VM with paired original selectors should be admitted for receipt validation.'

foreach ($invalidName in @(
        'Atlaso-PR-1036-test-vm',
        'Atlaso-PR-1037-installation-iso-other',
        'Atlaso-PR-1036-installation-iso-Bad_Suffix',
        ('Atlaso-PR-1036-installation-iso-' + ('a' * 33))
    )) {
    $rejected = $false
    try {
        $null = Assert-AtlasoTestVmValidationRootSelector -Worktree $worktree -OutputDirectory $output `
            -Name $invalidName -SourceCommit $sourceCommit -PullRequestNumber 1036 -LocalBuilder:$false `
            -ReceiptPath $receiptPath -ReceiptSha256 $receiptSha256
    }
    catch { $rejected = $true }
    Assert-ValidationRootCondition $rejected 'External-root admission must reject noncanonical or differently owned VM names.'
}

$record = [pscustomobject]@{
    schema = 1
    phase = 'installation-validation-root-created'
    kind = 'artifact'
    task_id = $context.TaskId
    repository = $context.Repository
    source_branch = $context.Branch
    source_commit = $rootSourceCommit
    worktree = $context.Worktree
    worktree_directory_identity = $context.WorktreeDirectoryId
    pull_request_number = $context.PullRequestNumber
    local_builder = $context.LocalBuilder
    path = $rootPath
    directory_identity = $rootIdentity
    created_utc = '2026-10-27T09:00:00.0000000+00:00'
    cleanup_tool = 'Remove-AtlasoWorkstationArtifactRoot -ExpectedRemovalRoot <exact originally recorded path>'
}
$validRecord = Assert-AtlasoTestVmValidationRootReceiptRecord -Context $context -Record $record `
    -ReceiptPath $receiptPath -ReceiptSha256 $receiptSha256 -ObservedRootIdentity $rootIdentity
Assert-ValidationRootCondition ($validRecord.Path -ceq $rootPath -and $validRecord.DirectoryIdentity -ceq $rootIdentity) `
    'The valid root receipt must preserve its exact path and native identity.'

$mutations = @(
    @{ Name = 'task'; Change = { param($candidate) $candidate.task_id = 'other-task' } },
    @{ Name = 'repository'; Change = { param($candidate) $candidate.repository = 'other/repository' } },
    @{ Name = 'worktree'; Change = { param($candidate) $candidate.worktree = 'E:\other\Atlaso' } },
    @{ Name = 'worktree-identity'; Change = { param($candidate) $candidate.worktree_directory_identity = '11111111:1111111111111111' } },
    @{ Name = 'branch'; Change = { param($candidate) $candidate.source_branch = 'other-branch' } },
    @{ Name = 'kind'; Change = { param($candidate) $candidate.kind = 'other' } },
    @{ Name = 'phase'; Change = { param($candidate) $candidate.phase = 'vm-created' } },
    @{ Name = 'PR'; Change = { param($candidate) $candidate.pull_request_number = 1037 } },
    @{ Name = 'directory-identity'; Change = { param($candidate) $candidate.directory_identity = '11111111:1111111111111111' } },
    @{ Name = 'non-UTC-timestamp'; Change = { param($candidate) $candidate.created_utc = '2026-10-27T09:00:00.0000000-07:00' } },
    @{ Name = 'path-root'; Change = { param($candidate) $candidate.path = 'C:\' } },
    @{ Name = 'path-worktree-overlap'; Change = { param($candidate) $candidate.path = $worktree } },
    @{ Name = 'path-evidence-overlap'; Change = { param($candidate) $candidate.path = $evidence } },
    @{ Name = 'cleanup'; Change = { param($candidate) $candidate.cleanup_tool = 'Remove-Item -Recurse' } },
    @{ Name = 'unexpected-field'; Change = { param($candidate) $candidate | Add-Member -NotePropertyName extra -NotePropertyValue 'unreviewed' } }
)
foreach ($mutation in $mutations) {
    $candidate = $record.PSObject.Copy()
    & $mutation.Change $candidate
    $rejected = $false
    try {
        $null = Assert-AtlasoTestVmValidationRootReceiptRecord -Context $context -Record $candidate `
            -ReceiptPath $receiptPath -ReceiptSha256 $receiptSha256 -ObservedRootIdentity $rootIdentity
    }
    catch { $rejected = $true }
    Assert-ValidationRootCondition $rejected "Validation-root receipt mutation was accepted: $($mutation.Name)"
}

$script:ValidationRootGitExitCode = 1
$rejectedAncestry = $false
try {
    $null = Assert-AtlasoTestVmValidationRootReceiptRecord -Context $context -Record $record `
        -ReceiptPath $receiptPath -ReceiptSha256 $receiptSha256 -ObservedRootIdentity $rootIdentity
}
catch { $rejectedAncestry = $true }
finally { $script:ValidationRootGitExitCode = 0 }
Assert-ValidationRootCondition $rejectedAncestry 'A root receipt from an unrelated source history must be rejected.'

$siblingContext = $context.PSObject.Copy()
$siblingContext.OutputDirectory = [IO.Path]::Combine([IO.Path]::GetDirectoryName($rootPath), 'other-root-output')
$rejectedSibling = $false
try {
    $null = Assert-AtlasoTestVmValidationRootReceiptRecord -Context $siblingContext -Record $record `
        -ReceiptPath $receiptPath -ReceiptSha256 $receiptSha256 -ObservedRootIdentity $rootIdentity
}
catch { $rejectedSibling = $true }
Assert-ValidationRootCondition $rejectedSibling 'A VM output path outside the receipted root must be rejected.'

$validText = $record | ConvertTo-Json -Compress
$validBytes = [Text.UTF8Encoding]::new($false).GetBytes($validText)
$validDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($validBytes)).ToLowerInvariant()
$parsedRecord = Read-AtlasoTestVmValidationRootReceiptEnvelope -Text $validText `
    -ExpectedSha256 $validDigest -ObservedSha256 $validDigest -Length $validBytes.Length
Assert-ValidationRootCondition ($parsedRecord.created_utc -is [string] -and
    $parsedRecord.created_utc -ceq $record.created_utc) `
    'Receipt parsing must preserve the exact UTC string instead of a host-local DateTime.'
$previousWhatIf = $WhatIfPreference
try {
    $WhatIfPreference = $true
    $null = Assert-AtlasoTestVmValidationRootReceiptRecord -Context $context -Record $parsedRecord `
        -ReceiptPath $receiptPath -ReceiptSha256 $receiptSha256 -ObservedRootIdentity $rootIdentity
}
finally { $WhatIfPreference = $previousWhatIf }
$tampered = $false
$tamperedText = $validText + ' '
$tamperedBytes = [Text.UTF8Encoding]::new($false).GetBytes($tamperedText)
$tamperedDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($tamperedBytes)).ToLowerInvariant()
try {
    $null = Read-AtlasoTestVmValidationRootReceiptEnvelope -Text $tamperedText `
        -ExpectedSha256 $validDigest -ObservedSha256 $tamperedDigest -Length $tamperedBytes.Length
}
catch { $tampered = $true }
Assert-ValidationRootCondition $tampered 'Changed receipt bytes must fail the original digest check.'

$pins = [IO.MemoryStream]::new()
$admission = ConvertTo-AtlasoTestVmValidationRootAdmission -RootPath $rootPath `
    -DirectoryIdentity $rootIdentity -ReceiptPath $receiptPath -ReceiptSha256 $receiptSha256 `
    -SourceCommit $rootSourceCommit -Pins $pins
$admissionContext = $context.PSObject.Copy()
$admissionContext | Add-Member -NotePropertyName ValidationRootAdmission -NotePropertyValue $admission
$binding = [ordered]@{
    path = $rootPath
    directory_identity = $rootIdentity
    receipt_path = $receiptPath
    receipt_sha256 = $receiptSha256
}
$vmRecord = [pscustomobject]@{ validation_root = $binding }
Assert-AtlasoTestVmValidationRootRecordBinding -Context $admissionContext -Record $vmRecord
$previousWhatIf = $WhatIfPreference
try {
    $WhatIfPreference = $true
    Assert-AtlasoTestVmValidationRootRecordBinding -Context $admissionContext `
        -Record ([pscustomobject]@{ validation_root = [pscustomobject]$binding })
}
finally { $WhatIfPreference = $previousWhatIf }
foreach ($field in @('path', 'directory_identity', 'receipt_path', 'receipt_sha256')) {
    $candidateBinding = [ordered]@{
        path = $rootPath
        directory_identity = $rootIdentity
        receipt_path = $receiptPath
        receipt_sha256 = $receiptSha256
    }
    $candidateBinding[$field] = 'changed'
    $rejected = $false
    try {
        Assert-AtlasoTestVmValidationRootRecordBinding -Context $admissionContext `
            -Record ([pscustomobject]@{ validation_root = $candidateBinding })
    }
    catch { $rejected = $true }
    Assert-ValidationRootCondition $rejected "VM receipt root binding accepted changed field $field."
}
$extraBinding = [ordered]@{}
foreach ($field in $binding.Keys) { $extraBinding[$field] = $binding[$field] }
$extraBinding['extra'] = 'unreviewed'
$rejected = $false
try {
    Assert-AtlasoTestVmValidationRootRecordBinding -Context $admissionContext `
        -Record ([pscustomobject]@{ validation_root = $extraBinding })
}
catch { $rejected = $true }
Assert-ValidationRootCondition $rejected 'VM receipt root binding must have exactly its four admitted fields.'

$ordinaryContext = [pscustomobject]@{ ValidationRootAdmission = $null }
Assert-AtlasoTestVmValidationRootBinding -Context $ordinaryContext -Record ([pscustomobject]@{ phase = 'legacy' })
$ordinaryRootClaimRejected = $false
try {
    Assert-AtlasoTestVmValidationRootBinding -Context $ordinaryContext `
        -Record ([pscustomobject]@{ validation_root = $binding })
}
catch { $ordinaryRootClaimRejected = $true }
Assert-ValidationRootCondition $ordinaryRootClaimRejected 'Legacy task-worktree VM records cannot claim an external validation root.'

$bindingValidatorText = Get-ValidationRootFunctionText -SourceAst $ownershipAst -Name 'Assert-AtlasoTestVmValidationRootBinding'
Assert-ValidationRootCondition ($bindingValidatorText.Contains('ValidationRootAdmission') -and
    $bindingValidatorText.Contains('.Disposed') -and
    $bindingValidatorText.Contains('WorkstationFileIdentity]::Get')) `
    'External VM binding validation must reject disposed roots and recheck the pinned native directory identity.'

$contextText = Get-ValidationRootFunctionText -SourceAst $ownershipAst -Name 'New-AtlasoTestVmOwnershipContext'
Assert-ValidationRootCondition ($contextText.Contains('External validation-root selectors require an enabled, receipt-backed task ownership context.') -and
    $contextText.Contains('ValidationRootAdmission = $validationRootAdmission')) `
    'Root selectors must require enabled ownership and the admitted pin must be retained in the returned context.'
$originalTaskId = $env:CODEX_THREAD_ID
try {
    Remove-Item Env:CODEX_THREAD_ID -ErrorAction SilentlyContinue
    . ([scriptblock]::Create($contextText))
    $disabledContextRejected = $false
    try {
        $null = New-AtlasoTestVmOwnershipContext -Worktree $worktree -OutputDirectory $output `
            -VmxPath ([IO.Path]::Combine($output, "$vmName.vmx")) -Name $vmName `
            -ValidationRootReceiptPath $receiptPath -ValidationRootReceiptSha256 $receiptSha256
    }
    catch { $disabledContextRejected = $_.Exception.Message.Contains('enabled, receipt-backed task ownership context') }
    Assert-ValidationRootCondition $disabledContextRejected `
        'External root selectors must fail before a disabled human context can return.'
}
finally {
    if ($null -eq $originalTaskId) { Remove-Item Env:CODEX_THREAD_ID -ErrorAction SilentlyContinue }
    else { $env:CODEX_THREAD_ID = $originalTaskId }
}

$admission.Dispose()
Assert-ValidationRootCondition (-not $pins.CanRead -and $admission.Disposed) `
    'Disposing the retained validation-root admission must release its original pins.'
$admission.Dispose()

$readerText = Get-ValidationRootFunctionText -SourceAst $ownershipAst -Name 'Read-AtlasoTestVmValidationRootReceipt'
Assert-ValidationRootCondition ($readerText.Contains('PinOrdinaryDirectoryPath($evidencePath, $true)') -and
    $readerText.Contains('PinOrdinaryReadFile($receipt, $true)') -and
    $readerText.Contains('PinOrdinaryDirectoryPath($rootPath, $true)')) `
    'External root admission must retain no-reparse evidence, receipt, and root pins.'

Write-Output 'Installation validation-root ownership checks passed.'
