<#
.SYNOPSIS
Exercise admitted Git source export and built-wheel pinning on owned Windows files.
.DESCRIPTION
Uses an immutable commit already present in the task repository, verifies exported bytes,
and checks write, rename, source-change, and wheel identity guards. All generated data stays
under the supplied fresh StateRoot. The durable resource receipt is published outside it.
.PARAMETER StateRoot
Fresh absolute child directory of this task's already receipted validation-output root.
.PARAMETER ResourceReceiptPath
Fresh absolute durable receipt path directly beneath the task evidence root, outside StateRoot.
.PARAMETER CreationReceiptPath
Original creation receipt for this task's existing validation-output directory.
.PARAMETER CreationReceiptSha256
Independently retained SHA-256 of that original validation-root receipt.
.PARAMETER TaskId
Exact task identity bound to the original validation-root receipt.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StateRoot,
    [Parameter(Mandatory)][string]$ResourceReceiptPath,
    [Parameter(Mandatory)][string]$CreationReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$CreationReceiptSha256,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_-]{1,128}$')][string]$TaskId
)

$ErrorActionPreference = 'Stop'
$evidenceRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ResourceReceiptPath))
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$fixtureWheelModulePath = Join-Path $repositoryRoot 'scripts/windows/vmware/Atlaso.FixtureWheel.psm1'
$cleanupModulePath = Join-Path $repositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1'
$relativeProofPath = 'scripts/windows/vmware/run-lifecycle-test.ps1'

Import-Module $cleanupModulePath -Force
Import-Module $fixtureWheelModulePath -Force

<#
.SYNOPSIS
Refuse a path containing reparse points or Win32 aliases.
.PARAMETER Path
Absolute path to validate.
.PARAMETER AllowMissingLeaf
Allow only the final path component to be absent.
#>
function Assert-OrdinaryFixturePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowMissingLeaf
    )
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or $Path.StartsWith('\\?\') -or
        $Path.StartsWith('\\.\') -or $Path -match '(^|[\\/])\.\.?([\\/]|$)' -or
        $Path -match '[. ]([\\/]|$)') {
        throw 'Fixture test paths must be ordinary absolute paths.'
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $cursor = $full
    if ($AllowMissingLeaf -and -not (Test-Path -LiteralPath $cursor)) {
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Fixture test path contains a reparse point.'
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if (-not $parent -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
}

<#
.SYNOPSIS
Read an existing Git object without using the working-tree file.
.PARAMETER RepositoryRoot
Task repository containing the immutable object.
.PARAMETER Commit
Full commit SHA that identifies the Git object.
.PARAMETER Path
Repository-relative file path to read.
#>
function Read-GitObjectByteArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
        [Parameter(Mandatory)][string]$Path
    )
    $process = [Diagnostics.Process]::new()
    $process.StartInfo.FileName = (Get-Command git -ErrorAction Stop).Source
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    foreach ($argument in @('-C', $RepositoryRoot, 'show', "$Commit`:$Path")) {
        $process.StartInfo.ArgumentList.Add($argument)
    }
    $memory = [IO.MemoryStream]::new()
    try {
        if (-not $process.Start()) { throw 'Could not read the selected Git object.' }
        $errorTask = $process.StandardError.ReadToEndAsync()
        $process.StandardOutput.BaseStream.CopyTo($memory)
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            $null = $errorTask.GetAwaiter().GetResult()
            throw 'The selected Git object is unavailable.'
        }
        return ,$memory.ToArray()
    } finally {
        $memory.Dispose()
        $process.Dispose()
    }
}

<#
.SYNOPSIS
Require an operation to fail while preserving the tested object.
.PARAMETER Action
Operation expected to be refused.
.PARAMETER Description
Bounded failure description when the operation unexpectedly succeeds.
.PARAMETER Pattern
Expected refusal text to reject unrelated failures.
#>
function Assert-Refused {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Pattern
    )
    $refused = $false
    try { & $Action | Out-Null }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        $refused = $true
    }
    if (-not $refused) { throw "Expected refusal: $Description" }
}

<#
.SYNOPSIS
Require a pinned file to refuse replacement while restoring bytes if it does not.
.PARAMETER Path
Owned file expected to remain pinned.
.PARAMETER OriginalBytes
Exact original bytes used to restore an unexpected write.
.PARAMETER ReplacementBytes
Different bytes offered by the write probe.
#>
function Assert-FileWriteRefused {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$OriginalBytes,
        [Parameter(Mandatory)][byte[]]$ReplacementBytes
    )
    $writeSucceeded = $false
    $writeRefusalObserved = $false
    try {
        [IO.File]::WriteAllBytes($Path, $ReplacementBytes)
        $writeSucceeded = $true
    } catch { $writeRefusalObserved = $true }
    $afterBytes = [IO.File]::ReadAllBytes($Path)
    $unchanged = [Convert]::ToBase64String($afterBytes) -ceq [Convert]::ToBase64String($OriginalBytes)
    if (-not $unchanged) {
        [IO.File]::WriteAllBytes($Path, $OriginalBytes)
        $restored = [IO.File]::ReadAllBytes($Path)
        if ([Convert]::ToBase64String($restored) -cne [Convert]::ToBase64String($OriginalBytes)) {
            throw 'Unexpected pinned-file write could not be restored exactly.'
        }
        throw 'Pinned file accepted a write and was restored for diagnosis.'
    }
    if ($writeSucceeded) { throw 'Pinned file accepted a no-op write.' }
    if (-not $writeRefusalObserved) { throw 'Pinned file write probe did not produce a refusal.' }
}

<#
.SYNOPSIS
Require an owned directory to reject rename and restore it if the guard regresses.
.PARAMETER Path
Directory pinned by the exporter.
.PARAMETER Description
Bounded failure description.
#>
function Assert-DirectoryRenameRefused {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )
    $moved = "$Path.fixture-wheel-rename-probe"
    $renamed = $false
    $renameRefused = $false
    try {
        [IO.Directory]::Move($Path, $moved)
        $renamed = $true
    } catch { $renameRefused = $true }
    if ($renamed) {
        try { [IO.Directory]::Move($moved, $Path) }
        catch { throw "Unexpected rename succeeded and restoration failed: $Description" }
        throw "Expected refusal: $Description"
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Refused rename did not preserve the original directory: $Description"
    }
    if (-not $renameRefused) { throw "Directory rename probe did not produce a refusal: $Description" }
}

<#
.SYNOPSIS
Require a wheel build result to be rejected and release any pins it acquired.
.PARAMETER OutputRoot
Owned wheel output directory.
.PARAMETER BuildOutput
Synthetic build result line to validate.
.PARAMETER Description
Bounded refusal description.
.PARAMETER Pattern
Expected wheel refusal text.
#>
function Assert-WheelRefused {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][string[]]$BuildOutput,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string]$Pattern
    )
    $pins = [Collections.Generic.List[IDisposable]]::new()
    $refused = $false
    try {
        try { Get-LifecycleBuiltWheel -OutputRoot $OutputRoot -BuildOutput $BuildOutput -ConsumerPins $pins | Out-Null }
        catch {
            if ($_.Exception.Message -notmatch $Pattern) { throw }
            $refused = $true
        }
        if (-not $refused) { throw "Expected refusal: $Description" }
    } finally {
        for ($i = $pins.Count - 1; $i -ge 0; $i--) { $pins[$i].Dispose() }
    }
}

<#
.SYNOPSIS
Return the active configured Codex worktree root.
.PARAMETER ConfigPath
Active Codex TOML configuration.
#>
function Get-ConfiguredWorktreeRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConfigPath)
    $lines = [IO.File]::ReadAllLines($ConfigPath)
    $inDesktop = $false
    $values = [Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        if ($line -match '^\s*\[([^\]]+)\]\s*(?:#.*)?$') {
            $inDesktop = $Matches[1] -ceq 'desktop'
            continue
        }
        if ($inDesktop -and $line -match '^\s*git-worktree-root\s*=\s*(?:''([^'']+)''|"([^"\\]+)")\s*(?:#.*)?$') {
            $values.Add($(if ($Matches[1]) { $Matches[1] } else { $Matches[2] }))
        }
    }
    if ($values.Count -ne 1) { throw 'Active Codex configuration must define exactly one desktop.git-worktree-root.' }
    return [IO.Path]::GetFullPath($values[0]).TrimEnd([IO.Path]::DirectorySeparatorChar)
}

if (-not [IO.Path]::IsPathFullyQualified($StateRoot) -or
    -not [IO.Path]::IsPathFullyQualified($ResourceReceiptPath)) {
    throw 'StateRoot and ResourceReceiptPath must be absolute.'
}
$StateRoot = [IO.Path]::GetFullPath($StateRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$ResourceReceiptPath = [IO.Path]::GetFullPath($ResourceReceiptPath)
Assert-OrdinaryFixturePath -Path $repositoryRoot
Assert-OrdinaryFixturePath -Path $fixtureWheelModulePath
Assert-OrdinaryFixturePath -Path $evidenceRoot
Assert-OrdinaryFixturePath -Path $creationReceiptPath
Assert-OrdinaryFixturePath -Path $StateRoot -AllowMissingLeaf
Assert-OrdinaryFixturePath -Path $ResourceReceiptPath -AllowMissingLeaf

$userProfilePath = [Environment]::GetFolderPath('UserProfile')
$codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $userProfilePath '.codex' }
$configPath = Join-Path $codexHome 'config.toml'
Assert-OrdinaryFixturePath -Path $configPath
$configuredRoot = Get-ConfiguredWorktreeRoot -ConfigPath $configPath
if (-not [IO.Path]::GetFullPath($repositoryRoot).StartsWith($configuredRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Task repository is outside the configured Codex worktree root.'
}
Assert-AtlasoStrictDescendantPath -ParentPath $configuredRoot -ChildPath $repositoryRoot `
    -FailureMessage 'Task repository containment check failed'
Assert-AtlasoStrictDescendantPath -ParentPath $configuredRoot -ChildPath $evidenceRoot `
    -FailureMessage 'Task evidence containment check failed'
if ([IO.Path]::GetDirectoryName($StateRoot) -cne (Join-Path $repositoryRoot 'validation-output')) {
    throw 'StateRoot must be a direct child of the receipted validation-output root.'
}
if ([IO.Path]::GetDirectoryName($ResourceReceiptPath) -cne $evidenceRoot -or
    $ResourceReceiptPath.StartsWith($StateRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
    $ResourceReceiptPath -ceq $StateRoot) {
    throw 'ResourceReceiptPath must be a new direct child of the task evidence root, outside StateRoot.'
}
if ((Test-Path -LiteralPath $StateRoot) -or (Test-Path -LiteralPath $ResourceReceiptPath)) {
    throw 'StateRoot and ResourceReceiptPath must both be fresh.'
}

$creationReceipt = Get-Content -LiteralPath $creationReceiptPath -Raw | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $CreationReceiptPath -Algorithm SHA256).Hash -ine $CreationReceiptSha256) {
    throw 'Original validation-root receipt differs from its independently retained digest.'
}
if ($creationReceipt.kind -cne 'generated_tree' -or
    $creationReceipt.cleanup_tool -cne 'PytestGeneratedTree' -or
    $creationReceipt.task_id -cne $TaskId -or
    $creationReceipt.repository -cne 'mdaneri/Atlaso' -or
    $creationReceipt.path -cne (Join-Path $repositoryRoot 'validation-output')) {
    throw 'Original validation-output creation receipt does not match this task.'
}
$validationRoot = [IO.Path]::GetFullPath($creationReceipt.path)
Assert-AtlasoStrictDescendantPath -ParentPath $configuredRoot -ChildPath $validationRoot `
    -FailureMessage 'Original validation-output containment check failed'
$rootIdentity = Get-AtlasoPathIdentity -Path $validationRoot -Description 'Original validation-output root'
$identityParts = @($creationReceipt.root_identity)
if ($identityParts.Count -ne 3) { throw 'Original validation-output receipt identity is malformed.' }
$expectedIdentity = '{0:X8}:{1:X8}{2:X8}' -f [uint32]$identityParts[0], [uint32]$identityParts[1], [uint32]$identityParts[2]
if ($rootIdentity -cne $expectedIdentity) { throw 'Original validation-output identity differs from its durable receipt.' }

$headOutput = @(& git -C $repositoryRoot rev-parse --verify HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or $headOutput.Count -ne 1 -or $headOutput[0] -notmatch '^[0-9a-f]{40}$') {
    throw 'Could not bind the test to the current repository HEAD.'
}
$sourceCommit = $headOutput[0]
$moduleSha256 = (Get-FileHash -LiteralPath $fixtureWheelModulePath -Algorithm SHA256).Hash.ToLowerInvariant()
$creationReceiptSha256 = (Get-FileHash -LiteralPath $creationReceiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
$runnerPath = Join-Path $repositoryRoot 'scripts/windows/vmware/run-lifecycle-test.ps1'
$runnerTokens = $null
$runnerParseErrors = $null
$runnerAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $runnerPath, [ref]$runnerTokens, [ref]$runnerParseErrors
)
$sourceCommitFunction = $runnerAst.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-LifecycleSourceCommit'
}, $false)
if ($runnerParseErrors -or -not $sourceCommitFunction) { throw 'Cannot load the caller source-admission guard.' }
. ([scriptblock]::Create($sourceCommitFunction.Extent.Text))
$workingChanges = @(& git -C $repositoryRoot status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the current source worktree.' }
$callerCleanPrecheckRefused = $false
if ($workingChanges.Count -gt 0) {
    try { Get-LifecycleSourceCommit -RepositoryRoot $repositoryRoot | Out-Null }
    catch {
        if ($_.Exception.Message -notmatch 'clean source worktree') { throw }
        $callerCleanPrecheckRefused = $true
    }
    if (-not $callerCleanPrecheckRefused) { throw 'Caller clean-source guard accepted a dirty worktree.' }
}

$rootCreationCapture = [pscustomobject]@{ Identity = '' }
$resourceRootPins = [Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath(
    $StateRoot,
    [Action[string, string]]({
        param($createdPath, $createdIdentity)
        if ($createdPath -cne $StateRoot) { throw 'StateRoot creation returned an unexpected path.' }
        $rootCreationCapture.Identity = $createdIdentity
        $resourceReceipt = [ordered]@{
            schema = 1
            kind = 'atlaso_fixture_wheel_test'
            task_id = $TaskId
            repository = 'mdaneri/Atlaso'
            source_commit = $sourceCommit
            candidate_module_sha256 = $moduleSha256
            original_validation_root = $validationRoot
            original_validation_root_identity = $rootIdentity
            original_validation_creation_receipt_sha256 = $creationReceiptSha256
            state_root = $createdPath
            state_root_identity = $createdIdentity
            resource_receipt_path = $ResourceReceiptPath
            created_utc = [DateTime]::UtcNow.ToString('O')
        }
        $stagePath = "$ResourceReceiptPath.$([guid]::NewGuid().ToString('N')).stage"
        $stage = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($stagePath)
        try {
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($resourceReceipt | ConvertTo-Json -Depth 4))
            $stage.Write($bytes, 0, $bytes.Length)
            [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($stage, $ResourceReceiptPath, $false)
        } finally { $stage.Dispose() }
    }.GetNewClosure())
)
$observedRootIdentity = Get-AtlasoPathIdentity -Path $StateRoot -Description 'New fixture-wheel state root'
if ($observedRootIdentity -cne $rootCreationCapture.Identity) { throw 'StateRoot identity differs from its creation callback.' }
$stateRootIdentity = $rootCreationCapture.Identity
$publishedReceipt = Get-Content -LiteralPath $ResourceReceiptPath -Raw | ConvertFrom-Json
if ($publishedReceipt.kind -cne 'atlaso_fixture_wheel_test' -or
    $publishedReceipt.task_id -cne $TaskId -or
    $publishedReceipt.repository -cne 'mdaneri/Atlaso' -or
    $publishedReceipt.source_commit -cne $sourceCommit -or
    $publishedReceipt.candidate_module_sha256 -cne $moduleSha256 -or
    $publishedReceipt.state_root_identity -cne $stateRootIdentity) {
    throw 'Durable StateRoot receipt does not match the creation callback.'
}
$resourceRootPins.Dispose()
$resourceRootPins = $null

$sourceConsumerPins = [Collections.Generic.List[IDisposable]]::new()
$wheelPinGroups = [Collections.Generic.List[object]]::new()
$expectedSourceBytes = $null
$snapshotPath = $null
try {
    # Prepare ordinary synthetic wheel inputs before the exporter pins StateRoot ancestors.
    $wheelNames = @('valid', 'wrong-name', 'wrong-size', 'wrong-digest', 'extra-output')
    $wheelRoots = @{}
    foreach ($name in $wheelNames) {
        $wheelRoot = Join-Path $StateRoot "wheel-$name"
        [IO.Directory]::CreateDirectory($wheelRoot) | Out-Null
        $wheelRoots[$name] = $wheelRoot
    }
    $wheelBytes = [Text.Encoding]::UTF8.GetBytes('Atlaso fixture wheel identity test payload')
    $wheelName = 'atlaso-0.0.0-py3-none-any.whl'
    $wheelDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($wheelBytes)).ToLowerInvariant()
    foreach ($name in $wheelNames) {
        [IO.File]::WriteAllBytes((Join-Path $wheelRoots[$name] $wheelName), $wheelBytes)
    }
    [IO.File]::WriteAllBytes((Join-Path $wheelRoots['extra-output'] 'atlaso-0.0.1-py3-none-any.whl'), $wheelBytes)
    $validBuildLine = "Created wheel for atlaso: filename=$wheelName size=$($wheelBytes.Length) sha256=$wheelDigest"

    $expectedSourceBytes = Read-GitObjectByteArray -RepositoryRoot $repositoryRoot -Commit $sourceCommit -Path $relativeProofPath
    $snapshotPath = New-LifecycleSourceSnapshot -RepositoryRoot $repositoryRoot -Commit $sourceCommit `
        -ConsumerPins $sourceConsumerPins -DestinationRoot $StateRoot
    $snapshotFile = Join-Path $snapshotPath $relativeProofPath
    $snapshotBytes = [IO.File]::ReadAllBytes($snapshotFile)
    if ([Convert]::ToBase64String($expectedSourceBytes) -cne [Convert]::ToBase64String($snapshotBytes)) {
        throw 'Exported source bytes differ from the selected immutable Git object.'
    }
    $snapshotDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($snapshotBytes)).ToLowerInvariant()
    $objectDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($expectedSourceBytes)).ToLowerInvariant()
    if ($snapshotDigest -cne $objectDigest) { throw 'Exported source digest differs from the selected Git object.' }

    $pinnedOriginalBytes = [IO.File]::ReadAllBytes($snapshotFile)
    Assert-FileWriteRefused -Path $snapshotFile -OriginalBytes $pinnedOriginalBytes `
        -ReplacementBytes ([Text.Encoding]::UTF8.GetBytes('must be refused'))
    $fileMoveSucceeded = $false
    $fileMoveRefused = $false
    $movedSourceFile = "$snapshotFile.fixture-wheel-rename-probe"
    try {
        [IO.File]::Move($snapshotFile, $movedSourceFile)
        $fileMoveSucceeded = $true
    } catch { $fileMoveRefused = $true }
    if ($fileMoveSucceeded) {
        try { [IO.File]::Move($movedSourceFile, $snapshotFile) }
        catch { throw 'Unexpected source-file rename succeeded and restoration failed.' }
        throw 'Pinned source file unexpectedly accepted rename.'
    }
    if (-not $fileMoveRefused) { throw 'Pinned source-file rename probe did not produce a refusal.' }
    Assert-DirectoryRenameRefused -Path $snapshotPath -Description 'pinned source root rename'
    Assert-DirectoryRenameRefused -Path $StateRoot -Description 'pinned StateRoot ancestor rename'
    $sourceWriteProbe = Join-Path $snapshotPath 'fixture-wheel-source-write-probe.tmp'
    $sourceWriteProbeBytes = [Text.Encoding]::UTF8.GetBytes('source namespace writes must be refused')
    $sourceWriteRefused = $false
    try {
        $probe = [IO.File]::Open($sourceWriteProbe, 'CreateNew', 'Write', 'None')
        try { $probe.Write($sourceWriteProbeBytes, 0, $sourceWriteProbeBytes.Length); $probe.Flush($true) }
        finally { $probe.Dispose() }
    } catch [UnauthorizedAccessException] { $sourceWriteRefused = $true }
    catch [IO.IOException] { $sourceWriteRefused = $true }
    if (-not $sourceWriteRefused) { throw 'Exported source namespace unexpectedly accepted a new file.' }
    $ancestorWriteProbe = Join-Path $StateRoot 'ancestor-write-probe.tmp'
    $ancestorWriteProbeBytes = [Text.Encoding]::UTF8.GetBytes('wheel output ancestors remain writable')
    $ancestorProbe = [IO.File]::Open($ancestorWriteProbe, 'CreateNew', 'Write', 'None')
    try {
        $ancestorProbe.Write($ancestorWriteProbeBytes, 0, $ancestorWriteProbeBytes.Length)
        $ancestorProbe.Flush($true)
    } finally { $ancestorProbe.Dispose() }
    $ancestorProbeItem = Get-Item -LiteralPath $ancestorWriteProbe -Force
    $ancestorProbeIdentity = Get-AtlasoPathIdentity -Path $ancestorWriteProbe -Description 'Wheel output ancestor probe'
    if ($ancestorProbeItem.PSIsContainer -or $ancestorProbeItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        $ancestorProbeIdentity -notmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
        [IO.File]::ReadAllText($ancestorWriteProbe) -cne 'wheel output ancestors remain writable') {
        throw 'Writable StateRoot output probe failed ordinary-file verification.'
    }

    $activeWheelPins = [Collections.Generic.List[IDisposable]]::new()
    $wheelPinGroups.Add($activeWheelPins)
    $validWheel = Get-LifecycleBuiltWheel -OutputRoot $wheelRoots['valid'] `
        -BuildOutput @($validBuildLine) -ConsumerPins $activeWheelPins
    if ($validWheel.Name -cne $wheelName -or $validWheel.Sha256 -ine $wheelDigest) {
        throw 'Valid synthetic wheel identity did not round-trip.'
    }
    Assert-FileWriteRefused -Path $validWheel.FullName -OriginalBytes $wheelBytes `
        -ReplacementBytes ([Text.Encoding]::UTF8.GetBytes('changed'))
    $wheelMoveSucceeded = $false
    $wheelMoveRefused = $false
    $movedWheel = "$($validWheel.FullName).fixture-wheel-rename-probe"
    try {
        [IO.File]::Move($validWheel.FullName, $movedWheel)
        $wheelMoveSucceeded = $true
    } catch { $wheelMoveRefused = $true }
    if ($wheelMoveSucceeded) {
        try { [IO.File]::Move($movedWheel, $validWheel.FullName) }
        catch { throw 'Unexpected wheel rename succeeded and restoration failed.' }
        throw 'Pinned wheel unexpectedly accepted rename.'
    }
    if (-not $wheelMoveRefused) { throw 'Pinned wheel rename probe did not produce a refusal.' }

    $badNameLine = $validBuildLine.Replace($wheelName, 'atlaso-other-py3-none-any.whl')
    Assert-WheelRefused -OutputRoot $wheelRoots['wrong-name'] -BuildOutput @($badNameLine) `
        -Description 'wheel filename mismatch' -Pattern 'Wheel output does not contain exactly'
    $badSizeLine = $validBuildLine.Replace("size=$($wheelBytes.Length)", "size=$($wheelBytes.Length + 1)")
    Assert-WheelRefused -OutputRoot $wheelRoots['wrong-size'] -BuildOutput @($badSizeLine) `
        -Description 'wheel size mismatch' -Pattern 'Built wheel bytes differ'
    $badDigestLine = $validBuildLine.Replace("sha256=$wheelDigest", ('sha256=' + ('0' * 64)))
    Assert-WheelRefused -OutputRoot $wheelRoots['wrong-digest'] -BuildOutput @($badDigestLine) `
        -Description 'wheel digest mismatch' -Pattern 'Built wheel bytes differ'
    Assert-WheelRefused -OutputRoot $wheelRoots['extra-output'] -BuildOutput @($validBuildLine) `
        -Description 'extra wheel output' -Pattern 'Wheel output does not contain exactly'

    # Change only the known committed VMware leaf directory; the watcher covers this namespace recursively.
    $watchedChildDirectory = Join-Path $snapshotPath 'scripts/windows/vmware'
    if (-not (Test-Path -LiteralPath $watchedChildDirectory -PathType Container)) {
        throw 'Selected committed source child directory is missing.'
    }
    if (@(Get-ChildItem -LiteralPath $watchedChildDirectory -Directory -Force).Count -ne 0) {
        throw 'Selected source child directory unexpectedly contains unreviewed nested directories.'
    }
    $sourceChangeEvents = @($sourceConsumerPins | Where-Object { $_ -is [Threading.EventWaitHandle] })
    if ($sourceChangeEvents.Count -ne 1 -or $sourceChangeEvents[0].WaitOne(0)) {
        throw 'Source change watcher was missing or already signaled before the ACL probe.'
    }
    Assert-LifecycleSourcePins -Pins $sourceConsumerPins
    $sourceAclBefore = Get-Acl -LiteralPath $watchedChildDirectory
    $sourceAclBeforeSddl = $sourceAclBefore.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::All
    )
    $childFileAclBefore = @{}
    foreach ($childFile in Get-ChildItem -LiteralPath $watchedChildDirectory -File -Force) {
        $childFileAclBefore[$childFile.FullName] = (Get-Acl -LiteralPath $childFile.FullName).GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::All
        )
    }
    if ($childFileAclBefore.Count -eq 0) { throw 'Selected source child directory has no committed file entries.' }
    $sourceAclGuardRefused = $false
    $sourceAclChanged = $false
    $sourceAclProbeError = $null
    try {
        $changedAcl = Get-Acl -LiteralPath $watchedChildDirectory
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $currentSid,
            [Security.AccessControl.FileSystemRights]::ReadAttributes,
            [Security.AccessControl.AccessControlType]::Deny
        )
        $changedAcl.AddAccessRule($rule)
        Set-Acl -LiteralPath $watchedChildDirectory -AclObject $changedAcl -ErrorAction Stop
        $sourceAclChanged = $true
        if (-not $sourceChangeEvents[0].WaitOne([TimeSpan]::FromSeconds(5))) {
            throw 'Recursive source watcher did not report the committed child-directory security change.'
        }
        try { Assert-LifecycleSourcePins -Pins $sourceConsumerPins }
        catch {
            if ($_.Exception.Message -notmatch 'source snapshot changed during consumption') { throw }
            $sourceAclGuardRefused = $true
        }
    } catch {
        $sourceAclProbeError = $_.Exception
    } finally {
        if ($sourceAclChanged) {
            Set-Acl -LiteralPath $watchedChildDirectory -AclObject $sourceAclBefore -ErrorAction Stop
        }
    }
    $sourceAclAfter = (Get-Acl -LiteralPath $watchedChildDirectory).GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::All
    )
    if ($sourceAclAfter -cne $sourceAclBeforeSddl) { throw 'Owned source child-directory ACL was not restored exactly.' }
    foreach ($childFilePath in $childFileAclBefore.Keys) {
        $childFileSddl = (Get-Acl -LiteralPath $childFilePath).GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::All
        )
        if ($childFileSddl -cne $childFileAclBefore[$childFilePath]) {
            throw 'Source child-directory ACL probe changed a committed child file ACL.'
        }
    }
    if ($sourceAclProbeError) { throw $sourceAclProbeError }
    if (-not $sourceAclGuardRefused) { throw 'Recursive source ACL change was not rejected by the source guard.' }

    [pscustomobject]@{
        result = 'passed'
        task_id = $TaskId
        repository = 'mdaneri/Atlaso'
        source_commit = $sourceCommit
        candidate_module_sha256 = $moduleSha256
        caller_clean_precheck_refused_due_to_dirty_checkout = $callerCleanPrecheckRefused
        original_validation_root_identity = $rootIdentity
        state_root = $StateRoot
        state_root_identity = $stateRootIdentity
        exported_git_path = $relativeProofPath
        exported_git_sha256 = $objectDigest
        wheel_sha256 = $validWheel.Sha256
        source_acl_change_guard_exercised = $true
        source_acl_restored_exactly = $true
        output_ancestor_writable = $true
        source_namespace_write_refused = $true
    } | ConvertTo-Json -Depth 4
} catch {
    throw
} finally {
    for ($i = $wheelPinGroups.Count - 1; $i -ge 0; $i--) {
        $pins = $wheelPinGroups[$i]
        for ($j = $pins.Count - 1; $j -ge 0; $j--) { $pins[$j].Dispose() }
    }
    for ($i = $sourceConsumerPins.Count - 1; $i -ge 0; $i--) { $sourceConsumerPins[$i].Dispose() }
}
