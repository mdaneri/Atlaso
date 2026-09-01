<#
.SYNOPSIS
Create and verify commit-derived source snapshots for VMware image builds.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Resolve one existing ordinary directory without following a reparse point.
.PARAMETER Path
Directory path to validate.
.PARAMETER Description
Non-secret description used in failures.
#>
function Resolve-AtlasoSourceSnapshotDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be one ordinary non-reparse-point directory."
    }
    return [System.IO.Path]::GetFullPath($item.FullName)
}

<#
.SYNOPSIS
Resolve the exact commit and branch-style identity of one Git checkout.
.PARAMETER RepositoryRoot
Canonical Git working tree to identify.
#>
function Get-AtlasoSourceCheckoutIdentity {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $resolvedRepository = Resolve-AtlasoSourceSnapshotDirectory `
        -Path $RepositoryRoot `
        -Description 'The source repository root'
    $gitRoot = [string](& git -C $resolvedRepository rev-parse --show-toplevel)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitRoot) -or
        -not [System.IO.Path]::GetFullPath($gitRoot.Trim()).Equals(
            $resolvedRepository,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'The source repository root is missing or ambiguous.'
    }
    $commit = [string](& git -C $resolvedRepository rev-parse --verify 'HEAD^{commit}')
    if ($LASTEXITCODE -ne 0 -or $commit.Trim() -notmatch '^[0-9a-f]{40}$') {
        throw 'The exact source commit could not be admitted.'
    }
    $commit = $commit.Trim()
    $branch = [string](& git -C $resolvedRepository branch --show-current)
    if ($LASTEXITCODE -ne 0) {
        throw 'The source checkout identity could not be inspected.'
    }
    $detached = [string]::IsNullOrWhiteSpace($branch)
    $branchIdentity = if ($detached) {
        "detached/$commit"
    }
    else {
        $branch.Trim()
    }
    & git check-ref-format --branch $branchIdentity 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'The source checkout branch identity is invalid.'
    }
    $confirmedCommit = [string](& git -C $resolvedRepository rev-parse --verify 'HEAD^{commit}')
    if ($LASTEXITCODE -ne 0 -or $confirmedCommit.Trim() -cne $commit) {
        throw 'The source commit changed during checkout identity admission.'
    }
    return [pscustomobject]@{
        Commit   = $commit
        Branch   = $branchIdentity
        Detached = $detached
    }
}

<#
.SYNOPSIS
Compute the deterministic byte inventory for one staged source tree.
.PARAMETER Root
Exact staged source root.
#>
function Get-AtlasoSourceSnapshotInventory {
    param([Parameter(Mandatory = $true)][string]$Root)

    $resolvedRoot = Resolve-AtlasoSourceSnapshotDirectory `
        -Path $Root `
        -Description 'The staged source root'
    $rootPrefix = $resolvedRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $records = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(Get-ChildItem -LiteralPath $resolvedRoot -Force -Recurse -ErrorAction Stop)) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'The staged source tree contains a reparse point.'
        }
        $resolvedItem = [System.IO.Path]::GetFullPath($item.FullName)
        if (-not $resolvedItem.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The staged source tree contains an item outside its admitted root.'
        }
        if ($item.PSIsContainer) {
            continue
        }
        if ($item -isnot [System.IO.FileInfo]) {
            throw 'The staged source tree contains an unsupported filesystem item.'
        }
        $relative = [System.IO.Path]::GetRelativePath($resolvedRoot, $resolvedItem).Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($relative) -or
            $relative -eq '..' -or
            $relative.StartsWith('../', [StringComparison]::Ordinal)) {
            throw 'The staged source tree contains an invalid relative path.'
        }
        $hash = (Get-FileHash -LiteralPath $resolvedItem -Algorithm SHA256).Hash.ToLowerInvariant()
        $records.Add("$relative`t$($item.Length)`t$hash")
    }
    $recordArray = $records.ToArray()
    [Array]::Sort($recordArray, [StringComparer]::Ordinal)
    $inventoryText = if ($recordArray.Count -eq 0) {
        ''
    }
    else {
        ($recordArray -join "`n") + "`n"
    }
    $inventoryBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($inventoryText)
    $digestBytes = [System.Security.Cryptography.SHA256]::HashData($inventoryBytes)
    return [pscustomobject]@{
        Root       = $resolvedRoot
        FileCount  = $recordArray.Count
        Sha256     = [Convert]::ToHexString($digestBytes).ToLowerInvariant()
        Records    = $recordArray
    }
}

<#
.SYNOPSIS
Verify that a staged source tree still matches its admitted byte inventory.
.PARAMETER Root
Exact staged source root.
.PARAMETER ExpectedSha256
Expected deterministic inventory SHA-256.
.PARAMETER ExpectedFileCount
Expected number of staged regular files.
#>
function Assert-AtlasoSourceSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ExpectedFileCount
    )

    $inventory = Get-AtlasoSourceSnapshotInventory -Root $Root
    if ($inventory.FileCount -ne $ExpectedFileCount -or
        $inventory.Sha256 -cne $ExpectedSha256) {
        throw 'The staged source tree no longer matches its admitted byte inventory.'
    }
    return $inventory
}

<#
.SYNOPSIS
Verify that a staged source inventory matches one exact Git commit.
.PARAMETER Root
Exact staged source root.
.PARAMETER RepositoryRoot
Canonical Git repository containing the admitted commit.
.PARAMETER Commit
Exact admitted Git commit.
.PARAMETER ExpectedSha256
Expected deterministic inventory SHA-256.
.PARAMETER ExpectedFileCount
Expected number of staged regular files.
.PARAMETER VerificationRoot
Fresh invocation-owned directory used for the independent commit export.
#>
function Assert-AtlasoSourceSnapshotCommitBinding {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ExpectedFileCount,
        [Parameter(Mandatory = $true)][string]$VerificationRoot
    )

    $resolvedRepository = Resolve-AtlasoSourceSnapshotDirectory `
        -Path $RepositoryRoot `
        -Description 'The source repository root'
    $resolvedVerification = [System.IO.Path]::GetFullPath($VerificationRoot)
    if (Test-Path -LiteralPath $resolvedVerification) {
        throw 'The source commit verification root is not fresh.'
    }
    $gitRoot = [string](& git -C $resolvedRepository rev-parse --show-toplevel)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitRoot) -or
        -not [System.IO.Path]::GetFullPath($gitRoot.Trim()).Equals(
            $resolvedRepository,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'The source repository root is missing or ambiguous.'
    }
    & git -C $resolvedRepository cat-file -e "$Commit^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'The admitted source commit is unavailable from the task repository.'
    }

    [void][System.IO.Directory]::CreateDirectory($resolvedVerification)
    $archivePath = Join-Path $resolvedVerification 'source.zip'
    $commitRoot = Join-Path $resolvedVerification 'source'
    try {
        & git -C $resolvedRepository archive `
            --format=zip `
            "--output=$archivePath" `
            $Commit
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
            throw 'The admitted source commit could not be independently archived.'
        }
        Expand-Archive -LiteralPath $archivePath -DestinationPath $commitRoot -ErrorAction Stop
        $commitInventory = Get-AtlasoSourceSnapshotInventory -Root $commitRoot
        $null = Assert-AtlasoSourceSnapshot `
            -Root $Root `
            -ExpectedSha256 $ExpectedSha256 `
            -ExpectedFileCount $ExpectedFileCount
        if ($commitInventory.FileCount -ne $ExpectedFileCount -or
            $commitInventory.Sha256 -cne $ExpectedSha256) {
            throw 'The staged source tree does not match the admitted Git commit.'
        }
        return $commitInventory
    }
    finally {
        if (Test-Path -LiteralPath $resolvedVerification) {
            Remove-Item -LiteralPath $resolvedVerification -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $resolvedVerification) {
                throw 'The source commit verification root could not be removed.'
            }
        }
    }
}

<#
.SYNOPSIS
Remove write access from one admitted source snapshot for its build lifetime.
.PARAMETER Root
Exact staged source root to protect.
.PARAMETER ExpectedSha256
Expected deterministic inventory SHA-256.
.PARAMETER ExpectedFileCount
Expected number of staged regular files.
#>
function Protect-AtlasoSourceSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$ExpectedFileCount
    )

    $inventory = Assert-AtlasoSourceSnapshot `
        -Root $Root `
        -ExpectedSha256 $ExpectedSha256 `
        -ExpectedFileCount $ExpectedFileCount
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $readOnlyAcl = [Security.AccessControl.DirectorySecurity]::new(
        $inventory.Root,
        [Security.AccessControl.AccessControlSections]::Access
    )
    $readOnlyAcl.SetAccessRuleProtection($true, $false)
    $readOnlyAcl.PurgeAccessRules($currentSid)
    $readOnlyAcl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $currentSid,
            [Security.AccessControl.FileSystemRights]'ReadAndExecute, Synchronize',
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    [System.IO.FileSystemAclExtensions]::SetAccessControl(
        [System.IO.DirectoryInfo]::new($inventory.Root),
        $readOnlyAcl
    )

    $probePath = Join-Path $inventory.Root ".atlaso-write-probe-$([guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllText(
            $probePath,
            'write access must remain unavailable',
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    catch [System.UnauthorizedAccessException] {
        return $inventory
    }
    if (Test-Path -LiteralPath $probePath) {
        Remove-Item -LiteralPath $probePath -Force -ErrorAction SilentlyContinue
    }
    throw 'The admitted source snapshot remained writable after protection.'
}

<#
.SYNOPSIS
Restore task-owner access before removing an invocation-owned source snapshot.
.PARAMETER Root
Exact staged source root whose build consumer has terminated.
#>
function Unprotect-AtlasoSourceSnapshot {
    param([Parameter(Mandatory = $true)][string]$Root)

    $resolvedRoot = Resolve-AtlasoSourceSnapshotDirectory `
        -Path $Root `
        -Description 'The staged source root'
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $ownerAcl = [Security.AccessControl.DirectorySecurity]::new(
        $resolvedRoot,
        [Security.AccessControl.AccessControlSections]::Access
    )
    $ownerAcl.SetAccessRuleProtection($true, $false)
    $ownerAcl.PurgeAccessRules($currentSid)
    $ownerAcl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $currentSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    [System.IO.FileSystemAclExtensions]::SetAccessControl(
        [System.IO.DirectoryInfo]::new($resolvedRoot),
        $ownerAcl
    )

    $probePath = Join-Path $resolvedRoot ".atlaso-write-probe-$([guid]::NewGuid().ToString('N'))"
    [System.IO.File]::WriteAllText(
        $probePath,
        'write access restored for cleanup',
        [System.Text.UTF8Encoding]::new($false)
    )
    Remove-Item -LiteralPath $probePath -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $probePath) {
        throw 'The staged source snapshot write-access probe could not be removed.'
    }
}

<#
.SYNOPSIS
Materialize one exact clean Git commit into an invocation-owned source tree.
.PARAMETER RepositoryRoot
Canonical Git working tree whose current commit is admitted.
.PARAMETER StagingRoot
Fresh invocation-owned ordinary directory that will contain source.zip and source.
#>
function New-AtlasoImmutableSourceSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$StagingRoot
    )

    $resolvedRepository = Resolve-AtlasoSourceSnapshotDirectory `
        -Path $RepositoryRoot `
        -Description 'The source repository root'
    $resolvedStaging = Resolve-AtlasoSourceSnapshotDirectory `
        -Path $StagingRoot `
        -Description 'The source staging root'
    $snapshotRoot = Join-Path $resolvedStaging 'source'
    $archivePath = Join-Path $resolvedStaging 'source.zip'
    if ((Test-Path -LiteralPath $snapshotRoot) -or
        (Test-Path -LiteralPath $archivePath)) {
        throw 'The source staging root is not fresh.'
    }

    $gitRoot = [string](& git -C $resolvedRepository rev-parse --show-toplevel)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitRoot) -or
        -not [System.IO.Path]::GetFullPath($gitRoot.Trim()).Equals(
            $resolvedRepository,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'The source repository root is missing or ambiguous.'
    }
    $sourceCommit = [string](& git -C $resolvedRepository rev-parse --verify 'HEAD^{commit}')
    if ($LASTEXITCODE -ne 0 -or $sourceCommit.Trim() -notmatch '^[0-9a-f]{40}$') {
        throw 'The exact source commit could not be admitted.'
    }
    $sourceCommit = $sourceCommit.Trim()
    $changes = @(& git -C $resolvedRepository status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) {
        throw 'The source working tree state could not be inspected.'
    }
    if ($changes.Count -ne 0) {
        throw 'The VMware image source working tree must be completely clean before snapshot admission.'
    }
    $confirmedCommit = [string](& git -C $resolvedRepository rev-parse --verify 'HEAD^{commit}')
    if ($LASTEXITCODE -ne 0 -or $confirmedCommit.Trim() -cne $sourceCommit) {
        throw 'The source commit changed during snapshot admission.'
    }
    $gitlinks = @(& git -C $resolvedRepository ls-tree -r --full-tree $sourceCommit |
            Where-Object { $_ -match '^160000\s' })
    if ($LASTEXITCODE -ne 0) {
        throw 'The admitted source tree could not be inspected.'
    }
    if ($gitlinks.Count -ne 0) {
        throw 'The admitted source tree contains an unsupported Git submodule entry.'
    }

    try {
        & git -C $resolvedRepository archive `
            --format=zip `
            "--output=$archivePath" `
            $sourceCommit
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
            throw 'The admitted source commit could not be archived.'
        }
        Expand-Archive -LiteralPath $archivePath -DestinationPath $snapshotRoot -ErrorAction Stop
        $firstInventory = Get-AtlasoSourceSnapshotInventory -Root $snapshotRoot
        if ($firstInventory.FileCount -le 0) {
            throw 'The admitted source snapshot is empty.'
        }
        $null = Assert-AtlasoSourceSnapshot `
            -Root $snapshotRoot `
            -ExpectedSha256 $firstInventory.Sha256 `
            -ExpectedFileCount $firstInventory.FileCount
        return [pscustomobject]@{
            Root       = $firstInventory.Root
            Commit     = $sourceCommit
            FileCount  = $firstInventory.FileCount
            Sha256     = $firstInventory.Sha256
        }
    }
    catch {
        $snapshotError = $_
        if (Test-Path -LiteralPath $snapshotRoot) {
            Remove-Item -LiteralPath $snapshotRoot -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $snapshotRoot) {
                throw 'The failed source snapshot could not be removed from invocation-owned staging.'
            }
        }
        throw $snapshotError
    }
    finally {
        if (Test-Path -LiteralPath $archivePath) {
            Remove-Item -LiteralPath $archivePath -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $archivePath) {
                throw 'The temporary source archive could not be removed from invocation-owned staging.'
            }
        }
    }
}

Export-ModuleMember -Function `
    Get-AtlasoSourceCheckoutIdentity, `
    New-AtlasoImmutableSourceSnapshot, `
    Assert-AtlasoSourceSnapshot, `
    Assert-AtlasoSourceSnapshotCommitBinding, `
    Get-AtlasoSourceSnapshotInventory, `
    Protect-AtlasoSourceSnapshot, `
    Unprotect-AtlasoSourceSnapshot
