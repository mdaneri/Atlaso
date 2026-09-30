<#
.SYNOPSIS
Publish original lifecycle resource identities outside every removal root.
.DESCRIPTION
The canonical runner loads this helper and the filesystem primitives from its
admitted Git objects before creating resources. No existing resource is adopted.
#>

<#
.SYNOPSIS
Resolve the exact active Codex worktree root without accepting a caller override.
#>
function Get-AtlasoLifecycleDurableRoot {
    [OutputType([string])]
    param()

    $codexDirectory = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex' }
    $configPath = Join-Path $codexDirectory 'config.toml'
    $parentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($codexDirectory)
    $configPin = $null
    $stream = $null
    $reader = $null
    try {
        $configPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($configPath, $true)
        $stream = [IO.FileStream]::new($configPin, [IO.FileAccess]::Read)
        if ($stream.Length -gt 1048576) { throw 'Active Codex configuration exceeds its bounded size.' }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true))
        $configuration = $reader.ReadToEnd()
        $parser = @'
import json, sys, tomllib
data = tomllib.loads(sys.stdin.read())
desktop = data.get("desktop")
assert isinstance(desktop, dict), "desktop must be a TOML table"
root = desktop.get("git-worktree-root")
assert isinstance(root, str) and root.strip(), "configure desktop.git-worktree-root"
print(json.dumps(root))
'@
        $parsed = @($configuration | & python -I -S -c $parser 2>$null)
        if ($LASTEXITCODE -ne 0 -or $parsed.Count -ne 1) { throw 'Cannot resolve the active supported Codex worktree root.' }
        $configuredPath = $parsed[0] | ConvertFrom-Json
        if (-not [IO.Path]::IsPathFullyQualified($configuredPath)) { throw 'Configured worktree root must be absolute.' }
        $root = [IO.Path]::GetFullPath($configuredPath).TrimEnd('\', '/')
        if ($root -eq [IO.Path]::GetPathRoot($root).TrimEnd('\', '/')) { throw 'Configured worktree root cannot be a volume root.' }
        $rootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($root, $true)
        try { return $root } finally { $rootPin.Dispose() }
    }
    finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
        elseif ($configPin) { $configPin.Dispose() }
        $parentPin.Dispose()
    }
}

<#
.SYNOPSIS
Persist a just-created original resource identity before its first use.
.PARAMETER DurableRoot
Independently resolved active Codex worktree root.
.PARAMETER Worktree
Admitted source checkout whose resources are being created.
.PARAMETER LabRoot
Exact newly created canonical lifecycle result root.
.PARAMETER ResourcePath
Original directory or VMX returned by the owning creation operation.
.PARAMETER Kind
Resource category being recorded at its creation boundary.
.PARAMETER TaskId
Exact originating Codex task identity.
.PARAMETER SourceCommit
Immutable source commit admitted before resource creation.
.PARAMETER PullRequestNumber
Positive PR owning the lifecycle validation.
.PARAMETER RequireEmpty
Require a newly created empty directory before its first child is populated.
#>
function New-AtlasoLifecycleOwnershipRecord {
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][string]$DurableRoot,
        [Parameter(Mandatory)][string]$Worktree,
        [Parameter(Mandatory)][string]$LabRoot,
        [Parameter(Mandatory)][string]$ResourcePath,
        [Parameter(Mandatory)][ValidateSet('lifecycle', 'vm-directory', 'vm')][string]$Kind,
        [Parameter(Mandatory)][string]$TaskId,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
        [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$PullRequestNumber,
        [switch]$RequireEmpty
    )

    if ($TaskId -notmatch '^[A-Za-z0-9_-]{1,128}$') { throw 'Exact lifecycle task identity is required.' }
    $root = [IO.Path]::GetFullPath($DurableRoot).TrimEnd('\', '/')
    $checkout = [IO.Path]::GetFullPath($Worktree).TrimEnd('\', '/')
    $lab = [IO.Path]::GetFullPath($LabRoot).TrimEnd('\', '/')
    $resource = [IO.Path]::GetFullPath($ResourcePath).TrimEnd('\', '/')
    if (-not $checkout.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        -not $lab.StartsWith($checkout + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        ($resource -ne $lab -and -not $resource.StartsWith($lab + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase))) {
        throw 'Lifecycle ownership paths escape their independently configured root.'
    }
    $rootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($root, $true)
    $resourcePin = $null
    $parentPin = $null
    $writer = $null
    try {
        $directory = $Kind -ne 'vm'
        if ($directory) {
            $resourcePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($resource, $true)
            if ($RequireEmpty -and @(Get-ChildItem -LiteralPath $resource -Force).Count) {
                throw 'Creation ownership requires the original empty directory; existing resources cannot be adopted.'
            }
        } else {
            $parentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $resource), $true)
            $resourcePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($resource, $true)
        }
        # The pinned resource cannot be replaced between original identity capture
        # and durable publication. This is the WindowsFiles identity tuple format.
        $nativeIdentity = [Atlaso.WorkstationFileIdentity]::Get($resource)
        if ($nativeIdentity -notmatch '^([0-9A-F]{8}):([0-9A-F]{8})([0-9A-F]{8})$') { throw 'Unsupported original resource identity.' }
        $identity = @([Convert]::ToUInt32($Matches[1], 16), [Convert]::ToUInt32($Matches[2], 16), [Convert]::ToUInt32($Matches[3], 16))
        $record = [ordered]@{
            schema = 1; task_id = $TaskId; repository = 'mdaneri/Atlaso'; source_commit = $SourceCommit
            pr = $PullRequestNumber; worktree = $checkout; lab_root = $lab; path = $resource
            kind = $Kind; root_identity = $identity; created_utc = [DateTimeOffset]::UtcNow.ToString('o')
            cleanup_tool = $(if ($Kind -eq 'lifecycle') { 'Remove-AtlasoWorkstationArtifactRoot' } else { 'scripts/windows/vmware/invoke-lifecycle-test.ps1 -CleanupVmsOnly' })
        }
        $name = 'atlaso-lifecycle-original-{0}-{1}.json' -f $PullRequestNumber, [guid]::NewGuid().ToString('N')
        $destination = Join-Path $root $name
        $stage = $destination + '.pending'
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Depth 5))
        $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($stage)
        $writer.Write($bytes)
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, $destination, $false)
        return [pscustomobject]@{ path = $destination; sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant(); resource = $resource }
    }
    finally {
        if ($writer) { $writer.Dispose() }
        if ($resourcePin) { $resourcePin.Dispose() }
        if ($parentPin) { $parentPin.Dispose() }
        $rootPin.Dispose()
    }
}
