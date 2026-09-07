<#
.SYNOPSIS
Validate the canonical Atlaso OVA and build its constrained Hyper-V package.
#>

Set-StrictMode -Version Latest

$script:MaximumGitHubAssetBytes = 2147483648
$script:MaximumHyperVExpandedBytes = 8589934592

<#
.SYNOPSIS
Resolve qemu-img from an explicit path or the current PATH.
.PARAMETER Path
Optional qemu-img executable path.
#>
function Resolve-AtlasoQemuImgPath {
    param([string]$Path = '')

    if ($Path) {
        $candidate = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($candidate.PSIsContainer -or
            ($candidate.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "qemu-img must identify an ordinary executable file: $Path"
        }
        return $candidate.FullName
    }
    $command = Get-Command qemu-img -ErrorAction SilentlyContinue
    if (-not $command) {
        throw 'qemu-img was not found. Install QEMU or pass -QemuImgPath.'
    }
    return $command.Source
}

<#
.SYNOPSIS
Resolve Python for the canonical OVA validator.
.PARAMETER Path
Optional Python executable path.
#>
function Resolve-AtlasoPythonPath {
    param([string]$Path = '')

    if ($Path) {
        $candidate = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($candidate.PSIsContainer -or
            ($candidate.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Python must identify an ordinary executable file: $Path"
        }
        return $candidate.FullName
    }
    foreach ($name in @('python', 'python3')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }
    throw 'Python was not found. Install Python or pass -PythonPath.'
}

<#
.SYNOPSIS
Resolve the repository-owned Hyper-V artifact output root.
.PARAMETER RepoRoot
Atlaso repository root.
.PARAMETER OutputRoot
Optional output root beneath artifacts/virtualization.
#>
function Resolve-AtlasoHyperVOutputRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$OutputRoot = ''
    )

    $repo = (Resolve-Path -LiteralPath $RepoRoot).Path
    $allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $repo 'artifacts\virtualization'))
    $requestedRoot = if ($OutputRoot) {
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot)
    }
    else {
        $allowedRoot
    }
    $requestedRoot = [System.IO.Path]::GetFullPath($requestedRoot)
    $prefix = $allowedRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($requestedRoot -ne $allowedRoot -and
        -not $requestedRoot.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Hyper-V artifacts must stay beneath the repository-owned root: $allowedRoot"
    }

    $relative = [System.IO.Path]::GetRelativePath($repo, $requestedRoot)
    if ($relative -eq '..' -or $relative.StartsWith("..$([System.IO.Path]::DirectorySeparatorChar)")) {
        throw 'Resolved Hyper-V output root escaped the repository.'
    }
    $cursor = $repo
    foreach ($component in $relative.Split(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.StringSplitOptions]::RemoveEmptyEntries
        )) {
        $cursor = Join-Path $cursor $component
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Hyper-V artifact output must traverse only ordinary directories: $cursor"
            }
        }
    }
    return $requestedRoot
}

<#
.SYNOPSIS
Return the synchronized Atlaso version recorded at one source commit.
.PARAMETER RepoRoot
Atlaso repository root containing the source commit.
.PARAMETER SourceCommit
Exact commit recorded in OVA provenance.
#>
function Get-AtlasoTemplateVersion {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$SourceCommit
    )

    if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
        throw 'OVA provenance contains an invalid source commit.'
    }
    $projectMetadata = @(& git -C $RepoRoot show "${SourceCommit}:pyproject.toml" 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($projectMetadata)) {
        throw "The OVA source commit is unavailable in this repository: $SourceCommit"
    }
    $match = [regex]::Match($projectMetadata, '(?m)^version\s*=\s*"(?<version>\d+\.\d+\.\d+)"\s*$')
    if (-not $match.Success) {
        throw 'Could not resolve the synchronized Atlaso version from the OVA source commit.'
    }
    return $match.Groups['version'].Value
}

<#
.SYNOPSIS
Validate and extract one canonical Atlaso OVA.
.PARAMETER RepoRoot
Atlaso repository root.
.PARAMETER OvaPath
Canonical OVA input path.
.PARAMETER ExtractDirectory
New empty extraction directory owned by this invocation.
.PARAMETER PythonPath
Resolved Python executable.
#>
function Invoke-AtlasoOvaValidation {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$OvaPath,
        [Parameter(Mandatory = $true)][string]$ExtractDirectory,
        [Parameter(Mandatory = $true)][string]$PythonPath
    )

    $validator = Join-Path $RepoRoot 'scripts\virtualization\validate_ova.py'
    $output = @(& $PythonPath $validator $OvaPath '--extract-directory' $ExtractDirectory 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $tail = @($output | Select-Object -Last 20) -join [Environment]::NewLine
        throw "Canonical OVA validation failed.$([Environment]::NewLine)$tail"
    }
    try {
        return (($output -join "`n") | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw 'Canonical OVA validation did not return the expected JSON contract.'
    }
}

<#
.SYNOPSIS
Invoke qemu-img and fail with bounded diagnostics.
.PARAMETER QemuImgPath
Resolved qemu-img executable.
.PARAMETER Arguments
Arguments supplied to qemu-img.
#>
function Invoke-AtlasoQemuImg {
    param(
        [Parameter(Mandatory = $true)][string]$QemuImgPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $output = @(& $QemuImgPath @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $tail = @($output | Select-Object -Last 20) -join [Environment]::NewLine
        throw "qemu-img failed with exit code $LASTEXITCODE.$([Environment]::NewLine)$tail"
    }
    return @($output)
}

<#
.SYNOPSIS
Validate one generated dynamic VHDX and its virtual capacity.
.PARAMETER QemuImgPath
Resolved qemu-img executable.
.PARAMETER Path
Generated disk path.
.PARAMETER VirtualSizeBytes
Expected virtual capacity in bytes.
#>
function Assert-AtlasoGeneratedVhdx {
    param(
        [Parameter(Mandatory = $true)][string]$QemuImgPath,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$VirtualSizeBytes
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Generated disk must be an ordinary file: $Path"
    }
    if ($item.Length -le 0) {
        throw "Generated VHDX is empty: $Path; file_bytes=$($item.Length). Check qemu-img conversion output."
    }
    $json = (Invoke-AtlasoQemuImg -QemuImgPath $QemuImgPath -Arguments @('info', '--output=json', $Path)) -join "`n"
    try {
        $info = $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "qemu-img returned invalid JSON while inspecting $Path"
    }
    Write-Host ("Generated disk {0}: file_bytes={1}; format={2}; virtual_size_bytes={3}; expected_virtual_size_bytes={4}" -f
        $item.Name, $item.Length, $info.format, $info.'virtual-size', $VirtualSizeBytes)
    if ($info.format -ne 'vhdx' -or [long]$info.'virtual-size' -ne $VirtualSizeBytes) {
        throw "Generated disk does not match the required dynamic VHDX/$VirtualSizeBytes contract: $Path"
    }
    # A dynamic VHDX is an uncompressed ZIP member, not a separately published asset.
    # Validate the final compressed archive against the release limit after streaming it.
}

<#
.SYNOPSIS
Reject an empty or oversized final Hyper-V release ZIP using its measured byte length.
.PARAMETER Path
Completed invocation-owned ZIP awaiting publication.
#>
function Assert-AtlasoHyperVArchiveSize {
    param([Parameter(Mandatory = $true)][string]$Path)

    $archive = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($archive.PSIsContainer -or
        ($archive.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Hyper-V ZIP must be an ordinary file: $Path"
    }
    Write-Host "Hyper-V ZIP $($archive.Name): archive_bytes=$($archive.Length); limit_bytes=$script:MaximumGitHubAssetBytes (exclusive)"
    if ($archive.Length -le 0) {
        throw "Hyper-V ZIP is empty: archive_bytes=$($archive.Length). Check archive creation before retrying."
    }
    if ($archive.Length -ge $script:MaximumGitHubAssetBytes) {
        throw (("Hyper-V ZIP exceeds the release asset limit: archive_bytes={0}; limit_bytes={1} (exclusive). " +
            "Reduce the template payload during construction and rebuild; do not split the package or boot the completed source template.") -f
            $archive.Length, $script:MaximumGitHubAssetBytes)
    }
}

<#
.SYNOPSIS
Stream package files into a new ZIP with ZIP64 support and verify member lengths.
.PARAMETER Files
Exact ordinary package files to archive at the ZIP root.
.PARAMETER DestinationPath
New invocation-owned ZIP path; existing files are never overwritten.
#>
function New-AtlasoHyperVArchive {
    param(
        [Parameter(Mandatory = $true)][string[]]$Files,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $members = @($Files | ForEach-Object { Get-Item -LiteralPath $_ -Force -ErrorAction Stop })
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($member in $members) {
        if ($member.PSIsContainer -or
            ($member.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $names.Add($member.Name)) {
            throw "ZIP members must be ordinary files with unique names: $($member.FullName)"
        }
    }
    # Match protected validation's aggregate extraction budget while allowing one
    # disk to exceed 2 GiB. This preserves a bounded hosted-runner disk footprint.
    [long]$expandedBytes = 0
    foreach ($member in $members) { $expandedBytes += $member.Length }
    if ($expandedBytes -gt $script:MaximumHyperVExpandedBytes) {
        throw "Hyper-V ZIP exceeds the extraction budget: uncompressed_bytes=$expandedBytes; limit_bytes=$script:MaximumHyperVExpandedBytes. Reduce the template payload during construction and rebuild."
    }
    # Compress-Archive uses Update mode, which buffers entries in memory and cannot
    # handle large VHDX members. Create mode streams DEFLATE and emits ZIP64 as needed.
    $stream = [System.IO.File]::Open($DestinationPath, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($member in $members) {
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $zip, $member.FullName, $member.Name, [System.IO.Compression.CompressionLevel]::Optimal
                ) | Out-Null
            }
        }
        finally { $zip.Dispose() }
    }
    finally { $stream.Dispose() }

    # Reopen only after the central directory is finalized. This read uses a seekable
    # file stream; it does not buffer or expand the potentially multi-GiB members.
    $readback = [System.IO.Compression.ZipFile]::OpenRead($DestinationPath)
    try {
        if ($readback.Entries.Count -ne $members.Count) {
            throw 'Hyper-V ZIP member count differs from the package inventory.'
        }
        foreach ($member in $members) {
            $entry = $readback.GetEntry($member.Name)
            if ($null -eq $entry -or $entry.Length -ne $member.Length) {
                throw "Hyper-V ZIP member length differs from the staged file: $($member.Name)"
            }
            Write-Host ("ZIP member {0}: uncompressed_bytes={1}; compressed_bytes={2}" -f
                $entry.FullName, $entry.Length, $entry.CompressedLength)
        }
    }
    finally { $readback.Dispose() }
    Assert-AtlasoHyperVArchiveSize -Path $DestinationPath
}

<#
.SYNOPSIS
Write exact SHA-256 verification metadata for a Hyper-V package directory.
.PARAMETER Directory
Completed staging directory.
#>
function Write-AtlasoArtifactChecksums {
    param([Parameter(Mandatory = $true)][string]$Directory)

    $entries = Get-ChildItem -LiteralPath $Directory -File |
        Where-Object Name -ne 'checksums.sha256' |
        Sort-Object Name |
        ForEach-Object {
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$hash  $($_.Name)"
        }
    [System.IO.File]::WriteAllText(
        (Join-Path $Directory 'checksums.sha256'),
        (($entries -join "`n") + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
}

Export-ModuleMember -Function @(
    'Assert-AtlasoGeneratedVhdx',
    'Assert-AtlasoHyperVArchiveSize',
    'Get-AtlasoTemplateVersion',
    'Invoke-AtlasoOvaValidation',
    'Invoke-AtlasoQemuImg',
    'New-AtlasoHyperVArchive',
    'Resolve-AtlasoHyperVOutputRoot',
    'Resolve-AtlasoPythonPath',
    'Resolve-AtlasoQemuImgPath',
    'Write-AtlasoArtifactChecksums'
)
