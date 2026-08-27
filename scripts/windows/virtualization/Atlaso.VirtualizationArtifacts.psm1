<#
.SYNOPSIS
Validate the canonical Atlaso OVA and build its constrained Hyper-V package.
#>

Set-StrictMode -Version Latest

$script:MaximumGitHubAssetBytes = 2147483648

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

    $json = (Invoke-AtlasoQemuImg -QemuImgPath $QemuImgPath -Arguments @('info', '--output=json', $Path)) -join "`n"
    try {
        $info = $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "qemu-img returned invalid JSON while inspecting $Path"
    }
    if ($info.format -ne 'vhdx' -or [long]$info.'virtual-size' -ne $VirtualSizeBytes) {
        throw "Generated disk does not match the required dynamic VHDX/$VirtualSizeBytes contract: $Path"
    }
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.Length -le 0 -or $item.Length -ge $script:MaximumGitHubAssetBytes) {
        throw "Generated disk is empty or exceeds the GitHub asset limit: $Path"
    }
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
    'Get-AtlasoTemplateVersion',
    'Invoke-AtlasoOvaValidation',
    'Invoke-AtlasoQemuImg',
    'Resolve-AtlasoHyperVOutputRoot',
    'Resolve-AtlasoPythonPath',
    'Resolve-AtlasoQemuImgPath',
    'Write-AtlasoArtifactChecksums'
)
