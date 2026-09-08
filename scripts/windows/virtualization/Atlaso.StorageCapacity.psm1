<#
.SYNOPSIS
Provides workspace-wide storage admission helpers for virtualization flows.
.DESCRIPTION
These helpers are intentionally non-mutating and fail closed when storage identity or residual capacity cannot be proven before a generation step.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AtlasoStorageVolumeResolver = {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [hashtable]$Fixtures = $null
    )

    $volume = Get-Volume -FilePath $Path
    $volumeList = @($volume)
    if ($volumeList.Count -ne 1) {
        throw "Storage volume resolution must map path to exactly one volume: $Path"
    }
    return $volumeList[0]
}

$script:AtlasoStorageVolumeFixtures = $null

<#
.SYNOPSIS
Convert an arbitrary value to Int64 after strict integer validation.
.PARAMETER Value
Candidate value from bytes/headroom inputs.
.PARAMETER Context
Call context included in a validation error.
.OUTPUTS
System.Int64 representing the validated integer.
#>
function ConvertTo-AtlasoNonNegativeInt64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($null -eq $Value) {
        throw "Storage capacity input must be a nonnegative integer for $Context, but it was null."
    }

    if ($Value -is [bool] -or $Value -is [System.Enum]) {
        throw "Storage capacity input must be a nonnegative integer for $Context."
    }

    if ($Value -is [double] -or $Value -is [float] -or $Value -is [single] -or $Value -is [decimal]) {
        throw "Storage capacity input must be a nonnegative integer for $Context."
    }

    if ($Value -is [string]) {
        $trimmed = $Value.Trim()
        if ($trimmed -notmatch '^(?:0|[1-9][0-9]*)$') {
            throw "Storage capacity input must be a nonnegative integer for $Context."
        }
        try {
            return [long][System.Int64]::Parse($trimmed, [System.Globalization.CultureInfo]::InvariantCulture)
        }
        catch {
            throw "Storage capacity input must be within Int64 range for $Context."
        }
    }

    if (-not ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [short] -or $Value -is [ushort] -or
        $Value -is [int] -or $Value -is [uint] -or $Value -is [long] -or $Value -is [ulong])) {
        if ($Value -is [System.Numerics.BigInteger]) {
            try {
                $candidate = [long]$Value
            }
            catch {
                throw "Storage capacity input must be within Int64 range for $Context."
            }

            if ($candidate -lt 0) {
                throw "Storage capacity input must be nonnegative for $Context."
            }

            return $candidate
        }

        throw "Storage capacity input must be a nonnegative integer for $Context."
    }

    try {
        $candidate = [long]$Value
    }
    catch {
        throw "Storage capacity input must be a nonnegative integer for $Context."
    }

    if ($candidate -lt 0) {
        throw "Storage capacity input must be nonnegative for $Context."
    }

    return $candidate
}

<#
.SYNOPSIS
Resolve one verified storage volume identity for an operation path.
.PARAMETER Path
Absolute filesystem path for the operation.
.OUTPUTS
PSCustomObject with Path, ExistingPath, VolumeId, and SizeRemaining.
#>
function Get-AtlasoStorageVolume {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Storage capacity resolution requires a non-empty Path.'
    }

    if (-not [System.IO.Path]::IsPathFullyQualified($Path)) {
        throw "Storage admission requires an absolute filesystem path: $Path"
    }

    try {
        $absolute = [System.IO.Path]::GetFullPath($Path)
    }
    catch {
        throw "Could not normalize storage path: $Path"
    }

    if ($absolute.StartsWith('\\')) {
        throw "UNC paths are unsupported for storage admission: $absolute"
    }

    $cursor = $absolute
    while ($cursor -and -not (Test-Path -LiteralPath $cursor)) {
        $parent = Split-Path $cursor -Parent
        if (-not $parent -or $parent -eq $cursor) {
            throw "No existing filesystem ancestor was found for: $absolute"
        }
        $cursor = $parent
    }

    $existingPath = (Resolve-Path -LiteralPath $cursor).Path
    $cursor = $existingPath
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (-not $item.PSIsContainer) {
            throw "Storage admission requires ordinary directories on the path: $cursor"
        }

        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Storage admission rejected a reparse-point path component: $cursor"
        }

        $parent = Split-Path $cursor -Parent
        if (-not $parent -or $parent -eq $cursor) {
            break
        }
        $cursor = $parent
    }

    $volume = & $script:AtlasoStorageVolumeResolver -Path $existingPath -Fixtures $script:AtlasoStorageVolumeFixtures
    $volumeList = @($volume)
    if ($volumeList.Count -ne 1) {
        throw "Storage volume resolution returned $($volumeList.Count) volume(s) for: $existingPath"
    }
    $volume = $volumeList[0]
    if ($null -eq $volume) {
        throw "Could not resolve an operating-system volume for: $existingPath"
    }

    $uniqueId = [string]$volume.UniqueId
    if ([string]::IsNullOrWhiteSpace($uniqueId)) {
        throw "Volume identity is unreliable for: $existingPath"
    }

    if (-not $volume.PSObject.Properties.Match('SizeRemaining')) {
        throw "Volume remaining-bytes evidence is unavailable for: $existingPath"
    }

    $remaining = ConvertTo-AtlasoNonNegativeInt64 -Value $volume.SizeRemaining -Context "volume.SizeRemaining ($existingPath)"
    if ($null -eq $remaining) {
        throw "Volume remaining-bytes evidence is invalid for: $existingPath"
    }

    return [pscustomobject]@{
        Path = $absolute
        ExistingPath = $existingPath
        VolumeId = $uniqueId
        SizeRemaining = $remaining
    }
}

<#
.SYNOPSIS
Assert aggregate storage capacity for one named build stage.
.PARAMETER Components
Component descriptors with Path, Name, and Bytes.
.PARAMETER Stage
Caller stage label for evidence and diagnostics.
.PARAMETER HeadroomBytes
Extra free-space headroom applied once per volume. Default is 2 GiB.
.OUTPUTS
No output. Throws on shortfall or unreliable evidence.
#>
function Assert-AtlasoStorageCapacity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Components,
        [Parameter(Mandatory = $true)][string]$Stage,
        [object]$HeadroomBytes = 2GB
    )

    $headroomBytes = ConvertTo-AtlasoNonNegativeInt64 -Value $HeadroomBytes -Context "HeadroomBytes on stage '$Stage'"

    $volumeBuckets = @{}
    $componentList = @($Components)

    if ($componentList.Count -eq 0) {
        Write-Host "Storage admission stage '$Stage' has no components; no capacity mutation required."
        return
    }

    foreach ($component in $componentList) {
        if ($null -eq $component) {
            throw "Storage admission cannot accept a null component for stage '$Stage'."
        }

        if (-not $component.PSObject.Properties.Match('Path')) {
            throw "Every storage component must include Path for stage '$Stage'."
        }

        if (-not $component.PSObject.Properties.Match('Name')) {
            throw "Every storage component must include Name for stage '$Stage'."
        }

        if (-not $component.PSObject.Properties.Match('Bytes')) {
            throw "Every storage component must include Bytes for stage '$Stage'."
        }

        $bytes = ConvertTo-AtlasoNonNegativeInt64 -Value $component.Bytes -Context "component '$($component.Name)' Bytes"

        $volume = Get-AtlasoStorageVolume -Path $component.Path
        $volumeKey = [string]$volume.VolumeId
        if ([string]::IsNullOrWhiteSpace($volumeKey)) {
            throw "Storage admission received an unreliable volume identity for stage '$Stage'."
        }

        $caseKey = $volumeKey.ToLowerInvariant()
        if (-not $volumeBuckets.ContainsKey($caseKey)) {
            $volumeBuckets[$caseKey] = [ordered]@{
                Path = $volume.Path
                ExistingPath = $volume.ExistingPath
                VolumeId = $volumeKey
                RemainingBytes = [decimal]$volume.SizeRemaining
                RequiredBytes = [decimal]0
                Components = @()
            }
        }

        $bucket = $volumeBuckets[$caseKey]
        $next = $bucket.RequiredBytes + [decimal]$bytes
        if ($next -lt $bucket.RequiredBytes -or $next -gt [decimal][long]::MaxValue) {
            throw "Storage admission arithmetic overflow for stage '$Stage' on volume '$($bucket.VolumeId)' before adding component '$($component.Name)'."
        }

        $bucket.RequiredBytes = $next
        $bucket.RemainingBytes = [Math]::Min($bucket.RemainingBytes, [decimal]$volume.SizeRemaining)
        $bucket.Components += [ordered]@{
            Name = [string]$component.Name
            Path = [string]$component.Path
            Bytes = $bytes
        }
    }

    $shortfalls = @()
    foreach ($entry in $volumeBuckets.GetEnumerator()) {
        $bucket = $entry.Value
        if ([decimal]$bucket.RequiredBytes + $headroomBytes -gt [decimal][long]::MaxValue) {
            throw "Storage admission arithmetic overflow for stage '$Stage' on volume '$($bucket.VolumeId)' after adding headroom."
        }

        $requiredWithHeadroom = $bucket.RequiredBytes + $headroomBytes
        $shortfall = if ($bucket.RemainingBytes -lt $requiredWithHeadroom) {
            $requiredWithHeadroom - $bucket.RemainingBytes
        }
        else {
            0
        }

        $componentsSummary = $bucket.Components |
            ForEach-Object { "{0}:{1}={2}" -f $_.Name, $_.Bytes, $_.Path } |
            Sort-Object
        $componentsSummary = [string]::Join(', ', $componentsSummary)

        Write-Host "Storage stage '$Stage' volume summary:"
        Write-Host ("  path={0}" -f $bucket.Path)
        Write-Host ("  existing_path={0}" -f $bucket.ExistingPath)
        Write-Host ("  volume={0}" -f $bucket.VolumeId)
        Write-Host ("  free={0}" -f [long]$bucket.RemainingBytes)
        Write-Host ("  required={0}" -f [long]$requiredWithHeadroom)
        Write-Host ("  shortfall={0}" -f [long]$shortfall)
        Write-Host ("  components=[{0}]" -f $componentsSummary)

        if ($shortfall -gt 0) {
            $shortfalls += [pscustomobject]@{
                Stage = $Stage
                VolumeId = $bucket.VolumeId
                Shortfall = [long]$shortfall
                Remaining = [long]$bucket.RemainingBytes
                Required = [long]$requiredWithHeadroom
                ExistingPath = [string]$bucket.ExistingPath
                Path = [string]$bucket.Path
                Components = $componentsSummary
            }
        }
    }

    if ($shortfalls.Count -gt 0) {
        $details = @(
            foreach ($entry in $shortfalls) {
                "volume $($entry.VolumeId): free=$($entry.Remaining) required=$($entry.Required) shortfall=$($entry.Shortfall); components=$($entry.Components)"
            }
        ) -join '; '
        throw "Storage admission failed for stage '$Stage': insufficient capacity on $($shortfalls.Count) volume(s): $details. Remediation: reduce or remove listed component bytes or choose an alternate destination with enough free space."
    }
}

Export-ModuleMember -Function @(
    'Assert-AtlasoStorageCapacity',
    'Get-AtlasoStorageVolume'
)
