Set-StrictMode -Version Latest

function Get-AtlasoExpectedChecksum {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$HexLength
    )

    $content = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop).Trim()
    $token = @($content -split '\s+' | Where-Object { $_ }) | Select-Object -First 1
    if (-not $token -or $token -notmatch "^[0-9A-Fa-f]{$HexLength}$") {
        throw "Checksum file does not begin with a $HexLength-character hexadecimal digest: $Path"
    }
    return $token.ToUpperInvariant()
}

function Save-AtlasoVerifiedDownloadPair {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$PayloadUri,
        [Parameter(Mandatory = $true)][string]$ChecksumUri,
        [Parameter(Mandatory = $true)][string]$PayloadPath,
        [Parameter(Mandatory = $true)][string]$ChecksumPath,
        [Parameter(Mandatory = $true)][ValidateSet('SHA512')][string]$Algorithm,
        [Parameter(Mandatory = $true)][scriptblock]$GetFileHash,
        [switch]$Force
    )

    $payloadParent = [System.IO.Path]::GetFullPath((Split-Path -Parent $PayloadPath))
    $checksumParent = [System.IO.Path]::GetFullPath((Split-Path -Parent $ChecksumPath))
    if (-not $payloadParent.Equals($checksumParent, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Verified payload and checksum targets must share one cache directory.'
    }
    if (-not (Test-Path -LiteralPath $payloadParent -PathType Container)) {
        throw "Verified download cache directory does not exist: $payloadParent"
    }

    $hexLength = switch ($Algorithm) {
        'SHA512' { 128 }
    }
    $cacheIsValid = $false
    if (-not $Force -and (Test-Path -LiteralPath $PayloadPath -PathType Leaf) -and (Test-Path -LiteralPath $ChecksumPath -PathType Leaf)) {
        try {
            $expected = Get-AtlasoExpectedChecksum -Path $ChecksumPath -HexLength $hexLength
            $actual = (& $GetFileHash $PayloadPath).ToUpperInvariant()
            $cacheIsValid = $expected -eq $actual
        } catch {
            $cacheIsValid = $false
        }
        if ($cacheIsValid) {
            Write-Host "Verified cached download: $PayloadPath"
            return $actual
        }
    }

    if (-not $PSCmdlet.ShouldProcess($PayloadPath, 'Download, validate, and atomically promote cache pair')) {
        return $null
    }

    foreach ($knownBadPath in @($PayloadPath, $ChecksumPath)) {
        if (Test-Path -LiteralPath $knownBadPath) {
            Remove-Item -LiteralPath $knownBadPath -Force -ErrorAction Stop
        }
    }

    $nonce = [guid]::NewGuid().ToString('N')
    $payloadPartial = "$PayloadPath.part.$nonce"
    $checksumPartial = "$ChecksumPath.part.$nonce"
    try {
        Invoke-WebRequest -Uri $ChecksumUri -OutFile $checksumPartial -ErrorAction Stop
        Invoke-WebRequest -Uri $PayloadUri -OutFile $payloadPartial -ErrorAction Stop
        $expected = Get-AtlasoExpectedChecksum -Path $checksumPartial -HexLength $hexLength
        $actual = (& $GetFileHash $payloadPartial).ToUpperInvariant()
        if ($expected -ne $actual) {
            throw "Checksum mismatch for downloaded payload. Expected $expected, got $actual."
        }

        Move-Item -LiteralPath $payloadPartial -Destination $PayloadPath -Force -ErrorAction Stop
        Move-Item -LiteralPath $checksumPartial -Destination $ChecksumPath -Force -ErrorAction Stop

        $persistedExpected = Get-AtlasoExpectedChecksum -Path $ChecksumPath -HexLength $hexLength
        $persistedActual = (& $GetFileHash $PayloadPath).ToUpperInvariant()
        if ($persistedExpected -ne $persistedActual) {
            throw "Promoted cache pair failed checksum verification: $PayloadPath"
        }
        Write-Host "$Algorithm verified: $([System.IO.Path]::GetFileName($PayloadPath))"
        return $persistedActual
    } finally {
        foreach ($partialPath in @($payloadPartial, $checksumPartial)) {
            if (Test-Path -LiteralPath $partialPath) {
                Remove-Item -LiteralPath $partialPath -Force -ErrorAction Stop
            }
        }
    }
}

Export-ModuleMember -Function 'Save-AtlasoVerifiedDownloadPair'
