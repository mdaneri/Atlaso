[CmdletBinding()]
param(
    [string]$InstallLocation = '',
    [string]$BaseImagePath = '',
    [string]$RepositoryRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
}
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WslBuild.psm1') -Force

$contract = Get-AtlasoWslBuildContract -RepositoryRoot $RepositoryRoot
$distribution = [string]$contract.distribution_name
$buildUser = [string]$contract.build_user

if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [System.Runtime.InteropServices.Architecture]::X64) {
    throw 'The pinned Atlaso-Build distribution currently supports AMD64 Windows hosts only.'
}

$wsl = Assert-AtlasoWslAvailable
$existingDistributions = @(Get-AtlasoWslDistributions)
$distributionExists = $existingDistributions | Where-Object {
    $_.Equals($distribution, [System.StringComparison]::OrdinalIgnoreCase)
} | Select-Object -First 1

if ([string]::IsNullOrWhiteSpace($InstallLocation)) {
    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($localAppData)) {
        throw 'Atlaso could not resolve the current user LocalApplicationData directory. Pass -InstallLocation explicitly.'
    }
    $InstallLocation = Join-Path $localAppData 'Atlaso\WSL\Atlaso-Build'
}
$InstallLocation = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallLocation)

if (-not $distributionExists) {
    if (Test-Path -LiteralPath $InstallLocation) {
        $existingItems = @(Get-ChildItem -LiteralPath $InstallLocation -Force -ErrorAction Stop)
        if ($existingItems.Count -gt 0) {
            throw "Atlaso-Build is not registered, but its install location is not empty: $InstallLocation. Move or inspect that directory before retrying."
        }
    }

    if ([string]::IsNullOrWhiteSpace($BaseImagePath)) {
        $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if ([string]::IsNullOrWhiteSpace($localAppData)) {
            throw 'Atlaso could not resolve a user-local download cache. Pass -BaseImagePath with the pinned Ubuntu Base image.'
        }
        $downloadDirectory = Join-Path $localAppData 'Atlaso\Downloads'
        New-Item -ItemType Directory -Path $downloadDirectory -Force | Out-Null
        $BaseImagePath = Join-Path $downloadDirectory ([string]$contract.base.filename)
        if (-not (Test-Path -LiteralPath $BaseImagePath -PathType Leaf)) {
            $partialPath = "$BaseImagePath.partial.$PID"
            try {
                Write-Host "Downloading pinned $($contract.base.name) image."
                Invoke-WebRequest -Uri ([string]$contract.base.url) -OutFile $partialPath
                $partialHash = (Get-FileHash -LiteralPath $partialPath -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($partialHash -ne [string]$contract.base.sha256) {
                    throw "Downloaded Atlaso-Build base image digest mismatch. Expected $($contract.base.sha256); got $partialHash."
                }
                Move-Item -LiteralPath $partialPath -Destination $BaseImagePath
            } finally {
                if (Test-Path -LiteralPath $partialPath -PathType Leaf) {
                    Remove-Item -LiteralPath $partialPath -Force
                }
            }
        }
    }

    $BaseImagePath = (Resolve-Path -LiteralPath $BaseImagePath).Path
    $baseHash = (Get-FileHash -LiteralPath $BaseImagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($baseHash -ne [string]$contract.base.sha256) {
        throw "Atlaso-Build base image digest mismatch. Expected $($contract.base.sha256); got $baseHash."
    }

    $installParent = Split-Path -Parent $InstallLocation
    New-Item -ItemType Directory -Path $installParent -Force | Out-Null
    $defaultBefore = Get-AtlasoWslDefaultDistribution
    if ($existingDistributions.Count -gt 0 -and [string]::IsNullOrWhiteSpace($defaultBefore)) {
        throw 'WSL has installed distributions but no default could be identified. Set a default explicitly, then rerun setup.'
    }

    $importArchivePath = Join-Path ([System.IO.Path]::GetTempPath()) "$PID-$($contract.base.import_filename)"
    $sourceStream = $null
    $gzipStream = $null
    $targetStream = $null
    try {
        try {
            $sourceStream = [System.IO.File]::OpenRead($BaseImagePath)
            $gzipStream = [System.IO.Compression.GZipStream]::new(
                $sourceStream,
                [System.IO.Compression.CompressionMode]::Decompress
            )
            $targetStream = [System.IO.File]::Create($importArchivePath)
            $gzipStream.CopyTo($targetStream)
        } finally {
            if ($targetStream) {
                $targetStream.Dispose()
            }
            if ($gzipStream) {
                $gzipStream.Dispose()
            }
            if ($sourceStream) {
                $sourceStream.Dispose()
            }
        }

        Write-Host "Importing $distribution under $InstallLocation."
        & $wsl --import $distribution $InstallLocation $importArchivePath --version 2
        if ($LASTEXITCODE -ne 0) {
            throw "WSL could not import $distribution. Atlaso did not enable Windows features, elevate, reboot, or run wsl --install."
        }
    } finally {
        if (Test-Path -LiteralPath $importArchivePath -PathType Leaf) {
            Remove-Item -LiteralPath $importArchivePath -Force
        }
    }

    $ownershipScript = @'
set -eu
umask 022
install -d -o root -g root -m 0755 /var/lib/atlaso-build
printf '{"schema_version":1,"base_sha256":"%s","distribution_name":"%s"}\n' "$1" "$2" > /var/lib/atlaso-build/ownership.json
'@
    Invoke-AtlasoWslCapture `
        -Distribution $distribution `
        -User 'root' `
        -Arguments @('sh', '-c', $ownershipScript, 'atlaso-wsl-ownership', [string]$contract.base.sha256, $distribution) `
        -FailureMessage "Atlaso-Build was imported but its ownership marker could not be written. Inspect '$InstallLocation' before retrying." | Out-Null

    if (-not [string]::IsNullOrWhiteSpace($defaultBefore)) {
        $defaultAfter = Get-AtlasoWslDefaultDistribution
        if (-not $defaultAfter.Equals($defaultBefore, [System.StringComparison]::OrdinalIgnoreCase)) {
            & $wsl --set-default $defaultBefore
            if ($LASTEXITCODE -ne 0) {
                throw "Atlaso-Build was imported, but WSL could not restore the previous default distribution '$defaultBefore'. Restore it with: wsl --set-default $defaultBefore"
            }
        }
    }
} else {
    $ownershipText = Invoke-AtlasoWslCapture `
        -Distribution $distribution `
        -User 'root' `
        -Arguments @('cat', '/var/lib/atlaso-build/ownership.json') `
        -FailureMessage "A distribution named '$distribution' already exists without an Atlaso ownership marker. Atlaso will not modify it."
    try {
        $ownership = $ownershipText | ConvertFrom-Json
    } catch {
        throw "The existing $distribution ownership marker is invalid. Atlaso will not modify the distribution."
    }
    if ([string]$ownership.distribution_name -ne $distribution -or [string]$ownership.base_sha256 -ne [string]$contract.base.sha256) {
        throw "The existing $distribution uses a different ownership or base-image contract. Export anything needed, unregister it manually, and rerun setup."
    }
}

$provisionScript = Join-Path $RepositoryRoot 'image\inventory-linux\provision-wsl-build-host.sh'
if (-not (Test-Path -LiteralPath $provisionScript -PathType Leaf)) {
    throw "Atlaso WSL provisioning script was not found: $provisionScript"
}
$linuxProvisionScript = Invoke-AtlasoWslCapture `
    -Distribution $distribution `
    -User 'root' `
    -Arguments @('wslpath', '-a', ($provisionScript -replace '\\', '/')) `
    -FailureMessage 'WSL could not resolve the Atlaso-Build provisioning script path.'

$provisionArguments = @(
    'bash',
    $linuxProvisionScript,
    [string]$contract.contract_version,
    [string]$contract.base.sha256,
    $buildUser
)
$provisionArguments += @($contract.packages | ForEach-Object { [string]$_ })
Invoke-AtlasoWslCapture `
    -Distribution $distribution `
    -User 'root' `
    -Arguments $provisionArguments `
    -FailureMessage "Atlaso-Build provisioning failed. The imported distribution was preserved; rerun this command after correcting the reported problem." | Out-Host

$environment = Assert-AtlasoWslBuildEnvironment -Contract $contract -Distribution $distribution
Write-Host "Atlaso-Build is ready. Native Inventory Linux cache: $($environment.CacheRoot)"
