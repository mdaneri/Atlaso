<#
.SYNOPSIS
Verify canonical Atlaso Photon kickstart generation.
.PARAMETER RepositoryRoot
Atlaso repository root.
.PARAMETER OutputDirectory
Isolated test-output directory.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Create a read-only SecureString from a non-secret test fixture.
.PARAMETER Value
Fixture text appended one character at a time.
#>
function ConvertTo-TestSecureString {
    param([Parameter(Mandatory = $true)][string]$Value)

    $secureValue = [SecureString]::new()
    foreach ($character in $Value.ToCharArray()) {
        $secureValue.AppendChar($character)
    }
    $secureValue.MakeReadOnly()
    return $secureValue
}

<#
.SYNOPSIS
Validate one non-secret retained-handle Packer fixture with a bounded child.
.PARAMETER PackerPath
Exact Packer executable path.
.PARAMETER VarFile
Pinned HCL variable file consumed by the fixture.
.PARAMETER Template
HCL template consumed by the fixture.
#>
function Invoke-PackerValidateFixture {
    param(
        [Parameter(Mandatory = $true)][string]$PackerPath,
        [Parameter(Mandatory = $true)][string]$VarFile,
        [Parameter(Mandatory = $true)][string]$Template
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PackerPath
    $startInfo.ArgumentList.Add('validate')
    $startInfo.ArgumentList.Add('-syntax-only')
    $startInfo.ArgumentList.Add("-var-file=$VarFile")
    $startInfo.ArgumentList.Add($Template)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'Packer validation fixture did not start.'
        }
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'Packer validation fixture exceeded its 30-second deadline.'
        }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output   = $process.StandardOutput.ReadToEnd()
            Error    = $process.StandardError.ReadToEnd()
        }
    }
    finally {
        $process.Dispose()
    }
}

$modulePath = Join-Path $RepositoryRoot 'scripts/windows/common/Atlaso.PhotonImage.psm1'
$module = Import-Module $modulePath -Force -PassThru
$emptyCleanupLedgerRoot = Join-Path $OutputDirectory 'empty-cleanup-ledger'
New-Item -ItemType Directory -Force -Path $emptyCleanupLedgerRoot | Out-Null
$identitySource = Join-Path $emptyCleanupLedgerRoot 'identity-source.txt'
$identityReplacement = Join-Path $emptyCleanupLedgerRoot 'identity-replacement.txt'
& $module {
    param([string]$Source, [string]$Replacement)
    Initialize-AtlasoPhotonPinnedFileType
    $writer = [Atlaso.PhotonPinnedFile]::Create($Source)
    [Atlaso.PhotonPinnedFile]::WriteUtf8($writer, 'source')
    $pin = [Atlaso.PhotonPinnedFile]::PinForReadConsumers($writer)
    $writer.Dispose()
    $replacementWriter = [Atlaso.PhotonPinnedFile]::Create($Replacement)
    [Atlaso.PhotonPinnedFile]::WriteUtf8($replacementWriter, 'replacement')
    $replacementWriter.Dispose()
    try {
        [Atlaso.PhotonPinnedFile]::DeleteExact($pin, $Replacement)
        throw 'Exact cleanup accepted a different filesystem identity.'
    }
    catch {
        if ($_.Exception.Message -notmatch 'Pinned plaintext identity changed before exact cleanup') {
            throw
        }
    }
    finally {
        $pin.Dispose()
    }
} $identitySource $identityReplacement
if (-not (Test-Path -LiteralPath $identitySource -PathType Leaf) -or
    -not (Test-Path -LiteralPath $identityReplacement -PathType Leaf)) {
    throw 'Exact cleanup modified an identity-mismatch fixture.'
}
Remove-Item -LiteralPath $identitySource, $identityReplacement -Force
$emptyCleanupLedger = [System.Collections.Generic.List[string]]::new()
$fixtureScript = Join-Path $emptyCleanupLedgerRoot 'create-fixture.py'
$fixtureSourceIso = Join-Path $emptyCleanupLedgerRoot 'source iso.iso'
$fixtureKickstart = Join-Path $emptyCleanupLedgerRoot 'photon-ks.json'
$fixtureOutputIso = Join-Path $emptyCleanupLedgerRoot 'prepared.iso'
[System.IO.File]::WriteAllText($fixtureKickstart, '{}')
[System.IO.File]::WriteAllText(
    $fixtureScript,
    @'
import io
import sys
import pycdlib

iso = pycdlib.PyCdlib()
iso.new(interchange_level=3, rock_ridge="1.09")
iso.add_directory("/BOOT", rr_name="boot")
iso.add_directory("/BOOT/GRUB2", rr_name="grub2")
payload = b"set default=0\n"
iso.add_fp(io.BytesIO(payload), len(payload), iso_path="/BOOT/GRUB2/GRUB.CFG;1", rr_name="grub.cfg")
iso.write(sys.argv[1])
iso.close()
'@
)
$pythonPath = (Get-Command python -ErrorAction Stop).Source
& $pythonPath $fixtureScript $fixtureSourceIso
if ($LASTEXITCODE -ne 0) {
    throw 'Could not create the remaster source ISO fixture.'
}
$fixtureSourceChecksum = "sha512:$((Get-FileHash -LiteralPath $fixtureSourceIso -Algorithm SHA512).Hash.ToLowerInvariant())"
$fixtureSourceUri = ([Uri](Resolve-Path -LiteralPath $fixtureSourceIso).Path).AbsoluteUri
$resolvedFixtureSource = & $module {
    param(
        [string]$UrlOrPath,
        [string]$Checksum,
        [string]$BuildDirectory,
        [string]$PackerDirectory,
        [string]$SharedSourceDirectory
    )
    Resolve-AtlasoPhotonSourceIso `
        -UrlOrPath $UrlOrPath `
        -Checksum $Checksum `
        -BuildDirectory $BuildDirectory `
        -PackerDirectory $PackerDirectory `
        -SharedSourceDirectory $SharedSourceDirectory
} $fixtureSourceUri $fixtureSourceChecksum $emptyCleanupLedgerRoot $emptyCleanupLedgerRoot $emptyCleanupLedgerRoot
$expectedFixtureSource = (Resolve-Path -LiteralPath $fixtureSourceIso).Path
if ($resolvedFixtureSource -cne $expectedFixtureSource) {
    throw "Local file URI did not resolve to the expected ISO path: $resolvedFixtureSource"
}
$missingFixtureUri = ([Uri](Join-Path $emptyCleanupLedgerRoot 'missing source.iso')).AbsoluteUri
try {
    & $module {
        param(
            [string]$UrlOrPath,
            [string]$Checksum,
            [string]$BuildDirectory,
            [string]$PackerDirectory,
            [string]$SharedSourceDirectory
        )
        Resolve-AtlasoPhotonSourceIso `
            -UrlOrPath $UrlOrPath `
            -Checksum $Checksum `
            -BuildDirectory $BuildDirectory `
            -PackerDirectory $PackerDirectory `
            -SharedSourceDirectory $SharedSourceDirectory
    } $missingFixtureUri $fixtureSourceChecksum $emptyCleanupLedgerRoot $emptyCleanupLedgerRoot $emptyCleanupLedgerRoot
    throw 'Missing local file URI unexpectedly reached cache discovery or download.'
}
catch {
    if ($_.Exception.Message -notlike 'IsoUrl file URI does not reference an existing local file:*') {
        throw
    }
}
$hostAuthorityFixtureUri = 'file://example.invalid/share/source.iso'
try {
    & $module {
        param(
            [string]$UrlOrPath,
            [string]$Checksum,
            [string]$BuildDirectory,
            [string]$PackerDirectory,
            [string]$SharedSourceDirectory
        )
        Resolve-AtlasoPhotonSourceIso `
            -UrlOrPath $UrlOrPath `
            -Checksum $Checksum `
            -BuildDirectory $BuildDirectory `
            -PackerDirectory $PackerDirectory `
            -SharedSourceDirectory $SharedSourceDirectory
    } $hostAuthorityFixtureUri $fixtureSourceChecksum $emptyCleanupLedgerRoot $emptyCleanupLedgerRoot $emptyCleanupLedgerRoot
    throw 'Host-authority file URI unexpectedly reached cache discovery or download.'
}
catch {
    if ($_.Exception.Message -notlike 'IsoUrl file URI must use an empty authority and reference a local file:*') {
        throw
    }
}
& $module {
    param(
        [string]$SourceIso,
        [string]$KickstartJson,
        [string]$OutputIso,
        [System.Collections.Generic.List[string]]$CleanupPaths
    )
    New-AtlasoRemasteredPhotonIso `
        -SourceIso $SourceIso `
        -KickstartJson $KickstartJson `
        -OutputIso $OutputIso `
        -CleanupPaths $CleanupPaths
} $fixtureSourceIso $fixtureKickstart $fixtureOutputIso $emptyCleanupLedger
if ($emptyCleanupLedger.Count -ne 1 -or
    $emptyCleanupLedger[0] -cne $fixtureOutputIso -or
    -not (Test-Path -LiteralPath $fixtureOutputIso -PathType Leaf)) {
    throw 'Fresh remastering did not retire its partial path after final-ISO promotion.'
}
$emptyCleanupLedger | ForEach-Object {
    if (Test-Path -LiteralPath $_) {
        Remove-Item -LiteralPath $_ -Force
    }
}
$pinnedFixtureKickstart = Join-Path $emptyCleanupLedgerRoot 'pinned-photon-ks.json'
$pinnedFixtureOutputIso = Join-Path $emptyCleanupLedgerRoot 'pinned-prepared.iso'
$pinnedFixtureHandles = @{}
$pinnedFixtureCleanup = [System.Collections.Generic.List[string]]::new()
& $module {
    param([string]$Path, [hashtable]$PinnedHandles)
    Write-AtlasoPinnedUtf8Text -Path $Path -Text '{}' -PinnedHandles $PinnedHandles
} $pinnedFixtureKickstart $pinnedFixtureHandles
& $module {
    param(
        [string]$SourceIso,
        [string]$KickstartJson,
        [string]$OutputIso,
        [System.Collections.Generic.List[string]]$CleanupPaths,
        [hashtable]$PinnedHandles
    )
    New-AtlasoRemasteredPhotonIso `
        -SourceIso $SourceIso `
        -KickstartJson $KickstartJson `
        -OutputIso $OutputIso `
        -CleanupPaths $CleanupPaths `
        -PinnedHandles $PinnedHandles
} $fixtureSourceIso $pinnedFixtureKickstart $pinnedFixtureOutputIso $pinnedFixtureCleanup $pinnedFixtureHandles
if (-not (Test-Path -LiteralPath $pinnedFixtureOutputIso -PathType Leaf)) {
    throw 'Remastering could not consume the kickstart through its retained no-delete handle.'
}
$pinnedFixtureDigest = & $module {
    param([string]$Path)
    Get-AtlasoFileHashHex -Path $Path -Algorithm SHA512
} $pinnedFixtureOutputIso
if ($pinnedFixtureDigest -notmatch '^[0-9a-f]{128}$') {
    throw 'Atlaso could not hash the retained-handle remastered ISO through a compatible Windows reader.'
}
$packerCommand = Get-Command packer -ErrorAction SilentlyContinue
if ($null -ne $packerCommand) {
    $pinnedPackerVarPath = Join-Path $emptyCleanupLedgerRoot 'pinned-reader.auto.pkrvars.hcl'
    $pinnedPackerTemplate = Join-Path $emptyCleanupLedgerRoot 'pinned-reader.pkr.hcl'
    & $module {
        param([string]$Path, [hashtable]$PinnedHandles)
        Write-AtlasoPinnedUtf8Text `
            -Path $Path `
            -Text 'test_value = "pinned-reader-ok"' `
            -PinnedHandles $PinnedHandles
    } $pinnedPackerVarPath $pinnedFixtureHandles
    [System.IO.File]::WriteAllText(
        $pinnedPackerTemplate,
        @"
variable "test_value" {
  type = string
}
"@
    )
    $packerVarResult = Invoke-PackerValidateFixture `
        -PackerPath $packerCommand.Source `
        -VarFile $pinnedPackerVarPath `
        -Template $pinnedPackerTemplate
    if ($packerVarResult.ExitCode -ne 0 -or $packerVarResult.Output -notmatch 'Syntax-only check passed') {
        $packerVarDetail = (($packerVarResult.Error + ' ' + $packerVarResult.Output) -replace '[\r\n]+', ' ').Trim()
        throw "Packer could not read the retained-handle variable file: $packerVarDetail"
    }
    & $module {
        param([string]$Path, [hashtable]$PinnedHandles)
        Remove-AtlasoPinnedPlaintextFile -Path $Path -PinnedHandles $PinnedHandles
    } $pinnedPackerVarPath $pinnedFixtureHandles
    Remove-Item -LiteralPath $pinnedPackerTemplate -Force
}
& $module {
    param([string]$Path, [hashtable]$PinnedHandles)
    Remove-AtlasoPinnedPlaintextFile -Path $Path -PinnedHandles $PinnedHandles
} $pinnedFixtureOutputIso $pinnedFixtureHandles
& $module {
    param([string]$Path, [hashtable]$PinnedHandles)
    Remove-AtlasoPinnedPlaintextFile -Path $Path -PinnedHandles $PinnedHandles
} $pinnedFixtureKickstart $pinnedFixtureHandles
if ($pinnedFixtureHandles.Count -ne 0 -or
    (Test-Path -LiteralPath $pinnedFixtureOutputIso) -or
    (Test-Path -LiteralPath $pinnedFixtureKickstart)) {
    throw 'Pinned remaster fixture cleanup did not delete the exact credential-bearing objects.'
}
$longFallbackSource = Join-Path $emptyCleanupLedgerRoot 'atlaso-photon-with-kickstart.iso'
$shortFallbackPath = & $module {
    param([string]$Path)
    New-AtlasoFallbackPreparedIsoPath -Path $Path
} $longFallbackSource
if ((Split-Path -Parent $shortFallbackPath) -cne (Split-Path -Parent $longFallbackSource) -or
    [System.IO.Path]::GetExtension($shortFallbackPath) -cne '.iso' -or
    [System.IO.Path]::GetFileName($shortFallbackPath).Length -ge
    [System.IO.Path]::GetFileName($longFallbackSource).Length) {
    throw 'Prepared-ISO fallback did not retain its parent and extension with a shorter collision-resistant leaf.'
}
$rejectedPreparedIsoPath = Join-Path $OutputDirectory 'rejected-credential-bearing.iso'
$rejectedSecurePassword = ConvertTo-TestSecureString -Value 'non-secret-test-credential'
try {
    Invoke-AtlasoPhotonImageBuild `
        -IsoUrl 'unused-for-rejected-iso-only-mode' `
        -IsoChecksum 'none' `
        -PackerDirectory (Join-Path $RepositoryRoot 'image\vmware-workstation') `
        -SshPassword $rejectedSecurePassword `
        -BuilderStaticIp '' `
        -PreparedIsoPath $rejectedPreparedIsoPath `
        -PrepareIsoOnly
    throw 'PrepareIsoOnly unexpectedly retained a credential-bearing remastered ISO.'
}
catch {
    if ($_.Exception.Message -notlike 'PrepareIsoOnly is not supported because a retained remastered ISO*') {
        throw
    }
}
if (Test-Path -LiteralPath $rejectedPreparedIsoPath) {
    throw 'Rejected ISO-only preparation created a credential-bearing artifact.'
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$preservedPreparedIsoPath = Join-Path $OutputDirectory 'caller-owned-prepared.iso'
$preservedPreparedIsoBytes = [System.Text.UTF8Encoding]::new($false).GetBytes('caller-owned-iso-fixture')
[System.IO.File]::WriteAllBytes($preservedPreparedIsoPath, $preservedPreparedIsoBytes)
try {
    Invoke-AtlasoPhotonImageBuild `
        -IsoUrl (Join-Path $OutputDirectory 'missing-source.iso') `
        -IsoChecksum 'sha512:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' `
        -PackerDirectory (Join-Path $RepositoryRoot 'image\vmware-workstation') `
        -SshPassword $rejectedSecurePassword `
        -BuilderStaticIp '' `
        -PreparedIsoPath $preservedPreparedIsoPath `
        -ValidateOnly
    throw 'Missing source ISO unexpectedly reached Photon remastering.'
}
catch {
    if ($_.Exception.Message -eq 'Missing source ISO unexpectedly reached Photon remastering.') {
        throw
    }
}
if (-not (Test-Path -LiteralPath $preservedPreparedIsoPath -PathType Leaf)) {
    throw 'Pre-remaster failure deleted the caller-owned prepared ISO.'
}
$actualPreservedPreparedIsoBytes = [System.IO.File]::ReadAllBytes($preservedPreparedIsoPath)
if (-not [System.Linq.Enumerable]::SequenceEqual[byte]($actualPreservedPreparedIsoBytes, $preservedPreparedIsoBytes)) {
    throw 'Pre-remaster failure modified the caller-owned prepared ISO.'
}
Remove-Item -LiteralPath $preservedPreparedIsoPath -Force

$sensitiveArtifactRoot = Join-Path $OutputDirectory 'sensitive-artifact-cleanup'
New-Item -ItemType Directory -Force -Path $sensitiveArtifactRoot | Out-Null
[System.IO.File]::WriteAllText(
    (Join-Path $sensitiveArtifactRoot 'credential.txt'),
    'non-secret-test-credential'
)
& $module {
    param([string]$Path)
    Remove-AtlasoSensitiveBuildArtifact -Path $Path
} $sensitiveArtifactRoot
if (Test-Path -LiteralPath $sensitiveArtifactRoot) {
    throw 'Sensitive Photon build artifact cleanup did not prove directory absence.'
}

$providers = @(
    [pscustomobject]@{
        Name                = 'vmware-workstation'
        InstallDiskLayout   = 'vmware-workstation'
        AdditionalPackages  = @('open-vm-tools', 'hyper-v')
        PostInstallCommands = @(
            'systemctl enable vmtoolsd || true',
            'systemctl enable hv_kvp_daemon || true',
            'systemctl enable hv_fcopy_daemon || true',
            'systemctl enable hv_vss_daemon || true'
        )
    }
)
$passwords = @(
    [string]::Concat('quote', [char]39, 'break'),
    [string]::Concat(
        'meta',
        [char]36,
        [char]40,
        'value',
        [char]41,
        [char]59,
        [char]38,
        [char]124,
        [char]60,
        [char]62,
        [char]34,
        [char]92,
        [char]96,
        'end'
    )
)

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
foreach ($provider in $providers) {
    foreach ($password in $passwords) {
        $path = Join-Path $OutputDirectory "$($provider.Name)-kickstart.json"
        $securePassword = ConvertTo-TestSecureString -Value $password
        & $module {
            param($KickstartPath, [SecureString]$Secret, $AdditionalPackages, $PostInstallCommands, $InstallDiskLayout)
            New-AtlasoPhotonKickstart `
                -Path $KickstartPath `
                -RootPassword $Secret `
                -BuildPassword $Secret `
                -BuildUsername 'atlaso-build' `
                -AdditionalPackages $AdditionalPackages `
                -PostInstallCommands $PostInstallCommands `
                -InstallDiskLayout $InstallDiskLayout
        } $path $securePassword $provider.AdditionalPackages $provider.PostInstallCommands $provider.InstallDiskLayout

        $kickstart = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        if ($kickstart.password.text -cne $password) {
            throw 'Photon kickstart did not preserve the root password exactly.'
        }
        if ($provider.Name -eq 'vmware-workstation') {
            if ($kickstart.disk -cne '$ATLASO_PHOTON_INSTALL_DISK') {
                throw 'VMware Photon kickstart does not bind installation through its topology-selected disk.'
            }
            $preInstall = @($kickstart.preinstall)
            if (($preInstall -join "`n") -notmatch 'scsi-0:0:0:0' -or
                ($preInstall -join "`n") -notmatch 'disk_count.*-ne 1') {
                throw 'VMware Photon kickstart does not fail closed on SCSI unit 0 discovery.'
            }
            if (($preInstall -join "`n") -match '/dev/sd[a-z]') {
                throw 'VMware Photon kickstart must not select its install disk by enumerated sdX name.'
            }
        }
        elseif ($kickstart.disk -cne '/dev/sda' -or @($kickstart.preinstall).Count -ne 0) {
            throw 'The default Photon kickstart disk contract changed unexpectedly.'
        }

        $postInstall = @($kickstart.postinstall)
        if (($postInstall -join "`n").Contains($password)) {
            throw 'Photon post-install commands contain the raw build password.'
        }

        $credentialCommand = @(
            $postInstall | Where-Object { $_ -like "*base64 -d | chpasswd" }
        )
        if ($credentialCommand.Count -ne 1) {
            throw 'Photon kickstart must contain exactly one encoded chpasswd command.'
        }

        $match = [regex]::Match(
            [string]$credentialCommand[0],
            "^printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d \| chpasswd$"
        )
        if (-not $match.Success) {
            throw 'Photon chpasswd command does not use the bounded Base64 stdin contract.'
        }

        $actualBytes = [System.Convert]::FromBase64String($match.Groups[1].Value)
        $expectedBytes = [System.Text.UTF8Encoding]::new($false).GetBytes("atlaso-build:$password`n")
        if (-not [System.Linq.Enumerable]::SequenceEqual[byte]($actualBytes, $expectedBytes)) {
            throw 'Photon chpasswd input did not preserve the original credential bytes.'
        }

        if (Get-Command bash -ErrorAction SilentlyContinue) {
            ($postInstall -join "`n") | & bash -n - 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw 'Photon post-install shell failed syntax validation.'
            }
        }
    }
}

Write-Output 'Atlaso Photon kickstart generator contract tests passed.'
