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

$modulePath = Join-Path $RepositoryRoot 'scripts/windows/common/Atlaso.PhotonImage.psm1'
$module = Import-Module $modulePath -Force -PassThru
$emptyCleanupLedgerRoot = Join-Path $OutputDirectory 'empty-cleanup-ledger'
New-Item -ItemType Directory -Force -Path $emptyCleanupLedgerRoot | Out-Null
$emptyCleanupLedger = [System.Collections.Generic.List[string]]::new()
$fixtureScript = Join-Path $emptyCleanupLedgerRoot 'create-fixture.py'
$fixtureSourceIso = Join-Path $emptyCleanupLedgerRoot 'source.iso'
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
if ($emptyCleanupLedger.Count -ne 2 -or
    -not $emptyCleanupLedger[0].StartsWith($emptyCleanupLedgerRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    $emptyCleanupLedger[1] -cne $fixtureOutputIso -or
    -not (Test-Path -LiteralPath $fixtureOutputIso -PathType Leaf)) {
    throw 'Fresh remastering did not promote its ISO through the initially empty cleanup ledger.'
}
$emptyCleanupLedger | ForEach-Object {
    if (Test-Path -LiteralPath $_) {
        Remove-Item -LiteralPath $_ -Force
    }
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
