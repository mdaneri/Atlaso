<#
.SYNOPSIS
Exercise Hyper-V generated-path admission and failure preservation without a hypervisor.
.PARAMETER RepositoryRoot
Atlaso checkout containing the importer and smoke scripts.
#>
[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$fixtureRoot = Join-Path $RepositoryRoot ('test-results/hv-' + [guid]::NewGuid().ToString('N'))
$smokeOutput = Join-Path $RepositoryRoot ('artifacts/virtualization-smoke/test-' + [guid]::NewGuid().ToString('N'))
$package = Join-Path $fixtureRoot 'p'
New-Item -ItemType Directory -Path $package | Out-Null
$HyperVFixture = @{ NewVmCalls = 0; AddUnknownFile = $false; ObservedPath = ''; FreeBytes = 1TB }

<#
.SYNOPSIS
Supply deterministic capacity without querying or changing host storage.
.PARAMETER FilePath
Existing destination ancestor queried by storage admission.
#>
$previousGlobalVolume = Get-Item Function:global:Get-Volume -ErrorAction SilentlyContinue
$volumeFixture = {
    [CmdletBinding()] param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { throw 'Capacity queried a nonexistent ancestor.' }
    [pscustomobject]@{ UniqueId='fixture-volume'; SizeRemaining=$HyperVFixture.FreeBytes }
}.GetNewClosure()
# Imported modules resolve commands in the global session, not this test script's
# scope. Bind the shared mutable fixture explicitly so admission never reads the
# runner's real free space, regardless of which tests imported the module first.
Set-Item Function:global:Get-Volume -Value $volumeFixture

<#
.SYNOPSIS
Return an empty provider inventory without querying host resources.
#>
function Get-VM { [CmdletBinding()] param() }
<#
.SYNOPSIS
Resolve one simulated existing switch.
.PARAMETER Name
Requested switch name.
#>
function Get-VMSwitch { [CmdletBinding()] param([string]$Name) [pscustomobject]@{ Name = $Name } }
<#
.SYNOPSIS
Supply deterministic file identities on Windows and Linux test hosts.
.PARAMETER Operation
Expected file operation.
.PARAMETER Verb
Expected identity query.
.PARAMETER Path
Ordinary fixture path.
#>
function fsutil {
    param([string]$Operation, [string]$Verb, [string]$Path)
    if ($Operation -ne 'file' -or $Verb -ne 'queryfileid' -or -not (Test-Path -LiteralPath $Path)) {
        throw 'Unexpected fixture identity query.'
    }
    $global:LASTEXITCODE = 0
    '0x' + [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Path)))
}
<#
.SYNOPSIS
Inspect the simulated disk capacity recorded in its small fixture payload.
.PARAMETER Path
Copied fixture disk path.
#>
function Get-VHD {
    [CmdletBinding()]
    param([string]$Path)
    [pscustomobject]@{ VhdFormat = 'VHDX'; VhdType = 'Dynamic'; Size = [long](Get-Content -LiteralPath $Path) }
}
<#
.SYNOPSIS
Fail provider creation after recording the actual selected layout.
.PARAMETER Name
Requested VM name.
.PARAMETER Generation
Requested generation.
.PARAMETER NoVHD
Accept the no-default-disk switch.
.PARAMETER Path
Provider parent directory selected by the importer.
.PARAMETER MemoryStartupBytes
Requested memory.
.PARAMETER SwitchName
Requested management switch.
#>
function New-VM {
    [CmdletBinding()]
    param([string]$Name, [int]$Generation, [switch]$NoVHD, [string]$Path,
        [long]$MemoryStartupBytes, [string]$SwitchName)
    if ($Generation -ne 2 -or -not $NoVHD -or $MemoryStartupBytes -ne 4GB -or $SwitchName -ne 'Management') {
        throw 'Unexpected provider parameters.'
    }
    $HyperVFixture.NewVmCalls++
    $HyperVFixture.ObservedPath = $Path
    if ($HyperVFixture.AddUnknownFile) { Set-Content -LiteralPath (Join-Path (Join-Path $Path $Name) 'unknown') -Value 'preserve' }
    throw 'Original provider failure: Smart Paging 0x800700CE'
}
<#
.SYNOPSIS
Require a failure diagnostic and return its complete error record.
.PARAMETER Action
Action expected to fail.
.PARAMETER Pattern
Expected wildcard diagnostic.
#>
function Assert-HyperVFailure {
    param([scriptblock]$Action, [string]$Pattern)
    try { & $Action }
    catch {
        if ($_.Exception.Message -notlike $Pattern) { throw }
        return $_
    }
    throw "Expected failure matching $Pattern"
}

try {
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'scripts/windows/virtualization/templates/Import-Atlaso.ps1') -Destination $package
    $roles = @('photon_os', 'atlaso_system', 'vcf_offline_depot', 'vcf_backups')
    $sizes = @(42949672960, 21474836480, 536870912000, 536870912000)
    $disks = @(for ($i = 0; $i -lt 4; $i++) {
        $path = Join-Path $package "disk$i.vhdx"
        Set-Content -LiteralPath $path -Value $sizes[$i]
        @{ file = "disk$i.vhdx"; role = $roles[$i]; scsi_slot = $i; format = 'vhdx';
            virtual_size_bytes = $sizes[$i]; bytes = (Get-Item -LiteralPath $path).Length;
            sha256 = (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() }
    })
    @{
        schema_version = 1; kind = 'atlaso-hyperv-artifact'; product_version = '0.9.319'
        source = @{ kind = 'atlaso-validated-ova'; commit = 'a' * 40; ova_sha256 = 'b' * 64; ova_validator = 1 }
        machine = @{ firmware = 'uefi'; secure_boot = $false; cpu_count = 4; memory_mib = 4096; nic_count = 2; disk_bus = 'scsi' }
        disks = $disks
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $package 'manifest.json')
    Get-ChildItem -LiteralPath $package -File | ForEach-Object {
        (Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant() + '  ' + $_.Name
    } | Set-Content -LiteralPath (Join-Path $package 'checksums.sha256')
    $importer = Join-Path $package 'Import-Atlaso.ps1'
    $name = 'Boundary'
    $HyperVFixture.FreeBytes = 1GB
    $lowSpaceRoot = Join-Path $fixtureRoot 'low-space'
    Assert-HyperVFailure {
        & $importer -Name $name -ManagementSwitch Management -DestinationRoot $lowSpaceRoot
    } '*Insufficient Hyper-V destination capacity*' | Out-Null
    if ($HyperVFixture.NewVmCalls -ne 0 -or (Test-Path -LiteralPath $lowSpaceRoot)) {
        throw 'Low-space importer admission created files or called the provider.'
    }
    $HyperVFixture.FreeBytes = 1TB
    # Root + separator + 64-character provider reserve is exactly 240.
    $parent = Join-Path $fixtureRoot ('x' * (175 - $fixtureRoot.Length - $name.Length - 2))
    Assert-HyperVFailure { & $importer -Name $name -ManagementSwitch Management -DestinationRoot $parent } '*Original provider failure*' | Out-Null
    if ($HyperVFixture.NewVmCalls -ne 1 -or $HyperVFixture.ObservedPath -ne $parent -or (Test-Path -LiteralPath (Join-Path $parent $name))) {
        throw 'The exact boundary did not use one VM directory or safely clean its copied disks.'
    }
    Assert-HyperVFailure { & $importer -Name $name -ManagementSwitch Management -DestinationRoot ($parent + 'x') } '*241 characters*shorter -DestinationRoot*' | Out-Null
    if ($HyperVFixture.NewVmCalls -ne 1 -or (Test-Path -LiteralPath ($parent + 'x'))) {
        throw 'Over-budget admission copied disks or invoked the provider.'
    }
    $HyperVFixture.AddUnknownFile = $true
    $failedParent = Join-Path $fixtureRoot 'failure'
    $importError = Assert-HyperVFailure { & $importer -Name $name -ManagementSwitch Management -DestinationRoot $failedParent } '*descendant identity changed*Original error:*0x800700CE*'
    if ($null -eq $importError.Exception.InnerException -or -not (Test-Path -LiteralPath (Join-Path $failedParent "$name/unknown"))) {
        throw 'Importer lost the original exception or removed an unrecorded provider descendant.'
    }

    # Run the actual smoke orchestration with a throwing packaged importer. It must
    # retain the original exception and never claim VM ownership from a name match.
    $smokePackage = Join-Path $fixtureRoot 'smoke-package'
    New-Item -ItemType Directory -Path $smokePackage | Out-Null
    Set-Content -LiteralPath (Join-Path $smokePackage 'Import-Atlaso.ps1') -Value "throw 'Original import failure: 0x800700CE; importer cleanup retained descendants'"
    $zip = Join-Path $fixtureRoot 'fixture.zip'
    Compress-Archive -LiteralPath (Join-Path $smokePackage 'Import-Atlaso.ps1') -DestinationPath $zip
    $smoke = Join-Path $RepositoryRoot 'scripts/windows/virtualization/smoke-hyperv.ps1'
    $HyperVFixture.FreeBytes = 1GB
    Assert-HyperVFailure {
        & $smoke -ZipPath $zip -Name T -ManagementSwitch Management -ServiceSwitch Services -OutputRoot $smokeOutput -PythonPath (Get-Process -Id $PID).Path
    } '*Storage admission failed*' | Out-Null
    if (Test-Path -LiteralPath $smokeOutput) { throw 'Low-space smoke admission extracted files.' }
    $HyperVFixture.FreeBytes = 1TB
    $errorRecord = Assert-HyperVFailure {
        & $smoke -ZipPath $zip -Name T -ManagementSwitch Management -ServiceSwitch Services -OutputRoot $smokeOutput -PythonPath (Get-Process -Id $PID).Path
    } '*Original import failure: 0x800700CE*importer cleanup retained descendants*Cleanup error:*exact created VM identity*preserved*'
    if ($null -eq $errorRecord.Exception.InnerException -or @(Get-ChildItem -LiteralPath $smokeOutput -Force).Count -ne 1) {
        throw 'Smoke did not preserve the original exception object and failed operation root.'
    }
    $tooLongOutput = Join-Path $smokeOutput ('y' * 100)
    Assert-HyperVFailure {
        & $smoke -ZipPath $zip -Name T -ManagementSwitch Management -ServiceSwitch Services -OutputRoot $tooLongOutput -PythonPath (Get-Process -Id $PID).Path
    } '*240-character budget*No files were extracted*' | Out-Null
    if (Test-Path -LiteralPath $tooLongOutput) { throw 'Smoke extracted an over-budget operation.' }
    $memberZip = Join-Path $fixtureRoot 'long-member.zip'
    $archive = [IO.Compression.ZipFile]::Open($memberZip, [IO.Compression.ZipArchiveMode]::Create)
    try { $archive.CreateEntry(('z' * 200) + '.vhdx') | Out-Null }
    finally { $archive.Dispose() }
    $memberOutput = Join-Path $smokeOutput 'member'
    Assert-HyperVFailure {
        & $smoke -ZipPath $memberZip -Name T -ManagementSwitch Management -ServiceSwitch Services -OutputRoot $memberOutput -PythonPath (Get-Process -Id $PID).Path
    } '*240-character budget*No files were extracted*' | Out-Null
    if (Test-Path -LiteralPath $memberOutput) { throw 'Smoke extracted an over-budget ZIP member.' }
}
finally {
    if ($null -ne $previousGlobalVolume) {
        Set-Item Function:global:Get-Volume -Value $previousGlobalVolume.ScriptBlock
    } else {
        Remove-Item Function:global:Get-Volume
    }
    # All provider commands in this fixture are mocks; these newly allocated roots
    # contain only this test's files. Never follow replacement/reparse descendants.
    foreach ($root in @($fixtureRoot, $smokeOutput)) {
        if (Test-Path -LiteralPath $root) {
            if (@(Get-Item -LiteralPath $root; Get-ChildItem -LiteralPath $root -Recurse -Force) |
                Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) {
                throw 'Fixture cleanup refused a reparse point.'
            }
            Remove-Item -LiteralPath $root -Recurse -Force
        }
    }
}
Write-Host 'Hyper-V path and failure-preservation regression tests passed.'
