<#
.SYNOPSIS
Verify the constrained OVA-to-Hyper-V exporter and importer safety contract.
.PARAMETER RepositoryRoot
Atlaso checkout containing the virtualization scripts.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\Atlaso.VirtualizationArtifacts.psm1'
$smokeIdentityModulePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\Atlaso.VirtualizationSmokeIdentity.psm1'
$exporterPath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\export-artifacts.ps1'
$importerPath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\templates\Import-Atlaso.ps1'
$hyperVSmokePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\smoke-hyperv.ps1'
$vmwareSmokePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\smoke-ova-vmware.ps1'
$ovaExporterPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\export-ovf.ps1'
$releaseModulePath = Join-Path $RepositoryRoot 'scripts\windows\virtualization\Atlaso.VirtualizationRelease.psm1'
$prereleaseWorkflowPath = Join-Path $RepositoryRoot '.github\workflows\virtualization-prerelease.yml'
$stableWorkflowPath = Join-Path $RepositoryRoot '.github\workflows\virtualization-stable.yml'
Import-Module $modulePath -Force
Import-Module $smokeIdentityModulePath -Force
Import-Module $releaseModulePath -Force

$head = [string](& git -C $RepositoryRoot rev-parse HEAD)
if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
    throw 'Could not resolve the current checkout commit for the version contract test.'
}
$version = Get-AtlasoTemplateVersion -RepoRoot $RepositoryRoot -SourceCommit $head
if ($version -notmatch '^\d+\.\d+\.\d+$') {
    throw 'The source-commit version resolver did not return a semantic version.'
}

$hyperVAdapters = @(
    [pscustomobject]@{
        Name = 'Services'; Id = 'service-id'; SwitchName = 'Services';
        MacAddress = '00155D445566'; IPAddresses = @('198.51.100.20')
    },
    [pscustomobject]@{
        Name = 'Management'; Id = 'management-id'; SwitchName = 'Management';
        MacAddress = '00155D112233'; IPAddresses = @('192.0.2.20')
    }
)
$hyperVIdentity = Resolve-AtlasoHyperVSmokeNetworkIdentity `
    -Adapters $hyperVAdapters `
    -ManagementSwitch 'Management' `
    -ServiceSwitch 'Services'
if ($hyperVIdentity.Address -ne '192.0.2.20' -or
    $hyperVIdentity.ManagementMac -ne '00:15:5d:11:22:33') {
    throw 'Services-first Hyper-V evidence did not select the named Management adapter address.'
}
try {
    $changedHyperVAdapters = @($hyperVAdapters | ForEach-Object { $_.PSObject.Copy() })
    $changedHyperVAdapters[1].MacAddress = '00155DAABBCC'
    Resolve-AtlasoHyperVSmokeNetworkIdentity `
        -Adapters $changedHyperVAdapters `
        -ManagementSwitch 'Management' `
        -ServiceSwitch 'Services' `
        -ExpectedIdentity $hyperVIdentity | Out-Null
    throw 'Changed Hyper-V management MAC evidence was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'Changed Hyper-V management MAC evidence was accepted.') { throw }
}
try {
    $duplicateHyperVAdapters = @($hyperVAdapters | ForEach-Object { $_.PSObject.Copy() })
    $duplicateHyperVAdapters[0].IPAddresses = @('192.0.2.20')
    Resolve-AtlasoHyperVSmokeNetworkIdentity `
        -Adapters $duplicateHyperVAdapters `
        -ManagementSwitch 'Management' `
        -ServiceSwitch 'Services' | Out-Null
    throw 'Duplicate Hyper-V management address evidence was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'Duplicate Hyper-V management address evidence was accepted.') { throw }
}

$vmxFixture = Join-Path ([IO.Path]::GetTempPath()) ('atlaso-smoke-identity-' + [guid]::NewGuid().ToString('N') + '.vmx')
try {
    $leaseAddresses = @(Get-AtlasoVmwareDhcpLeaseAddress `
            -LeaseText @(
                'lease 198.51.100.20 {',
                '  hardware ethernet 00:0c:29:44:55:66;',
                '}',
                'lease 192.0.2.20 {',
                '  hardware ethernet 00:0c:29:11:22:33;',
                '}'
            ) `
            -ManagementMac '00:0c:29:11:22:33')
    if ($leaseAddresses.Count -ne 1 -or $leaseAddresses[0] -ne '192.0.2.20') {
        throw 'VMware DHCP lease parsing did not retain only the ethernet0 management address candidate.'
    }
    [IO.File]::WriteAllLines($vmxFixture, @(
            'ethernet0.vnet = "VMnet8"',
            'ethernet0.generatedAddress = "00:0c:29:11:22:33"',
            'ethernet1.vnet = "VMnet1"',
            'ethernet1.generatedAddress = "00:0c:29:44:55:66"'
        ))
    $vmxIdentity = Get-AtlasoVmwareSmokeVmxNetworkIdentity `
        -VmxPath $vmxFixture `
        -ManagementVmnet 'VMnet8' `
        -ServiceVmnet 'VMnet1'
    $vmwareIdentity = Resolve-AtlasoVmwareSmokeAddressIdentity `
        -VmxIdentity $vmxIdentity `
        -NetworkAdapters @(
            [pscustomobject]@{
                Name = 'VMware Network Adapter VMnet8';
                InterfaceDescription = 'VMware Virtual Ethernet Adapter for VMnet8';
                ifIndex = 8; Status = 'Up'
            }
        ) `
        -Neighbors @(
            [pscustomobject]@{
                InterfaceIndex = 8; IPAddress = '198.51.100.20';
                LinkLayerAddress = '00-0c-29-44-55-66'; State = 'Reachable'
            },
            [pscustomobject]@{
                InterfaceIndex = 8; IPAddress = '192.0.2.20';
                LinkLayerAddress = '00-0c-29-11-22-33'; State = 'Reachable'
            }
        ) `
        -ExpectedIdentity $vmxIdentity
    if ($vmwareIdentity.Address -ne '192.0.2.20' -or
        $vmwareIdentity.ManagementMac -ne '00:0c:29:11:22:33') {
        throw 'Services-first VMware neighbor evidence did not select ethernet0 on the management vmnet.'
    }
    try {
        $driftedVmwareIdentity = $vmwareIdentity.PSObject.Copy()
        $driftedVmwareIdentity.Address = '192.0.2.21'
        Resolve-AtlasoVmwareSmokeAddressIdentity `
            -VmxIdentity $vmxIdentity `
            -NetworkAdapters @(
                [pscustomobject]@{
                    Name = 'VMware Network Adapter VMnet8';
                    InterfaceDescription = 'VMware Virtual Ethernet Adapter for VMnet8';
                    ifIndex = 8; Status = 'Up'
                }
            ) `
            -Neighbors @(
                [pscustomobject]@{
                    InterfaceIndex = 8; IPAddress = '192.0.2.20';
                    LinkLayerAddress = '00-0c-29-11-22-33'; State = 'Reachable'
                }
            ) `
            -ExpectedIdentity $driftedVmwareIdentity | Out-Null
        throw 'Changed VMware management address evidence was accepted.'
    }
    catch {
        if ($_.Exception.Message -eq 'Changed VMware management address evidence was accepted.') { throw }
    }
}
finally {
    Remove-Item -LiteralPath $vmxFixture -Force -ErrorAction SilentlyContinue
}

$resolvedRoot = Resolve-AtlasoHyperVOutputRoot -RepoRoot $RepositoryRoot
$expectedRoot = [System.IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'artifacts\virtualization'))
if ($resolvedRoot -ne $expectedRoot) {
    throw 'The default Hyper-V artifact root is not the repository-owned virtualization directory.'
}
try {
    Resolve-AtlasoHyperVOutputRoot -RepoRoot $RepositoryRoot -OutputRoot ([System.IO.Path]::GetTempPath()) | Out-Null
    throw 'An output root outside the repository-owned virtualization directory was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'An output root outside the repository-owned virtualization directory was accepted.') {
        throw
    }
}

$exporter = Get-Content -Raw -LiteralPath $exporterPath
$importer = Get-Content -Raw -LiteralPath $importerPath
$module = Get-Content -Raw -LiteralPath $modulePath
$ovaExporter = Get-Content -Raw -LiteralPath $ovaExporterPath
$hyperVSmoke = Get-Content -Raw -LiteralPath $hyperVSmokePath
$vmwareSmoke = Get-Content -Raw -LiteralPath $vmwareSmokePath
$releaseModule = Get-Content -Raw -LiteralPath $releaseModulePath
$prereleaseWorkflow = Get-Content -Raw -LiteralPath $prereleaseWorkflowPath
$stableWorkflow = Get-Content -Raw -LiteralPath $stableWorkflowPath
if ($vmwareSmoke.Contains('"--prop:atlaso.admin_password=$passwordText"') -or
    $vmwareSmoke.Contains('"--prop:atlaso.root_password=$passwordText"')) {
    throw 'VMware smoke still exposes the disposable credential through OVF Tool process arguments.'
}
try {
    Resolve-AtlasoVirtualizationStagingDirectory -StagingRoot 'relative\release' -Tag 'virtualization-v0.9.237-rc.1' | Out-Null
    throw 'A relative virtualization staging root was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'A relative virtualization staging root was accepted.') { throw }
}
$releaseScope = Get-Module Atlaso.VirtualizationRelease
if ($null -eq $releaseScope) {
    throw 'The virtualization release module was not imported for focused prerelease tests.'
}
$prereleaseParameters = (Get-Command Invoke-AtlasoVirtualizationPrerelease).Parameters.Keys
if ('PrereleaseIdentifier' -in $prereleaseParameters) {
    throw 'The removed PrereleaseIdentifier parameter remains available.'
}
$builderInvocationRoot = Join-Path $RepositoryRoot (
    '.atlaso-local\virtualization-builder-invocation-test-' + [guid]::NewGuid().ToString('N')
)
$builderStubPath = Join-Path $builderInvocationRoot 'build-photon-image-stub.ps1'
try {
    New-Item -ItemType Directory -Path $builderInvocationRoot | Out-Null
    [IO.File]::WriteAllText(
        $builderStubPath,
        @'
[CmdletBinding()]
param(
    [string]$IsoUrl = 'default-iso-url',
    [string]$IsoChecksum = 'default-iso-checksum',
    [SecureString]$SshPassword,
    [SecureString]$BootstrapAdminPassword,
    [string]$OnePasswordEnvironmentId = '',
    [string]$OnePasswordAccount = '',
    [string]$OnePasswordServiceAccountTokenFile = '',
    [string]$OnePasswordPython = '',
    [switch]$ReleaseBuilder,
    [string]$ReleaseVersion = '',
    [string]$ReleaseSourceCommit = '',
    [string]$OutputDirectory = '',
    [switch]$Headless,
    [switch]$EnableRealSystemAdapters
)

[pscustomobject]@{
    IsoUrl = $IsoUrl
    IsoChecksum = $IsoChecksum
    SshPasswordBound = $PSBoundParameters.ContainsKey('SshPassword')
    BootstrapAdminPasswordBound = $PSBoundParameters.ContainsKey('BootstrapAdminPassword')
    OnePasswordEnvironmentId = $OnePasswordEnvironmentId
    OnePasswordAccount = $OnePasswordAccount
    OnePasswordServiceAccountTokenFile = $OnePasswordServiceAccountTokenFile
    OnePasswordPython = $OnePasswordPython
    ReleaseBuilder = [bool]$ReleaseBuilder
    ReleaseVersion = $ReleaseVersion
    ReleaseSourceCommit = $ReleaseSourceCommit
    OutputDirectory = $OutputDirectory
    Headless = [bool]$Headless
    EnableRealSystemAdapters = [bool]$EnableRealSystemAdapters
}
'@,
        [Text.UTF8Encoding]::new($false)
    )
    $builderInvocation = & $releaseScope {
        param($ScriptPath, $OutputPath)
        Invoke-AtlasoVirtualizationReleaseImageBuilder `
            -BuilderScriptPath $ScriptPath `
            -ReleaseVersion '0.9.306' `
            -ReleaseSourceCommit '0123456789abcdef0123456789abcdef01234567' `
            -OutputDirectory $OutputPath `
            -OnePasswordEnvironmentId 'environment-selector' `
            -OnePasswordAccount 'account-selector' `
            -OnePasswordServiceAccountTokenFile 'token-file-selector' `
            -OnePasswordPython 'python-selector'
    } $builderStubPath (Join-Path $builderInvocationRoot 'output')
    if ($builderInvocation.IsoUrl -cne 'default-iso-url' -or
        $builderInvocation.IsoChecksum -cne 'default-iso-checksum' -or
        $builderInvocation.SshPasswordBound -or
        $builderInvocation.BootstrapAdminPasswordBound -or
        -not $builderInvocation.ReleaseBuilder -or
        $builderInvocation.ReleaseVersion -cne '0.9.306' -or
        $builderInvocation.ReleaseSourceCommit -cne '0123456789abcdef0123456789abcdef01234567' -or
        $builderInvocation.OutputDirectory -cne (Join-Path $builderInvocationRoot 'output') -or
        -not $builderInvocation.Headless -or
        -not $builderInvocation.EnableRealSystemAdapters -or
        $builderInvocation.OnePasswordEnvironmentId -cne 'environment-selector' -or
        $builderInvocation.OnePasswordAccount -cne 'account-selector' -or
        $builderInvocation.OnePasswordServiceAccountTokenFile -cne 'token-file-selector' -or
        $builderInvocation.OnePasswordPython -cne 'python-selector') {
        throw 'The virtualization producer did not invoke the VMware builder with the exact named non-secret parameters.'
    }
}
finally {
    Remove-Item -LiteralPath $builderInvocationRoot -Recurse -Force -ErrorAction SilentlyContinue
}
$expectedDefaultRoot = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot 'artifacts\virtualization-release'))
$defaultRootExisted = Test-Path -LiteralPath $expectedDefaultRoot
$defaultRoot = & $releaseScope {
    param($Root)
    Resolve-AtlasoVirtualizationStagingRoot -RepoRoot $Root
} $RepositoryRoot
if ($defaultRoot -cne $expectedDefaultRoot -or
    (Test-Path -LiteralPath $defaultRoot) -ne $defaultRootExisted) {
    throw 'Default virtualization prerelease staging-root preflight is not non-mutating.'
}
$retainedRoot = Join-Path $RepositoryRoot ('.atlaso-local\virtualization-release-test-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path (Join-Path $retainedRoot 'virtualization-v0.9.304-rc.7') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $retainedRoot 'virtualization-v0.9.303-rc.99') -Force | Out-Null
    $discoveredRetained = @(& $releaseScope {
            param($Root)
            Get-AtlasoVirtualizationRetainedOperationTags -StagingRoot $Root -Version '0.9.304'
        } $retainedRoot)
    if ($discoveredRetained.Count -ne 1 -or
        $discoveredRetained[0] -cne 'virtualization-v0.9.304-rc.7') {
        throw 'Retained-operation discovery did not isolate the current synchronized version.'
    }
    New-Item -ItemType Directory -Path (Join-Path $retainedRoot 'virtualization-v0.9.304-rc.8') | Out-Null
    $ambiguousRetained = @(& $releaseScope {
            param($Root)
            Get-AtlasoVirtualizationRetainedOperationTags -StagingRoot $Root -Version '0.9.304'
        } $retainedRoot)
    if ($ambiguousRetained.Count -ne 2) {
        throw 'Multiple current-version retained operations were not discovered for fail-closed selection.'
    }
    New-Item -ItemType Directory -Path (Join-Path $retainedRoot 'Virtualization-v0.9.304-rc.9') | Out-Null
    try {
        & $releaseScope {
            param($Root)
            Get-AtlasoVirtualizationRetainedOperationTags -StagingRoot $Root -Version '0.9.304'
        } $retainedRoot | Out-Null
        throw 'A noncanonical retained-operation directory name was accepted.'
    }
    catch {
        if ($_.Exception.Message -eq 'A noncanonical retained-operation directory name was accepted.') { throw }
    }
}
finally {
    Remove-Item -LiteralPath $retainedRoot -Recurse -Force -ErrorAction SilentlyContinue
}
$selectionCases = @(
    @{ Remote = @(); Releases = @(); Expected = 'virtualization-v0.9.304-rc.1' },
    @{ Remote = @('virtualization-v0.9.304-rc.1'); Releases = @(); Expected = 'virtualization-v0.9.304-rc.2' },
    @{ Remote = @('virtualization-v0.9.304-rc.1', 'virtualization-v0.9.304-rc.4'); Releases = @(); Expected = 'virtualization-v0.9.304-rc.5' },
    @{ Remote = @('virtualization-v0.9.304-rc.2'); Releases = @('virtualization-v0.9.304-rc.2', 'virtualization-v0.9.304-rc.3'); Expected = 'virtualization-v0.9.304-rc.4' }
)
foreach ($case in $selectionCases) {
    $selected = & $releaseScope {
        param($Remote, $Releases)
        Select-AtlasoVirtualizationPrereleaseTag `
            -Version '0.9.304' `
            -RemoteTagNames $Remote `
            -ReleaseTagNames $Releases
    } $case.Remote $case.Releases
    if ($selected -cne $case.Expected) {
        throw "Unexpected automatic virtualization prerelease selection: $selected"
    }
}
$releaseInventory = @(& $releaseScope {
        <#
        .SYNOPSIS
        Return nested GitHub CLI output for focused inventory validation.
        .PARAMETER Arguments
        Ignored GitHub CLI arguments from the release inventory helper.
        #>
        function Invoke-AtlasoReleaseGh {
            param([string[]]$Arguments)
            $null = $Arguments
            return ,@(
                'virtualization-v0.9.304-rc.2',
                'virtualization-v0.9.304-rc.5',
                'virtualization-v0.9.303-rc.99'
            )
        }
        Get-AtlasoVirtualizationReleaseTagNames -Repository 'example/Atlaso' -Version '0.9.304'
    })
if ($releaseInventory.Count -ne 2 -or
    'virtualization-v0.9.304-rc.2' -notin $releaseInventory -or
    'virtualization-v0.9.304-rc.5' -notin $releaseInventory) {
    throw 'GitHub Release tag inventory did not enumerate and filter every captured output line.'
}
$retainedSelection = & $releaseScope {
    Select-AtlasoVirtualizationPrereleaseTag `
        -Version '0.9.304' `
        -RetainedTags @('virtualization-v0.9.304-rc.7') `
        -RemoteTagNames @('virtualization-v0.9.304-rc.9')
}
if ($retainedSelection -cne 'virtualization-v0.9.304-rc.7') {
    throw 'The one retained operation was not selected for retry.'
}
foreach ($presenceChange in @(
        @{ WasPresent = $false; IsPresent = $true },
        @{ WasPresent = $true; IsPresent = $false }
    )) {
    try {
        & $releaseScope {
            param($WasPresent, $IsPresent)
            Assert-AtlasoVirtualizationFrozenPresence `
                -Tag 'virtualization-v0.9.304-rc.7' `
                -IdentityKind tag `
                -WasPresent $WasPresent `
                -IsPresent $IsPresent
        } $presenceChange.WasPresent $presenceChange.IsPresent
        throw 'A post-selection remote-identity presence change was accepted.'
    }
    catch {
        if ($_.Exception.Message -eq 'A post-selection remote-identity presence change was accepted.') { throw }
    }
}
& $releaseScope {
    Assert-AtlasoVirtualizationFrozenPresence `
        -Tag 'virtualization-v0.9.304-rc.7' `
        -IdentityKind Release `
        -WasPresent $true `
        -IsPresent $true
}
try {
    & $releaseScope {
        Select-AtlasoVirtualizationPrereleaseTag `
            -Version '0.9.304' `
            -RetainedTags @('virtualization-v0.9.304-rc.1', 'virtualization-v0.9.304-rc.2')
    } | Out-Null
    throw 'Ambiguous retained virtualization operations were accepted.'
}
catch {
    if ($_.Exception.Message -eq 'Ambiguous retained virtualization operations were accepted.') { throw }
}
$switches = & $releaseScope {
    Resolve-AtlasoVirtualizationHyperVSwitches -SwitchInventory @(
        [pscustomobject]@{ Name = 'Atlaso Management' },
        [pscustomobject]@{ Name = 'Atlaso Services' }
    )
}
if ($switches.Management -cne 'Atlaso Management' -or $switches.Service -cne 'Atlaso Services') {
    throw 'Default Hyper-V switch selection is incorrect.'
}
$switchOverrides = & $releaseScope {
    Resolve-AtlasoVirtualizationHyperVSwitches `
        -ManagementSwitch 'Management Override' `
        -ServiceSwitch 'Services Override' `
        -SwitchInventory @(
            [pscustomobject]@{ Name = 'Management Override' },
            [pscustomobject]@{ Name = 'Services Override' }
        )
}
if ($switchOverrides.Management -cne 'Management Override' -or
    $switchOverrides.Service -cne 'Services Override') {
    throw 'Explicit Hyper-V switch overrides were not authoritative.'
}
foreach ($badInventory in @(
        @([pscustomobject]@{ Name = 'Atlaso Management' }),
        @(
            [pscustomobject]@{ Name = 'Atlaso Management' },
            [pscustomobject]@{ Name = 'Atlaso Management' },
            [pscustomobject]@{ Name = 'Atlaso Services' }
        ),
        @(
            [pscustomobject]@{ Name = 'atlaso management' },
            [pscustomobject]@{ Name = 'atlaso services' }
        )
    )) {
    try {
        & $releaseScope {
            param($Inventory)
            Resolve-AtlasoVirtualizationHyperVSwitches -SwitchInventory $Inventory
        } $badInventory | Out-Null
        throw 'Missing or duplicate Hyper-V switch inventory was accepted.'
    }
    catch {
        if ($_.Exception.Message -eq 'Missing or duplicate Hyper-V switch inventory was accepted.') { throw }
    }
}
foreach ($required in @(
        '[string]$StagingRoot',
        '[string]$FromPrerelease',
        '[switch]$CandidateOnly',
        'Invoke-AtlasoVirtualizationPrerelease',
        'Invoke-AtlasoVirtualizationReleaseImageBuilder',
        'Invoke-AtlasoVirtualizationStablePromotion',
        'Invoke-AtlasoReleaseWorkflow',
        'git -C $RepoRoot remote get-url origin',
        "'repo', 'view', `$repository",
        'differs from the checkout origin',
        "'--json', 'databaseId,displayTitle'",
        '[string]$run.conclusion -cne ''success''',
        'Select-AtlasoVirtualizationPrereleaseTag',
        'Multiple retained virtualization-v$Version release-candidate operations make retry intent ambiguous',
        "'api', '--paginate'",
        'Enumerate both levels explicitly before matching tag lines',
        'does not use the canonical tag casing',
        "'Atlaso Management'",
        "'Atlaso Services'",
        'Resolve-AtlasoOnePasswordEnvironmentId',
        'Assert-AtlasoOnePasswordEnvironmentId',
        'Resolve-AtlasoOnePasswordAuthentication',
        'Resolve-AtlasoOnePasswordPython',
        'Virtualization prerelease preflight:',
        'The selected tag is frozen before the first staging mutation',
        'Assert-AtlasoVirtualizationFrozenPresence',
        'changed after prerelease selection',
        'show-ref --verify --quiet',
        'cat-file -t',
        'Always reconstruct the signed source',
        "'.software-release-download-' + [guid]::NewGuid().ToString('N')",
        'A retry never trusts retained pre-verification network bytes',
        "'--verify-existing', `$candidate",
        'Retained virtualization candidate verification failed',
        'Published assets are immutable',
        'if ($CandidateOnly) {',
        'Invoke-AtlasoVirtualizationPrereleaseFinalizer',
        '-ExpectedSourceCommit $identity.Commit',
        '-RequireCleanSource',
        'The retained VMware image is incomplete and will be rebuilt',
        'Update-AtlasoVmwarePayloadProvenance',
        "Value -ceq 'software-deployed'",
        'Start-AtlasoVirtualizationDeploymentVm',
        'Stop-AtlasoVirtualizationDeploymentVm',
        "'getGuestIPAddress', `$resolvedVmx, '-wait'",
        "'stop', `$resolvedVmx, 'soft'",
        'Proven shutdown is required before hashing or exporting',
        'Existing virtualization Release $tag is misclassified',
        'A published prerelease may need hosted attestation',
        'elseif ($releaseState.isDraft)',
        'ProxmoxRunnerLabel must be the release-specific label',
        'KvmRunnerLabel must be the release-specific label',
        '-OutputRoot $hypervRoot -Force',
        "'release', 'create', `$tag",
        "'--verify-tag'",
        "'release', 'upload', `$Tag",
        'already contains different bytes',
        'OnePasswordEnvironmentId = $OnePasswordEnvironmentId',
        'OnePasswordServiceAccountTokenFile = $OnePasswordServiceAccountTokenFile',
        'artifacts\virtualization\$tag',
        'artifacts\virtualization-smoke\$tag',
        "-Workflow 'virtualization-prerelease.yml'",
        "-Workflow 'virtualization-stable.yml'"
    )) {
    if (-not $releaseModule.Contains($required) -and -not $ovaExporter.Contains($required)) {
        throw "Virtualization release orchestration is missing required marker: $required"
    }
}
if ($releaseModule.Contains('PrereleaseIdentifier') -or $ovaExporter.Contains('PrereleaseIdentifier')) {
    throw 'The removed PrereleaseIdentifier interface remains in release code or help.'
}
$summaryIndex = $releaseModule.IndexOf("Write-Host 'Virtualization prerelease preflight:'")
$stagingMutationIndex = $releaseModule.IndexOf(
    '$operation = Resolve-AtlasoVirtualizationStagingDirectory',
    $releaseModule.IndexOf('function Invoke-AtlasoVirtualizationPrerelease')
)
if ($summaryIndex -lt 0 -or $stagingMutationIndex -lt 0 -or $summaryIndex -gt $stagingMutationIndex) {
    throw 'Sanitized prerelease summary must precede the first staging mutation.'
}
foreach ($secretMarker in @(
        'Write-Host $OnePasswordEnvironmentId',
        'Write-Host $OnePasswordAccount',
        'Write-Host $OnePasswordPython'
    )) {
    if ($releaseModule.Contains($secretMarker)) {
        throw "Prerelease summary exposes a resolved selector: $secretMarker"
    }
}
$releaseSourceChecks = ([regex]::Matches(
        $releaseModule,
        '-ExpectedSourceCommit \$identity\.Commit\s+`\s*\r?\n\s*-RequireCleanSource'
    )).Count
if ($releaseSourceChecks -ne 2) {
    throw 'Virtualization production must enforce exact clean build provenance on reuse and after build.'
}
$candidateVerificationIndex = $releaseModule.IndexOf("'--verify-existing', `$candidate")
$exportIndex = $releaseModule.IndexOf("'scripts\windows\vmware\export-ovf.ps1'")
if ($candidateVerificationIndex -lt 0 -or $exportIndex -lt 0 -or
    $candidateVerificationIndex -gt $exportIndex) {
    throw 'Retained candidate verification must run before any OVA export on retry.'
}
$publishedResumeIndex = $releaseModule.IndexOf(
    'if ($null -ne $releaseState -and -not $releaseState.isDraft)'
)
$candidateOnlyResumeIndex = $releaseModule.IndexOf('if ($CandidateOnly) {', $publishedResumeIndex)
$candidateReuseIndex = $releaseModule.IndexOf('$reuseCandidate = Test-Path', $publishedResumeIndex)
if ($publishedResumeIndex -lt 0 -or $candidateOnlyResumeIndex -lt 0 -or
    $candidateReuseIndex -lt 0 -or $candidateOnlyResumeIndex -gt $candidateReuseIndex) {
    throw 'Candidate-only published retries must stop before rebuilding or reusing local bytes.'
}
foreach ($forbidden in @('--clobber', 'RELEASE_SIGNING_PRIVATE_KEY')) {
    if ($releaseModule.Contains($forbidden)) {
        throw "The Windows producer crosses a protected publication boundary: $forbidden"
    }
}
foreach ($required in @(
        'environment: appliance-release',
        '--classification prerelease',
        'already_published=true',
        "steps.identity.outputs.already_published != 'true'",
        'gh release edit "$RELEASE_TAG" --draft=false --prerelease --verify-tag'
    )) {
    if (-not $prereleaseWorkflow.Contains($required)) {
        throw "The hosted prerelease finalizer is missing required marker: $required"
    }
}
foreach ($required in @(
        'runs-on: [self-hosted, Linux, X64',
        'actions: read',
        'contents: read',
        '--classification stable',
        'test "$PROXMOX_RUNNER_LABEL" = "atlaso-proxmox-$LABEL_SUFFIX"',
        'test "$KVM_RUNNER_LABEL" = "atlaso-kvm-$LABEL_SUFFIX"',
        'cmp --silent',
        'gh attestation verify'
    )) {
    if (-not $stableWorkflow.Contains($required)) {
        throw "Stable virtualization promotion is missing required marker: $required"
    }
}
if ($stableWorkflow.Contains('ref: ${{ steps.identity.outputs.release_sha }}') -or
    $stableWorkflow.Contains('ref: ${{ needs.admit.outputs.release_sha }}')) {
    throw 'Stable promotion executes release-selected source on a hosted or self-hosted runner.'
}
if ($prereleaseWorkflow.Contains('gh-pages') -or $stableWorkflow.Contains('gh-pages')) {
    throw 'A virtualization workflow may not mutate the appliance update site.'
}
foreach ($required in @(
        "Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'",
        'must be a strict descendant of its owned output root',
        'owned directory cannot be a reparse point',
        'Get-AtlasoWindowsFileId',
        'Assert-AtlasoVmwareVmIdentity',
        'Get-AtlasoVmwareDescendantIdentity',
        'Get-AtlasoVmwareInventoryPathById',
        '$ownedDescendantIds.ContainsKey($_)',
        'The pre-provider VMware smoke root identity changed',
        '$partialDescendants.ContainsKey($_)',
        'unexpected VMX set',
        'unexpected display name',
        'root identity changed after provider deletion',
        '"--configFile=$ovfToolConfigPath"',
        '$configAcl.SetAccessRuleProtection($true, $false)',
        'Remove-Item -LiteralPath $ovfToolConfigPath -Force',
        '$passwordText = $null'
    )) {
    if (-not $vmwareSmoke.Contains($required)) {
        throw "VMware smoke is missing a protected non-argv OVF Tool credential marker: $required"
    }
}
foreach ($required in @(
        'Invoke-AtlasoOvaValidation',
        'Get-AtlasoTemplateVersion',
        'atlaso-v$version-hyperv-x86_64.zip',
        "'convert', '-p', '-f', 'vmdk', '-O', 'vhdx'",
        "'create', '-f', 'vhdx'",
        '536870912000',
        'Import-Atlaso.ps1',
        'Write-AtlasoArtifactChecksums'
    )) {
    if (-not $exporter.Contains($required)) {
        throw "The Hyper-V exporter is missing required contract marker: $required"
    }
}
foreach ($retired in @("'Kvm'", "'Proxmox'", "'qcow2'", 'AllowedTargetNames')) {
    if ($exporter.Contains($retired) -or $module.Contains($retired)) {
        throw "The standalone QCOW2 exporter contract remains: $retired"
    }
}
foreach ($required in @(
        'Write-AtlasoOvaProvenance',
        'atlaso-provenance.json',
        'atlaso-vmware-ova-provenance',
        'Assert-AtlasoCanonicalOvf',
        'Assert-AtlasoCanonicalOva',
        'scripts\virtualization\validate_ova.py'
    )) {
    if (-not $ovaExporter.Contains($required)) {
        throw "The canonical OVA exporter is missing provenance or validation marker: $required"
    }
}
$ovfValidationIndex = $ovaExporter.IndexOf('Assert-AtlasoCanonicalOvf -RepoRoot $repoRoot -OvfPath $ovfPath')
$provenanceIndex = $ovaExporter.IndexOf('$provenancePath = Write-AtlasoOvaProvenance')
if ($ovfValidationIndex -lt 0 -or $provenanceIndex -lt 0 -or $ovfValidationIndex -gt $provenanceIndex) {
    throw 'The canonical OVF machine contract must validate before OVA provenance is written.'
}
foreach ($required in @(
        "'atlaso-hyperv-artifact'",
        "'atlaso-validated-ova'",
        "@('photon_os', 'atlaso_system', 'vcf_offline_depot', 'vcf_backups')",
        '@(42949672960, 21474836480, 536870912000, 536870912000)',
        '-Generation 2',
        '-EnableSecureBoot Off',
        'Get-VHD -Path $destinationDisk',
        "VhdType -ne 'Dynamic'",
        '-ControllerType SCSI',
        '-FirstBootDevice $drives[0]',
        'if ($vmCreated -and $null -ne $vm)',
        'Remove-VM -VM $vm',
        '$vmRemovalVerified',
        'Get-VM -ErrorAction Stop | Where-Object Id -eq $vm.Id',
        '$verifiedVmMatches',
        '$verifiedVm = $verifiedVmMatches[0]',
        'exact created Hyper-V VM identity changed',
        'if ($vmRootCreated',
        'Get-AtlasoHyperVWindowsFileId',
        'Get-AtlasoHyperVDescendantIdentity',
        '$ownedDescendantIds[[string]$disk.file]',
        '$ownedDescendantIds.ContainsKey($_)',
        'an unrecorded partial copy is preserved',
        'root identity changed before filesystem deletion',
        'descendant identity changed before filesystem deletion',
        'files were preserved'
    )) {
    if (-not $importer.Contains($required)) {
        throw "The Hyper-V importer is missing required topology or rollback marker: $required"
    }
}
foreach ($required in @(
        'listRegisteredVM',
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
        'Get-Command vmrun',
        '$vmRootSafeToRemove',
        '$cleanupFailure',
        'its files were preserved'
    )) {
    if (-not $vmwareSmoke.Contains($required)) {
        throw "The VMware smoke cleanup is missing fail-closed marker: $required"
    }
}
foreach ($required in @(
        'Remove-VM -VM $createdVm -Force -ErrorAction Stop',
        'Get-VM -ErrorAction Stop | Where-Object Id -eq $createdVm.Id',
        'atlaso.first_boot_access',
        'Get-AtlasoHyperVFirstBootAccess',
        'did not return an exact created VM identity',
        '$createdVmMatches = @(',
        '& $importer',
        'did not return one exact created virtual-machine identity',
        '$operationRootSafeToRemove = -not $importAttempted',
        '$operationRootSafeToRemove',
        'Get-AtlasoHyperVSmokeWindowsFileId',
        'Get-AtlasoHyperVSmokeDescendantIdentity',
        '$ownedDescendantIds.ContainsKey($_)',
        'root identity changed before filesystem deletion',
        'descendant identity changed before filesystem deletion',
        'Atlaso.VirtualizationSmokeIdentity.psm1',
        'Resolve-AtlasoHyperVSmokeNetworkIdentity',
        'Wait-AtlasoHyperVSmokeNetworkIdentity',
        "'--phase' 'post-reboot'",
        'its files were preserved'
    )) {
    if (-not $hyperVSmoke.Contains($required)) {
        throw "The Hyper-V smoke cleanup is missing fail-closed marker: $required"
    }
}
if ($importer.Contains('Remove-VM -VM $vm -Force -ErrorAction Continue') -or
    $hyperVSmoke.Contains('Remove-VM -Name $Name -Force -ErrorAction Continue')) {
    throw 'A Hyper-V cleanup still ignores VM removal failure.'
}
if ($importer.Contains('Get-VM -Name $Name')) {
    throw 'The Hyper-V importer reacquires its invocation-owned VM by name.'
}
if (($hyperVSmoke.Split('Get-VM -ErrorAction Stop | Where-Object Name -eq $Name').Count - 1) -ne 1) {
    throw 'Hyper-V smoke cleanup still claims a post-failure VM by name instead of a captured ID.'
}
if ($hyperVSmoke.Contains('-Start | Out-Null') -or
    $hyperVSmoke.Contains('$createdVmMatches = @(Get-VM -Name $Name')) {
    throw 'Hyper-V smoke discards the importer-owned VM identity and reacquires it by name.'
}
if ($hyperVSmoke.Contains('ForEach-Object IPAddresses')) {
    throw 'Hyper-V smoke still flattens addresses across the Management and Services adapters.'
}
foreach ($required in @(
        'Atlaso.VirtualizationSmokeIdentity.psm1',
        'Get-AtlasoVmwareSmokeVmxNetworkIdentity',
        'Resolve-AtlasoVmwareSmokeAddressIdentity',
        'Wait-AtlasoVmwareSmokeNetworkIdentity',
        'Get-AtlasoVmwareDhcpLeaseAddress',
        '& $ping -4 -S',
        'Get-NetNeighbor -AddressFamily IPv4',
        "'--phase' 'post-reboot'"
    )) {
    if (-not $vmwareSmoke.Contains($required)) {
        throw "VMware smoke is missing a provider-bound management identity marker: $required"
    }
}
if ($vmwareSmoke.Contains('getGuestIPAddress')) {
    throw 'VMware smoke still trusts the unqualified VMware Tools guest address result.'
}

Write-Host 'Hyper-V virtualization artifact contract test passed.'
