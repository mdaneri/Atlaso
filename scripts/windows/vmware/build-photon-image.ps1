<#
.SYNOPSIS
Build or validate the supported Atlaso VMware Workstation Photon image.
.PARAMETER IsoUrl
Pinned Photon source URL or local path.
.PARAMETER IsoChecksum
Expected Photon ISO checksum.
.PARAMETER SshPassword
Optional temporary Packer SSH password override. When omitted, the wrapper
retrieves DEFAULT_ROOT_PASSWORD from the exact Atlaso 1Password Environment.
.PARAMETER BootstrapAdminPassword
Optional initial administrator password override. When omitted, the wrapper
retrieves DEFAULT_ADMIN_PASSWORD from the exact Atlaso 1Password Environment.
.PARAMETER OnePasswordEnvironmentId
Opaque ID of the exact Atlaso 1Password Environment. When omitted, the wrapper
reads the checkout-local onepassword-environment-id selector.
.PARAMETER EnvironmentIdFile
Optional single-line Atlaso Environment ID file. The legacy
OnePasswordEnvironmentIdFile name remains available as an alias.
.PARAMETER OnePasswordAccount
1Password account name or ID approved for desktop SDK authorization when either
credential is omitted.
.PARAMETER OnePasswordPython
CPython 3.10 through 3.13 executable used by the locked Windows 1Password SDK
runtime when either credential is omitted.
.PARAMETER CredentialTimeoutSeconds
Bounded timeout for each 1Password SDK preparation and retrieval operation.
.PARAMETER ImageBuildTimeoutSeconds
Bounded deadline for the isolated plaintext-consuming Photon/Packer child.
.PARAMETER CredentialBundlePath
Internal current-user DPAPI credential bundle used only by the isolated child.
.PARAMETER CredentialChild
Internal marker proving the current process is the isolated image-build child.
.PARAMETER BuilderStaticDnsJson
Internal JSON transport for the non-secret builder DNS server array.
.PARAMETER BuilderStaticDnsBound
Internal marker preserving whether the caller explicitly bound the builder DNS array.
.PARAMETER SensitiveBuildDirectory
Internal task-owned directory containing all plaintext image-build artifacts.
.PARAMETER OutputCleanupClaimPath
Internal durable marker proving the isolated child claimed a pre-existing output root.
.PARAMETER VmName
Builder virtual-machine name.
.PARAMETER OutputDirectory
Artifact output directory.
.PARAMETER SshHost
Optional explicit builder SSH address.
.PARAMETER SharedSourceDirectory
Shared checksum-verified ISO cache.
.PARAMETER VmrunPath
Optional VMware vmrun executable path.
.PARAMETER VmnetName
Management VMware network.
.PARAMETER ServiceVmnetName
Services VMware network.
.PARAMETER BridgedInterfaceAlias
Optional host adapter for bridged management.
.PARAMETER BuilderStaticIp
Temporary Photon builder address.
.PARAMETER BuilderStaticNetmask
Temporary Photon builder netmask.
.PARAMETER BuilderStaticGateway
Temporary Photon builder gateway.
.PARAMETER BuilderStaticDns
Temporary Photon builder DNS servers.
.PARAMETER FinalMgmtAddress
Final appliance management address policy.
.PARAMETER FinalMgmtGateway
Final appliance management gateway.
.PARAMETER FinalMgmtInterface
Final appliance management interface.
.PARAMETER PipGlobalIndex
Optional pip global index setting.
.PARAMETER PipGlobalIndexUrl
Optional pip index URL.
.PARAMETER PackerDirectory
VMware Packer template directory.
.PARAMETER PreparedIsoPath
Optional remastered ISO path.
.PARAMETER PackerOnError
Packer failure-handling mode.
.PARAMETER PackerStartupTimeoutSeconds
Maximum interval from monitored Packer process start to SSH provisioning.
.PARAMETER PackerHeartbeatSeconds
Interval for sanitized builder startup diagnostics.
.PARAMETER AllowExistingManagementSubnet
Permit an existing matching management subnet.
.PARAMETER SkipNetworkCheck
Skip VMware network preflight.
.PARAMETER Headless
Run the VMware builder without a console window.
.PARAMETER KeepExistingOutput
Preserve an existing output directory.
.PARAMETER EnableRealSystemAdapters
Enable real system adapters in the image.
.PARAMETER ValidateOnly
Validate Packer inputs without building.
.PARAMETER PrepareIsoOnly
Reject ISO-only preparation because the retained ISO would contain reusable credentials.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordEnvironmentId',
    Justification = 'Opaque Environment identifier; bounded children retrieve concealed values.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordAccount',
    Justification = 'Desktop authorization account identifier, not an account password.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordPython',
    Justification = 'Executable selector for the isolated SDK runtime, not a password.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'CredentialBundlePath',
    Justification = 'Path to current-user DPAPI ciphertext, not a plaintext password.'
)]
[CmdletBinding()]
param(
    [Parameter()]
    [string]$IsoUrl = 'https://packages.broadcom.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso',

    [Parameter()]
    [string]$IsoChecksum = 'sha512:6a7a258399a258da742032987c043ab25503698d35edafaf1ae000f12127da1a161d8b84caa17fd8f23d129e81e1faa7ab087c20ab9229772a643f8f9475305f',

    [SecureString]$SshPassword,
    [SecureString]$BootstrapAdminPassword,
    [string]$OnePasswordEnvironmentId = '',
    [Alias('OnePasswordEnvironmentIdFile')]
    [string]$EnvironmentIdFile = '',
    [string]$OnePasswordAccount = '',
    [string]$OnePasswordPython = '',
    [ValidateRange(1, 3600)]
    [int]$CredentialTimeoutSeconds = 300,
    [ValidateRange(300, 86400)]
    [int]$ImageBuildTimeoutSeconds = 21600,
    [string]$CredentialBundlePath = '',
    [switch]$CredentialChild,
    [string]$BuilderStaticDnsJson = '',
    [switch]$BuilderStaticDnsBound,
    [string]$SensitiveBuildDirectory = '',
    [string]$OutputCleanupClaimPath = '',
    [string]$VmName = 'Atlaso-Photon-Builder-VMware',
    [string]$OutputDirectory = '',
    [string]$SshHost = '',
    [string]$SharedSourceDirectory = '',
    [string]$VmrunPath = '',
    [string]$VmnetName = 'VMnet8',
    [string]$ServiceVmnetName = 'VMnet1',
    [string]$BridgedInterfaceAlias = '',
    # Legacy fallbacks; normal builds replace these from the selected VMware vmnet unless explicitly passed.
    [string]$BuilderStaticIp = '192.168.167.30/24',
    [string]$BuilderStaticNetmask = '255.255.255.0',
    [string]$BuilderStaticGateway = '192.168.167.2',
    [string[]]$BuilderStaticDns = @(),
    [string]$FinalMgmtAddress = 'dhcp',
    [string]$FinalMgmtGateway = '',
    [string]$FinalMgmtInterface = 'eth0',
    [string]$PipGlobalIndex = '',
    [string]$PipGlobalIndexUrl = '',
    [string]$PackerDirectory = '',
    [string]$PreparedIsoPath = '',
    [ValidateSet('cleanup', 'abort', 'ask', 'run-cleanup-provisioner')]
    [string]$PackerOnError = 'cleanup',
    [ValidateRange(30, 3600)]
    [int]$PackerStartupTimeoutSeconds = 2700,
    [ValidateRange(1, 300)]
    [int]$PackerHeartbeatSeconds = 30,
    [switch]$AllowExistingManagementSubnet,
    [switch]$SkipNetworkCheck,
    [switch]$Headless,
    [switch]$KeepExistingOutput,
    [switch]$EnableRealSystemAdapters,
    [switch]$ValidateOnly,
    [switch]$PrepareIsoOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PrepareIsoOnly) {
    throw 'PrepareIsoOnly is not supported because a retained remastered ISO would contain reusable build credentials. Run Packer validation or a build so the ISO can be deleted after the bounded consumer exits.'
}

. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\common\Atlaso.PhotonImage.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwarePayload.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationBuildMonitor.psm1') -Force

<#
.SYNOPSIS
Remove a proven-inactive Photon root and durably retire its marker.

.PARAMETER MarkerPath
Exact non-secret cleanup marker path.

.PARAMETER Marker
Validated marker payload owning the exact root.

.PARAMETER ExpectedRootPath
Exact task-created root that the marker must still own.
#>
function Complete-AtlasoPhotonBuildCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][object]$Marker,
        [Parameter(Mandatory = $true)][string]$ExpectedRootPath
    )

    $markerProperties = @($Marker.PSObject.Properties.Name)
    if ($markerProperties.Count -ne 4 -or
        'Schema' -notin $markerProperties -or
        'RootPath' -notin $markerProperties -or
        'BootIdentity' -notin $markerProperties -or
        'Phase' -notin $markerProperties -or
        $Marker.Schema -ne 1 -or
        $Marker.Phase -notin @('active', 'root-absent', 'retired')) {
        throw 'Invalid cleanup marker schema.'
    }
    $resolvedRoot = [System.IO.Path]::GetFullPath([string]$Marker.RootPath)
    $resolvedExpectedRoot = [System.IO.Path]::GetFullPath($ExpectedRootPath)
    $rootLeaf = Split-Path -Leaf $resolvedRoot
    if (-not $resolvedRoot.Equals($resolvedExpectedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $rootLeaf -notmatch '^atlaso-photon-build-credentials-[0-9a-f]{32}$') {
        throw 'Cleanup marker root does not match the exact task-created Photon root.'
    }
    if (Test-Path -LiteralPath $resolvedRoot) {
        $rootItem = Get-Item -LiteralPath $resolvedRoot -Force -ErrorAction Stop
        if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'Invalid cleanup root type.'
        }
        [System.IO.Directory]::Delete($resolvedRoot, $true)
    }
    if (Test-Path -LiteralPath $resolvedRoot) {
        throw 'Retained Photon credential artifact cleanup did not complete.'
    }
    # Flush the parent on the sensitive root's own volume before a marker on a
    # different volume is allowed to claim that the deletion is durable.
    Sync-AtlasoDirectoryMetadata -DirectoryPath (Split-Path -Parent $resolvedRoot)
    $Marker.Phase = 'root-absent'
    Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $Marker -Replace
    $Marker.Phase = 'retired'
    Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $Marker -Replace
    Remove-Item -LiteralPath $MarkerPath -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $MarkerPath) {
        throw 'Retained Photon cleanup marker removal did not complete.'
    }
}

<#
.SYNOPSIS
Recover a retained Photon sensitive-build root after a proven host restart.

.PARAMETER MarkerPath
Exact non-secret cleanup marker path.
#>
function Invoke-AtlasoPhotonBuildCleanupRecovery {
    param([Parameter(Mandatory = $true)][string]$MarkerPath)

    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
        return
    }
    try {
        $marker = Get-Content -LiteralPath $MarkerPath -Raw -ErrorAction Stop | ConvertFrom-Json
        $markerProperties = @($marker.PSObject.Properties.Name)
        if ($markerProperties.Count -ne 4 -or
            'Schema' -notin $markerProperties -or
            'RootPath' -notin $markerProperties -or
            'BootIdentity' -notin $markerProperties -or
            'Phase' -notin $markerProperties -or
            $marker.Schema -ne 1) {
            throw 'Invalid cleanup marker schema.'
        }
        $resolvedRoot = [System.IO.Path]::GetFullPath([string]$marker.RootPath)
        $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        $tempRootPrefix = $resolvedTempRoot.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedRoot.StartsWith($tempRootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedRoot) -notmatch '^atlaso-photon-build-credentials-[0-9a-f]{32}$') {
            throw 'Invalid cleanup root.'
        }
        if ($marker.Phase -notin @('active', 'root-absent', 'retired')) {
            throw 'Invalid cleanup marker phase.'
        }
        if ($marker.Phase -ceq 'active' -and
            [string]$marker.BootIdentity -ceq (Get-AtlasoWindowsBootIdentity)) {
            throw 'A Windows restart is required before retained Photon credential artifacts can be cleaned safely.'
        }
        Complete-AtlasoPhotonBuildCleanup `
            -MarkerPath $MarkerPath `
            -Marker $marker `
            -ExpectedRootPath $resolvedRoot
    }
    catch {
        throw 'A prior Photon image build has unresolved sensitive cleanup. Restart Windows, then rerun this wrapper.'
    }
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$cleanupMarkerPath = Join-Path $repoRoot '.atlaso-local\photon-image-build-cleanup.json'
if ($CredentialChild) {
    if ($SshPassword -or $BootstrapAdminPassword -or
        [string]::IsNullOrWhiteSpace($CredentialBundlePath) -or
        -not (Test-Path -LiteralPath $CredentialBundlePath -PathType Leaf)) {
        throw 'The isolated Photon credential bundle is unavailable or invalid.'
    }
    $credentialBundleRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $CredentialBundlePath))
    $resolvedOutputCleanupClaimPath = if ([string]::IsNullOrWhiteSpace($OutputCleanupClaimPath)) {
        ''
    }
    else {
        [System.IO.Path]::GetFullPath($OutputCleanupClaimPath)
    }
    $sensitiveBuildRoot = if ([string]::IsNullOrWhiteSpace($SensitiveBuildDirectory)) {
        ''
    }
    else {
        [System.IO.Path]::GetFullPath($SensitiveBuildDirectory)
    }
    $credentialRootPrefix = $credentialBundleRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    if ([string]::IsNullOrWhiteSpace($sensitiveBuildRoot) -or
        -not $sensitiveBuildRoot.StartsWith($credentialRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The isolated Photon sensitive-build root is unavailable or invalid.'
    }
    if ([string]::IsNullOrWhiteSpace($resolvedOutputCleanupClaimPath) -or
        -not $resolvedOutputCleanupClaimPath.StartsWith(
            $credentialRootPrefix,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        (Split-Path -Leaf $resolvedOutputCleanupClaimPath) -cne 'output-cleanup-claimed.json') {
        throw 'The isolated Photon output-cleanup claim path is unavailable or invalid.'
    }
    if (-not [string]::IsNullOrWhiteSpace($PreparedIsoPath)) {
        $resolvedChildPreparedIsoPath = [System.IO.Path]::GetFullPath($PreparedIsoPath)
        $sensitiveBuildPrefix = $sensitiveBuildRoot.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedChildPreparedIsoPath.StartsWith(
                $sensitiveBuildPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'The isolated Photon prepared-ISO path is unavailable or invalid.'
        }
    }
    try {
        $credentialBundle = Get-Content -LiteralPath $CredentialBundlePath -Raw | ConvertFrom-Json
        $bundleProperties = @($credentialBundle.PSObject.Properties.Name)
        if ($bundleProperties.Count -ne 2 -or
            'AdminPasswordCiphertext' -notin $bundleProperties -or
            'RootPasswordCiphertext' -notin $bundleProperties) {
            throw 'The isolated Photon credential bundle is invalid.'
        }
        $BootstrapAdminPassword = ConvertTo-SecureString $credentialBundle.AdminPasswordCiphertext
        $SshPassword = ConvertTo-SecureString $credentialBundle.RootPasswordCiphertext
    }
    catch {
        throw 'The isolated Photon credential bundle is unavailable or invalid.'
    }
    $credentialBundle = $null
    if (-not [string]::IsNullOrWhiteSpace($BuilderStaticDnsJson)) {
        try {
            $transportedDns = @(ConvertFrom-Json -InputObject $BuilderStaticDnsJson)
            if (@($transportedDns | Where-Object { $_ -isnot [string] }).Count -ne 0) {
                throw 'Invalid builder DNS transport.'
            }
            $BuilderStaticDns = @($transportedDns)
        }
        catch {
            throw 'The isolated Photon builder DNS transport is invalid.'
        }
    }
}
else {
    # Recovery precedes new credential access or image mutation. A changed boot
    # identity is the fail-closed proof that an untracked descendant cannot
    # recreate credential-bearing files after absence verification.
    Invoke-AtlasoPhotonBuildCleanupRecovery -MarkerPath $cleanupMarkerPath
    $needsOnePasswordDefaults = $null -eq $SshPassword -or $null -eq $BootstrapAdminPassword
    $resolvedEnvironmentId = ''
    if ($needsOnePasswordDefaults) {
        $resolvedEnvironmentId = Resolve-AtlasoOnePasswordEnvironmentId `
            -EnvironmentId $OnePasswordEnvironmentId `
            -EnvironmentIdFile $EnvironmentIdFile `
            -RepositoryRoot $repoRoot `
            -ConsumerDescription 'VMware Photon image building'
    }

    # Credential preflight completes before the isolated child can perform any
    # network, cleanup, ISO, Packer, or image mutation.
    $credentialPair = Get-AtlasoOnePasswordCredentialPair `
        -RepositoryRoot $repoRoot `
        -EnvironmentId $resolvedEnvironmentId `
        -OnePasswordAccount $OnePasswordAccount `
        -OnePasswordPython $OnePasswordPython `
        -AdminPassword $BootstrapAdminPassword `
        -RootPassword $SshPassword `
        -TimeoutSeconds $CredentialTimeoutSeconds `
        -ConsumerDescription 'VMware Photon image build'
    $credentialRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "atlaso-photon-build-credentials-$([guid]::NewGuid().ToString('N'))"
    )
    # Resolve every operator-controlled output and child path before publishing
    # an active cleanup marker, so a normalization failure cannot strand it.
    $childCredentialBundlePath = Join-Path $credentialRoot 'credentials.json'
    $childSensitiveBuildDirectory = Join-Path $credentialRoot 'sensitive-build'
    $childOutputCleanupClaimPath = Join-Path $credentialRoot 'output-cleanup-claimed.json'
    $outerCleanupPackerDirectory = if ([string]::IsNullOrWhiteSpace($PackerDirectory)) {
        Join-Path $PSScriptRoot '..\..\..\image\vmware-workstation'
    }
    else {
        $PackerDirectory
    }
    $outerCleanupOutputDirectory = Resolve-WorkstationOutputDirectory `
        -PackerDirectory $outerCleanupPackerDirectory `
        -OutputDirectory $OutputDirectory
    $outerCleanupOutputExistedBeforeChild = Test-Path -LiteralPath $outerCleanupOutputDirectory
    $preparedIsoLeaf = if ($PSBoundParameters.ContainsKey('PreparedIsoPath') -and
        -not [string]::IsNullOrWhiteSpace($PreparedIsoPath)) {
        [System.IO.Path]::GetFileName($PreparedIsoPath)
    }
    else {
        'atlaso-photon-with-kickstart.iso'
    }
    if ([string]::IsNullOrWhiteSpace($preparedIsoLeaf)) {
        $preparedIsoLeaf = 'atlaso-photon-with-kickstart.iso'
    }
    $childPreparedIsoPath = Join-Path (Join-Path $childSensitiveBuildDirectory 'kickstart') $preparedIsoLeaf
    if (-not $Headless -and -not $ValidateOnly) {
        # This parent is outside the sensitive Windows job and owns the only
        # permitted Workstation UI launch; descendants receive no breakaway right.
        $parentVmrunPath = Resolve-WorkstationVmrunPath -Path $VmrunPath
        $null = Initialize-AtlasoWorkstationGui -VmrunPath $parentVmrunPath
    }
    [void][System.IO.Directory]::CreateDirectory($credentialRoot)
    $cleanupMarkerDirectory = Split-Path -Parent $cleanupMarkerPath
    [void][System.IO.Directory]::CreateDirectory($cleanupMarkerDirectory)
    $cleanupMarkerPayload = [ordered]@{
        Schema       = 1
        RootPath     = [System.IO.Path]::GetFullPath($credentialRoot)
        BootIdentity = Get-AtlasoWindowsBootIdentity
        Phase        = 'active'
    }
    Write-AtlasoDurableJsonFile -Path $cleanupMarkerPath -Payload $cleanupMarkerPayload
    if (-not (Test-Path -LiteralPath $cleanupMarkerPath -PathType Leaf)) {
        throw 'Photon sensitive-cleanup ownership could not be established.'
    }
    $cleanupMarkerPayload = $null
    $processTreeTerminationUnproven = $false
    try {
        $credentialPayload = [ordered]@{
            AdminPasswordCiphertext = ConvertFrom-SecureString -SecureString $credentialPair.AdminPassword
            RootPasswordCiphertext  = ConvertFrom-SecureString -SecureString $credentialPair.RootPassword
        }
        [System.IO.File]::WriteAllText(
            $childCredentialBundlePath,
            ($credentialPayload | ConvertTo-Json -Compress),
            [System.Text.UTF8Encoding]::new($false)
        )
        $credentialPayload = $null
        $credentialPair = $null
        $SshPassword = $null
        $BootstrapAdminPassword = $null

        $childArguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive',
            '-File', $PSCommandPath,
            '-CredentialChild',
            '-CredentialBundlePath', $childCredentialBundlePath,
            '-SensitiveBuildDirectory', $childSensitiveBuildDirectory,
            '-OutputCleanupClaimPath', $childOutputCleanupClaimPath,
            '-PreparedIsoPath', $childPreparedIsoPath
        )
        $excludedParameters = @(
            'SshPassword', 'BootstrapAdminPassword',
            'OnePasswordEnvironmentId', 'EnvironmentIdFile',
            'OnePasswordAccount', 'OnePasswordPython',
            'CredentialTimeoutSeconds', 'ImageBuildTimeoutSeconds',
            'CredentialBundlePath', 'CredentialChild',
            'BuilderStaticDnsJson', 'BuilderStaticDnsBound',
            'SensitiveBuildDirectory', 'OutputCleanupClaimPath', 'PreparedIsoPath'
        )
        foreach ($entry in $PSBoundParameters.GetEnumerator()) {
            if ($entry.Key -in $excludedParameters) {
                continue
            }
            if ($entry.Value -is [switch]) {
                if ($entry.Value.IsPresent) {
                    $childArguments += "-$($entry.Key)"
                }
                continue
            }
            if ($entry.Key -ceq 'BuilderStaticDns' -and
                ($null -eq $entry.Value -or $entry.Value -is [array])) {
                $transportedDns = if ($null -eq $entry.Value) { @() } else { @($entry.Value) }
                $childArguments += '-BuilderStaticDnsJson'
                $childArguments += ConvertTo-Json -InputObject $transportedDns -Compress
                $childArguments += '-BuilderStaticDnsBound'
                continue
            }
            if ($entry.Value -is [array]) {
                if ($entry.Key -cne 'BuilderStaticDns') {
                    throw "Unsupported isolated Photon array parameter: $($entry.Key)."
                }
            }
            else {
                if ($null -eq $entry.Value) {
                    throw "Unsupported null isolated Photon parameter: $($entry.Key)."
                }
                $childArguments += "-$($entry.Key)"
                $childArguments += $entry.Value.ToString()
            }
        }
        try {
            Invoke-AtlasoBoundedStreamingProcess `
                -FilePath (Get-Process -Id $PID).Path `
                -ArgumentList $childArguments `
                -TimeoutSeconds $ImageBuildTimeoutSeconds `
                -Action 'The isolated VMware Photon image build'
        }
        catch {
            if ($_.Exception.Data['AtlasoProcessTreeTerminationUnproven']) {
                $processTreeTerminationUnproven = $true
                throw 'The isolated VMware Photon image build could not prove whole-tree termination. Restart Windows, then rerun this wrapper to complete sensitive cleanup.'
            }
            if ($_.Exception.Data['AtlasoProcessTreeTerminationProven'] -and
                $PackerOnError -eq 'cleanup' -and (
                    -not $outerCleanupOutputExistedBeforeChild -or
                    (-not $KeepExistingOutput -and
                        (Test-Path -LiteralPath $childOutputCleanupClaimPath -PathType Leaf))
                )) {
                if (Test-Path -LiteralPath $outerCleanupOutputDirectory) {
                    $cleanupVmrunPath = Resolve-WorkstationVmrunPath -Path $VmrunPath
                    Write-Host 'The outer image deadline selected checked VMware artifact cleanup.'
                    Remove-AtlasoWorkstationArtifactRoot `
                        -VmrunPath $cleanupVmrunPath `
                        -ExpectedRemovalRoot $outerCleanupOutputDirectory `
                        -RemovalRoot $outerCleanupOutputDirectory `
                        -Confirm:$false
                }
            }
            throw
        }
    }
    finally {
        $credentialPair = $null
        $SshPassword = $null
        $BootstrapAdminPassword = $null
        $resolvedCredentialRoot = [System.IO.Path]::GetFullPath($credentialRoot)
        $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if (-not $resolvedCredentialRoot.StartsWith($resolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedCredentialRoot) -notmatch '^atlaso-photon-build-credentials-[0-9a-f]{32}$') {
            throw 'Refusing to clean an invalid Photon credential bridge root.'
        }
        if (-not $processTreeTerminationUnproven) {
            $cleanupMarker = Get-Content -LiteralPath $cleanupMarkerPath -Raw -ErrorAction Stop |
                ConvertFrom-Json
            Complete-AtlasoPhotonBuildCleanup `
                -MarkerPath $cleanupMarkerPath `
                -Marker $cleanupMarker `
                -ExpectedRootPath $credentialRoot
        }
    }
    return
}

<#
.SYNOPSIS
Normalize and validate a VMware vmnet name.
.PARAMETER Name
Network name to normalize.
.PARAMETER ParameterName
Caller parameter name used in diagnostics.
#>
function ConvertTo-WorkstationVmnetName {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ParameterName
    )

    if ($Name -notmatch '^(?i)vmnet(\d+)$') {
        throw "$ParameterName must be a VMware Workstation VMnet name such as VMnet1; got '$Name'."
    }
    return "VMnet$($Matches[1])"
}

<#
.SYNOPSIS
Convert an IPv4 address to its integer representation.
.PARAMETER Address
IPv4 address to convert.
#>
function ConvertTo-Ipv4Integer {
    param([Parameter(Mandatory = $true)][string]$Address)

    $bytes = [System.Net.IPAddress]::Parse($Address).GetAddressBytes()
    if ($bytes.Count -ne 4) {
        throw "Expected an IPv4 address, got: $Address"
    }
    return (([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3])
}

<#
.SYNOPSIS
Convert an integer to an IPv4 address.
.PARAMETER Address
Unsigned 32-bit network-order address to render in dotted-decimal form.
#>
function ConvertFrom-Ipv4Integer {
    param([Parameter(Mandatory = $true)][uint32]$Address)

    $bytes = [byte[]]@(
        (($Address -shr 24) -band 0xff),
        (($Address -shr 16) -band 0xff),
        (($Address -shr 8) -band 0xff),
        ($Address -band 0xff)
    )
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

<#
.SYNOPSIS
Return the prefix length for a contiguous IPv4 netmask.
.PARAMETER Netmask
IPv4 netmask to validate.
#>
function Get-Ipv4PrefixLength {
    param([Parameter(Mandatory = $true)][string]$Netmask)

    $mask = ConvertTo-Ipv4Integer -Address $Netmask
    $prefix = 0
    $seenZero = $false
    for ($bit = 31; $bit -ge 0; $bit--) {
        $isSet = (($mask -shr $bit) -band 1) -eq 1
        if ($isSet -and $seenZero) {
            throw "Netmask is not contiguous: $Netmask"
        }
        if ($isSet) {
            $prefix++
        } else {
            $seenZero = $true
        }
    }
    return $prefix
}

<#
.SYNOPSIS
Return a host CIDR at an offset within an IPv4 subnet.
.PARAMETER Subnet
IPv4 subnet base address.
.PARAMETER Netmask
IPv4 subnet netmask.
.PARAMETER HostOffset
Host offset within the subnet.
#>
function Get-Ipv4CidrFromSubnetOffset {
    param(
        [Parameter(Mandatory = $true)][string]$Subnet,
        [Parameter(Mandatory = $true)][string]$Netmask,
        [Parameter(Mandatory = $true)][uint32]$HostOffset
    )

    $prefix = Get-Ipv4PrefixLength -Netmask $Netmask
    $hostBits = 32 - $prefix
    if ($hostBits -lt 2) {
        throw "VMware network $Subnet/$prefix does not have enough host addresses for a static Atlaso appliance address."
    }

    $hostCapacity = [uint64]1 -shl $hostBits
    if ([uint64]$HostOffset -ge ($hostCapacity - 1)) {
        throw "Host offset $HostOffset is outside VMware network $Subnet/$prefix."
    }

    $network = ConvertTo-Ipv4Integer -Address $Subnet
    $address = $network + $HostOffset
    return "$(ConvertFrom-Ipv4Integer -Address $address)/$prefix"
}

<#
.SYNOPSIS
Return a host address at an offset within an IPv4 subnet.
.PARAMETER Subnet
IPv4 subnet base address.
.PARAMETER Netmask
IPv4 subnet netmask.
.PARAMETER HostOffset
Host offset within the subnet.
#>
function Get-Ipv4AddressFromSubnetOffset {
    param(
        [Parameter(Mandatory = $true)][string]$Subnet,
        [Parameter(Mandatory = $true)][string]$Netmask,
        [Parameter(Mandatory = $true)][uint32]$HostOffset
    )

    return (Get-Ipv4CidrFromSubnetOffset -Subnet $Subnet -Netmask $Netmask -HostOffset $HostOffset) -split '/', 2 | Select-Object -First 1
}

<#
.SYNOPSIS
Resolve the VMware Workstation vmrun executable.
.PARAMETER Path
Optional explicit executable path.
#>
function Resolve-WorkstationVmrunPath {
    param([string]$Path)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "vmrun.exe not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    $candidates = @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

<#
.SYNOPSIS
Resolve the guarded VMware build output directory.
.PARAMETER PackerDirectory
VMware Packer template directory.
.PARAMETER OutputDirectory
Optional explicit artifact directory.
#>
function Resolve-WorkstationOutputDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$PackerDirectory,
        [string]$OutputDirectory
    )

    $effectiveOutput = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        Join-Path $PackerDirectory 'output\atlaso-photon-vmware-workstation'
    } elseif ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
        $OutputDirectory
    } else {
        Join-Path $PackerDirectory $OutputDirectory
    }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($effectiveOutput)
}

<#
.SYNOPSIS
Write and verify role-bound VMware build provenance.
.PARAMETER OutputDirectory
Completed Packer artifact directory.
.PARAMETER VmName
Expected VMX base name.
.PARAMETER RepoRoot
Source repository root.
#>
function Write-AtlasoVmwareBuildProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$VmName,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )

    $vmx = Get-Item -LiteralPath (Join-Path $OutputDirectory "$VmName.vmx") -ErrorAction Stop
    $payloadLayout = @(Get-AtlasoVmwarePayloadLayout -VmxPath $vmx.FullName -RequireExactlyTwoVmdks)
    $sourceCommit = [string](& git -C $RepoRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or $sourceCommit.Trim() -notmatch '^[0-9a-f]{40}$') {
        throw 'Could not resolve the exact source commit for the VMware image build.'
    }
    $trackedChanges = @(& git -C $RepoRoot status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not inspect tracked source changes for VMware image provenance.'
    }
    $provenance = [ordered]@{
        schema_version       = 2
        source_commit        = $sourceCommit.Trim()
        tracked_source_dirty = $trackedChanges.Count -ne 0
        vmx                  = [ordered]@{
            name   = $vmx.Name
            bytes  = $vmx.Length
            sha256 = (Get-FileHash -LiteralPath $vmx.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        payload_disks        = @($payloadLayout | ForEach-Object {
                [ordered]@{
                    role           = $_.Role
                    scsi_unit      = $_.ScsiUnit
                    name           = $_.File.Name
                    capacity_bytes = $_.CapacityBytes
                    bytes          = $_.File.Length
                    sha256         = (Get-FileHash -LiteralPath $_.File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            })
    }
    $provenancePath = [System.IO.Path]::ChangeExtension($vmx.FullName, 'provenance.json')
    $json = $provenance | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($provenancePath, "$json`n", [System.Text.UTF8Encoding]::new($false))
    $null = Assert-AtlasoVmwarePayloadProvenance -VmxPath $vmx.FullName -ProvenancePath $provenancePath
    Write-Host "VMware build provenance: $provenancePath ($($provenance.source_commit))"
}

<#
.SYNOPSIS
Return the validated VMware management-network build plan.
.PARAMETER NetworkName
Management vmnet name.
.PARAMETER ServiceNetworkName
Services vmnet name.
.PARAMETER ResolvedVmrunPath
Resolved vmrun executable.
.PARAMETER BridgedInterfaceAlias
Optional host adapter for bridged management.
#>
function Get-WorkstationManagementNetwork {
    param(
        [string]$NetworkName,
        [string]$ServiceNetworkName,
        [string]$ResolvedVmrunPath,
        [string]$BridgedInterfaceAlias
    )

    $networkArgs = @{
        VmrunPath         = $ResolvedVmrunPath
        ManagementNetwork = $NetworkName
        BridgedInterfaceAlias = $BridgedInterfaceAlias
        ManagementOnly    = $true
        PlanOnly          = $true
    }
    if ([string]::IsNullOrWhiteSpace($ResolvedVmrunPath)) {
        $networkArgs.Remove('VmrunPath')
    }
    if ([string]::IsNullOrWhiteSpace($BridgedInterfaceAlias)) {
        $networkArgs.Remove('BridgedInterfaceAlias')
    }

    $planText = (& (Join-Path $PSScriptRoot 'prepare-networks.ps1') @networkArgs | Out-String).Trim()
    if (-not $?) {
        throw 'VMware Workstation network discovery failed.'
    }
    $plan = $planText | ConvertFrom-Json
    if ($plan.missing_networks.Count -gt 0) {
        throw "Missing VMware Workstation networks: $($plan.missing_networks -join ', '). Create them in Virtual Network Editor, then rerun this script."
    }

    $name = $NetworkName.ToLowerInvariant()
    $management = $plan.discovered_networks | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $management) {
        throw "Management VMware network was not found: $NetworkName"
    }
    if ([string]::IsNullOrWhiteSpace($management.Subnet) -or [string]::IsNullOrWhiteSpace($management.Mask)) {
        throw "Management VMware network $NetworkName did not report an IPv4 subnet and mask."
    }

    if (-not [string]::IsNullOrWhiteSpace($ServiceNetworkName)) {
        $serviceName = $ServiceNetworkName.ToLowerInvariant()
        $service = $plan.discovered_networks | Where-Object { $_.Name -eq $serviceName } | Select-Object -First 1
        if (-not $service) {
            throw "Services VMware network was not found: $ServiceNetworkName. Create it in Virtual Network Editor, pass -ServiceVmnetName, or pass -SkipNetworkCheck."
        }
    }
    return $management
}

if ([string]::IsNullOrWhiteSpace($PackerDirectory)) {
    $PackerDirectory = Join-Path $PSScriptRoot '..\..\..\image\vmware-workstation'
}
$workstationOutputDirectory = Resolve-WorkstationOutputDirectory -PackerDirectory $PackerDirectory -OutputDirectory $OutputDirectory

$VmnetName = ConvertTo-WorkstationVmnetName -Name $VmnetName -ParameterName 'VmnetName'
$ServiceVmnetName = ConvertTo-WorkstationVmnetName -Name $ServiceVmnetName -ParameterName 'ServiceVmnetName'

$builderIpWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticIp')
$builderNetmaskWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticNetmask')
$builderGatewayWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticGateway')
$builderDnsWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticDns') -or $BuilderStaticDnsBound
$finalAddressWasPassed = $PSBoundParameters.ContainsKey('FinalMgmtAddress')
$finalGatewayWasPassed = $PSBoundParameters.ContainsKey('FinalMgmtGateway')

if (-not $SkipNetworkCheck) {
    $management = Get-WorkstationManagementNetwork -NetworkName $VmnetName -ServiceNetworkName $ServiceVmnetName -ResolvedVmrunPath $VmrunPath -BridgedInterfaceAlias $BridgedInterfaceAlias
    $managementGateway = if ($management.PSObject.Properties['Gateway'] -and -not [string]::IsNullOrWhiteSpace($management.Gateway)) {
        $management.Gateway
    } else {
        Get-Ipv4AddressFromSubnetOffset -Subnet $management.Subnet -Netmask $management.Mask -HostOffset 2
    }
    if (-not $builderNetmaskWasPassed) {
        $BuilderStaticNetmask = $management.Mask
    }
    if (-not $builderIpWasPassed) {
        $BuilderStaticIp = Get-Ipv4CidrFromSubnetOffset -Subnet $management.Subnet -Netmask $management.Mask -HostOffset 30
    }
    if (-not $builderGatewayWasPassed) {
        $BuilderStaticGateway = $managementGateway
    }
    if (-not $builderDnsWasPassed -and $BuilderStaticDns.Count -eq 0 -and $management.Type -eq 'nat') {
        $BuilderStaticDns = @($managementGateway)
        Write-Host "Using VMware NAT gateway DNS for Photon builder: $($BuilderStaticDns -join ', ')."
    }
    if (-not $finalAddressWasPassed) {
        $FinalMgmtAddress = 'dhcp'
    }
    if (-not $finalGatewayWasPassed -and $FinalMgmtAddress -ne 'dhcp') {
        $FinalMgmtGateway = $managementGateway
    }
    Write-Host "Using VMware management network $($management.Name) on $($management.Subnet)/$($management.Mask)."
    Write-Host "Using VMware services network $ServiceVmnetName for the second appliance NIC."
    Write-Host "Photon builder temporary SSH address: $BuilderStaticIp; final appliance management address: $FinalMgmtAddress."
}

if (-not $ValidateOnly -and -not $PrepareIsoOnly -and -not $SkipNetworkCheck) {
    $builderAddress = if ($BuilderStaticIp) { ($BuilderStaticIp -split '/', 2)[0] } else { '' }
    $managementSubnet = if ($builderAddress -match '^(\d+)\.(\d+)\.(\d+)\.') { "$($Matches[1]).$($Matches[2]).$($Matches[3]).0" } else { '192.168.49.0' }
    $networkArgs = @{
        VmrunPath          = $VmrunPath
        ManagementNetwork = $VmnetName
        ManagementSubnet  = $managementSubnet
        BridgedInterfaceAlias = $BridgedInterfaceAlias
        ManagementOnly    = $true
    }
    if ([string]::IsNullOrWhiteSpace($VmrunPath)) {
        $networkArgs.Remove('VmrunPath')
    }
    if ([string]::IsNullOrWhiteSpace($BridgedInterfaceAlias)) {
        $networkArgs.Remove('BridgedInterfaceAlias')
    }
    if ($AllowExistingManagementSubnet) {
        $networkArgs['AllowExistingManagementSubnet'] = $true
    }
    & (Join-Path $PSScriptRoot 'prepare-networks.ps1') @networkArgs | Out-Host
    if (-not $?) {
        throw 'VMware Workstation network validation failed.'
    }
}

$packerVariables = @{
    vmnet_name         = $VmnetName
    service_vmnet_name = $ServiceVmnetName
    headless           = [bool]$Headless
}

$packerBuildInvoker = $null
if (-not $ValidateOnly -and -not $PrepareIsoOnly) {
    $resolvedVmrunPath = Resolve-WorkstationVmrunPath -Path $VmrunPath
    if (-not $KeepExistingOutput) {
        # Claim a pre-existing output only after all network preparation has
        # completed and immediately before checked removal begins. The bounded
        # parent may finish that exact removal after proven child termination.
        Write-AtlasoDurableJsonFile -Path $resolvedOutputCleanupClaimPath -Payload ([ordered]@{
            Schema = 1
            OutputPath = $workstationOutputDirectory
        })
        Remove-AtlasoWorkstationArtifactRoot `
            -VmrunPath $resolvedVmrunPath `
            -ExpectedRemovalRoot $workstationOutputDirectory `
            -RemovalRoot $workstationOutputDirectory `
            -Confirm:$false
    }
    $builderAddress = if (-not [string]::IsNullOrWhiteSpace($SshHost)) {
        $SshHost
    }
    elseif ($BuilderStaticIp) {
        ($BuilderStaticIp -split '/', 2)[0]
    }
    else {
        ''
    }
    if ([string]::IsNullOrWhiteSpace($builderAddress)) {
        throw 'A configured builder address is required for bounded VMware startup monitoring.'
    }
    $builderVmxPath = Join-Path $workstationOutputDirectory "$VmName.vmx"
    $timeoutHandler = {
        param($SelectedOnError, $State, $Diagnostic)

        if ($SelectedOnError -eq 'cleanup' -and (Test-Path -LiteralPath $workstationOutputDirectory)) {
            Write-Host "Monitored Packer failure selected checked cleanup [$($Diagnostic.Code)]."
            Remove-AtlasoWorkstationArtifactRoot `
                -VmrunPath $resolvedVmrunPath `
                -ExpectedRemovalRoot $workstationOutputDirectory `
                -RemovalRoot $workstationOutputDirectory `
                -Confirm:$false
            return
        }
        Write-Warning "Monitored Packer failure preserved the exact builder artifacts because -PackerOnError is '$SelectedOnError'."
    }.GetNewClosure()
    $packerBuildInvoker = {
        param($PackerArguments, $WorkingDirectory)

        # ISO preparation and Packer initialization can be lengthy, so prove the
        # GUI provider is responsive at the last safe point before Packer starts.
        if (-not $Headless) {
            $requireExistingUi = {
                param($FilePath)
                throw 'The parent-launched VMware Workstation UI is no longer available.'
            }.GetNewClosure()
            $null = Initialize-AtlasoWorkstationGui `
                -VmrunPath $resolvedVmrunPath `
                -ProcessLauncher $requireExistingUi
        }
        $packerPath = (Get-Command packer -ErrorAction Stop).Source
        Invoke-AtlasoMonitoredPackerBuild `
            -PackerPath $packerPath `
            -Arguments $PackerArguments `
            -WorkingDirectory $WorkingDirectory `
            -VmrunPath $resolvedVmrunPath `
            -VmxPath $builderVmxPath `
            -BuilderAddress $builderAddress `
            -StartupTimeoutSeconds $PackerStartupTimeoutSeconds `
            -HeartbeatSeconds $PackerHeartbeatSeconds `
            -PackerOnError $PackerOnError `
            -TimeoutHandler $timeoutHandler
    }.GetNewClosure()
}

Invoke-AtlasoPhotonImageBuild `
    -IsoUrl $IsoUrl `
    -IsoChecksum $IsoChecksum `
    -PackerDirectory $PackerDirectory `
    -SshPassword $SshPassword `
    -BootstrapAdminPassword $BootstrapAdminPassword `
    -VmName $VmName `
    -OutputDirectory $OutputDirectory `
    -SshHost $SshHost `
    -SharedSourceDirectory $SharedSourceDirectory `
    -BuilderStaticIp $BuilderStaticIp `
    -BuilderStaticNetmask $BuilderStaticNetmask `
    -BuilderStaticGateway $BuilderStaticGateway `
    -BuilderStaticDns $BuilderStaticDns `
    -FinalMgmtAddress $FinalMgmtAddress `
    -FinalMgmtGateway $FinalMgmtGateway `
    -FinalMgmtInterface $FinalMgmtInterface `
    -PipGlobalIndex $PipGlobalIndex `
    -PipGlobalIndexUrl $PipGlobalIndexUrl `
    -PreparedIsoPath $PreparedIsoPath `
    -SensitiveBuildDirectory $SensitiveBuildDirectory `
    -PackerOnError $PackerOnError `
    -GuestPackages @('open-vm-tools', 'hyper-v') `
    -GuestPostInstallCommands @(
        'systemctl enable vmtoolsd || true',
        'systemctl enable hv_kvp_daemon || true',
        'systemctl enable hv_fcopy_daemon || true',
        'systemctl enable hv_vss_daemon || true'
    ) `
    -InstallDiskLayout 'vmware-workstation' `
    -AdditionalPackerVariables $packerVariables `
    -PackerBuildInvoker $packerBuildInvoker `
    -KeepExistingOutput:$KeepExistingOutput `
    -EnableRealSystemAdapters:$EnableRealSystemAdapters `
    -ValidateOnly:$ValidateOnly `
    -PrepareIsoOnly:$PrepareIsoOnly

if (-not $ValidateOnly -and -not $PrepareIsoOnly) {
    Write-AtlasoVmwareBuildProvenance `
        -OutputDirectory $workstationOutputDirectory `
        -VmName $VmName `
        -RepoRoot $repoRoot
}
