<#
.SYNOPSIS
Build or validate the supported Atlaso VMware Workstation Photon image.
.PARAMETER IsoUrl
Pinned Photon source URL or local path.
.PARAMETER IsoChecksum
Expected Photon ISO checksum.
.PARAMETER SshPassword
Temporary Packer SSH password. The wrapper prompts securely when omitted.
.PARAMETER BootstrapAdminPassword
Initial appliance administrator password. The wrapper prompts securely when omitted.
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
Stop after preparing the remastered ISO.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$IsoUrl = 'https://packages.broadcom.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso',

    [Parameter()]
    [string]$IsoChecksum = 'sha512:6a7a258399a258da742032987c043ab25503698d35edafaf1ae000f12127da1a161d8b84caa17fd8f23d129e81e1faa7ab087c20ab9229772a643f8f9475305f',

    [SecureString]$SshPassword,
    [SecureString]$BootstrapAdminPassword,
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

# Passwords have no repository defaults; resolve them before network or build mutation.
if ($null -eq $SshPassword) {
    $SshPassword = Read-Host -Prompt 'Temporary Photon builder SSH password' -AsSecureString
}
if ($null -eq $BootstrapAdminPassword) {
    $BootstrapAdminPassword = Read-Host -Prompt 'Atlaso bootstrap administrator password' -AsSecureString
}

Import-Module (Join-Path $PSScriptRoot '..\common\Atlaso.PhotonImage.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwarePayload.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationBuildMonitor.psm1') -Force

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
Integer address value.
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
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path

$VmnetName = ConvertTo-WorkstationVmnetName -Name $VmnetName -ParameterName 'VmnetName'
$ServiceVmnetName = ConvertTo-WorkstationVmnetName -Name $ServiceVmnetName -ParameterName 'ServiceVmnetName'

$builderIpWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticIp')
$builderNetmaskWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticNetmask')
$builderGatewayWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticGateway')
$builderDnsWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticDns')
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
            $null = Initialize-AtlasoWorkstationGui -VmrunPath $resolvedVmrunPath
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
    -PackerOnError $PackerOnError `
    -GuestPackages @('open-vm-tools') `
    -GuestPostInstallCommands @('systemctl enable vmtoolsd || true') `
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
