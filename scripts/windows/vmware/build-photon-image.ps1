[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
[CmdletBinding()]
param(
    [Parameter()]
    [string]$IsoUrl = 'https://packages.broadcom.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso',

    [Parameter()]
    [string]$IsoChecksum = 'sha512:6a7a258399a258da742032987c043ab25503698d35edafaf1ae000f12127da1a161d8b84caa17fd8f23d129e81e1faa7ab087c20ab9229772a643f8f9475305f',

    [string]$SshPassword = 'PhotonBuild01!',
    [string]$BootstrapAdminPassword = 'VMware01!',
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
    [string]$WslDistribution = 'Atlaso-Build',
    [ValidateSet('cleanup', 'abort', 'ask', 'run-cleanup-provisioner')]
    [string]$PackerOnError = 'cleanup',
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

Import-Module (Join-Path $PSScriptRoot '..\common\Atlaso.PhotonImage.psm1') -Force

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

function ConvertTo-Ipv4Integer {
    param([Parameter(Mandatory = $true)][string]$Address)

    $bytes = [System.Net.IPAddress]::Parse($Address).GetAddressBytes()
    if ($bytes.Count -ne 4) {
        throw "Expected an IPv4 address, got: $Address"
    }
    return (([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3])
}

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

function Get-Ipv4AddressFromSubnetOffset {
    param(
        [Parameter(Mandatory = $true)][string]$Subnet,
        [Parameter(Mandatory = $true)][string]$Netmask,
        [Parameter(Mandatory = $true)][uint32]$HostOffset
    )

    return (Get-Ipv4CidrFromSubnetOffset -Subnet $Subnet -Netmask $Netmask -HostOffset $HostOffset) -split '/', 2 | Select-Object -First 1
}

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

function Invoke-WorkstationVmrunBestEffort {
    param(
        [Parameter(Mandatory = $true)][string]$ResolvedVmrunPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    & $ResolvedVmrunPath @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "$FailureMessage vmrun $($Arguments -join ' ') exited with code $LASTEXITCODE."
    }
}

function Unregister-ExistingWorkstationTemplate {
    param(
        [Parameter(Mandatory = $true)][string]$ResolvedVmrunPath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$VmName
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
        return
    }

    $preferredVmx = Join-Path $OutputDirectory "$VmName.vmx"
    $vmx = if (Test-Path -LiteralPath $preferredVmx -PathType Leaf) {
        Get-Item -LiteralPath $preferredVmx
    } else {
        Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.vmx' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if (-not $vmx) {
        return
    }

    $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path.TrimEnd('\')
    $resolvedVmx = (Resolve-Path -LiteralPath $vmx.FullName).Path
    if (-not ($resolvedVmx.StartsWith($resolvedOutput + '\', [System.StringComparison]::OrdinalIgnoreCase))) {
        throw "Refusing to unregister VMware template outside the configured image output directory: $resolvedVmx"
    }

    Write-Host "Unregistering existing VMware Workstation template before replacing output: $resolvedVmx"
    Invoke-WorkstationVmrunBestEffort -ResolvedVmrunPath $ResolvedVmrunPath -Arguments @('-T', 'ws', 'stop', $resolvedVmx, 'hard') -FailureMessage 'Existing template was not running or could not be stopped; continuing to unregister.'
    Invoke-WorkstationVmrunBestEffort -ResolvedVmrunPath $ResolvedVmrunPath -Arguments @('-T', 'ws', 'unregister', $resolvedVmx) -FailureMessage 'Existing template could not be unregistered before rebuild.'
}

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

if (-not $ValidateOnly -and -not $PrepareIsoOnly -and -not $KeepExistingOutput) {
    $resolvedVmrunPath = Resolve-WorkstationVmrunPath -Path $VmrunPath
    $workstationOutputDirectory = Resolve-WorkstationOutputDirectory -PackerDirectory $PackerDirectory -OutputDirectory $OutputDirectory
    Unregister-ExistingWorkstationTemplate -ResolvedVmrunPath $resolvedVmrunPath -OutputDirectory $workstationOutputDirectory -VmName $VmName
}

if (-not $ValidateOnly -and -not $PrepareIsoOnly) {
    & (Join-Path $PSScriptRoot '..\common\Build-AtlasoInventoryLinux.ps1') -WslDistribution $WslDistribution
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
    -AdditionalPackerVariables $packerVariables `
    -KeepExistingOutput:$KeepExistingOutput `
    -EnableRealSystemAdapters:$EnableRealSystemAdapters `
    -ValidateOnly:$ValidateOnly `
    -PrepareIsoOnly:$PrepareIsoOnly
