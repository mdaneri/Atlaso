[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$LabName = 'AtlasoLifecycle',
    [Parameter(Mandatory = $true)]
    [string]$ApplianceVhdxPath,
    [string]$ClientVhdxPath = '',
    [string]$EsxIsoPath = '',
    [string]$ClientManagementSwitch = 'Default Switch',
    [string]$ApplianceIPAddress = '192.168.49.1',
    [string]$ApplianceUrl = '',
    [int64]$ApplianceMemoryStartupBytes = 4GB,
    [int64]$ClientMemoryStartupBytes = 1GB,
    [int]$ApplianceProcessorCount = 2,
    [int]$ClientProcessorCount = 1,
    [string]$SiteInterface = 'eth1.12',
    [string]$SiteCidr = '192.168.12.1/24',
    [int]$SiteVlanId = 12,
    [int]$VlanId = 50,
    [string]$TaggedVlanCidr = '192.168.60.1/24',
    [string]$WanCidr = '172.31.50.1/24',
    [string]$AdminUsername = 'admin',
    [Parameter(Mandatory = $true)]
    [string]$AdminPassword,
    [string]$SshUser = '',
    [string]$ApplianceSshUser = 'admin',
    [string]$ClientSshUser = 'alpine',
    [string]$SshKeyPath = '',
    [string]$SshPassword = '',
    [string]$VcfBackupPassword = 'VMware01!Test',
    [string]$SignedReleaseRepositoryUrl = '',
    [switch]$AllowDryRunApply,
    [switch]$SkipBackupRestoreTest,
    [switch]$AllowExistingLifecycleLab,
    [switch]$CleanupCreatedLab,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
if (-not $ApplianceUrl) {
    $ApplianceUrl = "https://${ApplianceIPAddress}"
}
if (-not $ClientVhdxPath) {
    $ClientVhdxPath = Join-Path $repoRoot 'image\hyperv\clients\alpine-cloud\atlaso-tiny-linux-client.vhdx'
}
$resultStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultRoot = Join-Path $repoRoot "test-results\hyperv-lifecycle\$resultStamp"
$diskRoot = Join-Path $resultRoot 'disks'
$seedRoot = Join-Path $resultRoot 'seed'
$createdVms = New-Object System.Collections.Generic.List[string]

function Assert-SafeLifecycleName {
    param([string]$Name)

    $reserved = @('Atlaso', 'Atlaso-Photon-Builder')
    if ($reserved -contains $Name) {
        throw "Refusing to use reserved VM name '$Name'. Lifecycle tests must use a separate VM set."
    }
    if (-not $Name.StartsWith($LabName)) {
        throw "Refusing VM name '$Name' because it does not start with lifecycle lab prefix '$LabName'."
    }
}

function Assert-InputVhdx {
    param([string]$Path, [string]$Label)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label VHDX not found: $Path"
    }
}

function New-LifecycleDifferencingDisk {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$ParentPath,
        [string]$ChildPath,
        [string]$Label
    )

    if (Test-Path -LiteralPath $ChildPath) {
        throw "$Label differencing disk already exists: $ChildPath"
    }
    if ($PSCmdlet.ShouldProcess($ChildPath, "Create $Label differencing disk")) {
        New-VHD -Path $ChildPath -ParentPath (Resolve-Path -LiteralPath $ParentPath) -Differencing | Out-Null
    }
}

function New-LifecycleVm {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Name,
        [string]$VhdxPath,
        [string]$SwitchName,
        [int64]$MemoryStartupBytes,
        [int]$ProcessorCount
    )

    Assert-SafeLifecycleName -Name $Name
    $existing = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if ($existing -and -not $AllowExistingLifecycleLab) {
        throw "Lifecycle VM already exists: $Name. Use a new -LabName or pass -AllowExistingLifecycleLab to reuse it."
    }
    if ($existing) {
        Write-Host "Reusing lifecycle VM: $Name"
        return
    }
    if ($PSCmdlet.ShouldProcess($Name, 'Create lifecycle Hyper-V VM')) {
        New-VM -Name $Name -Generation 2 -MemoryStartupBytes $MemoryStartupBytes -VHDPath $VhdxPath -SwitchName $SwitchName | Out-Null
        Set-VMProcessor -VMName $Name -Count $ProcessorCount
        Set-VMFirmware -VMName $Name -EnableSecureBoot Off
        if (-not $createdVms.Contains($Name)) {
            $createdVms.Add($Name)
        }
        Write-Host "Created lifecycle VM: $Name"
    }
}

function Ensure-ClientSshKey {
    if (-not $SshKeyPath) {
        if ($SshPassword) {
            return ''
        }
        throw 'Client SSH access requires -SshPassword or an existing -SshKeyPath.'
    }
    $publicPath = "$SshKeyPath.pub"
    if (-not (Test-Path -LiteralPath $publicPath)) {
        throw "SSH public key not found: $publicPath"
    }
    return (Get-Content -LiteralPath $publicPath -Raw).Trim()
}

function New-CloudInitSeedIso {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Path,
        [string]$HostName,
        [string]$PublicKey = ''
    )

    if (Test-Path -LiteralPath $Path) {
        if (-not $AllowExistingLifecycleLab) {
            throw "Cloud-init seed disk already exists: $Path"
        }
        return
    }

    if ($PSCmdlet.ShouldProcess($Path, "Create NoCloud seed disk for $HostName")) {
        python -c 'import pycdlib' 2>$null
        if ($LASTEXITCODE -ne 0) {
            python -m pip install pycdlib
        }
        $helper = Join-Path $repoRoot 'scripts\interop\create_nocloud_seed_iso.py'
        $arguments = @(
            $helper,
            '--output', $Path,
            '--hostname', $HostName,
            '--user', $ClientSshUser
        )
        if ($PublicKey) {
            $arguments += @('--public-key', $PublicKey)
        }
        if ($SshPassword) {
            $arguments += @('--password', $SshPassword)
        }
        python @arguments | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create NoCloud seed ISO for $HostName"
        }
    }
}

function Ensure-HardDisk {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$VMName,
        [string]$Path
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $existing = Get-VMHardDiskDrive -VMName $VMName | Where-Object { $_.Path -eq $resolved }
    if ($existing) {
        return
    }
    if ($PSCmdlet.ShouldProcess($VMName, "Attach disk $resolved")) {
        Add-VMHardDiskDrive -VMName $VMName -Path $resolved
    }
}

function Ensure-DvdDrive {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$VMName,
        [string]$Path
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $existing = Get-VMDvdDrive -VMName $VMName -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $resolved }
    if ($existing) {
        return
    }
    $dvd = Get-VMDvdDrive -VMName $VMName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dvd) {
        if ($PSCmdlet.ShouldProcess($VMName, "Attach seed ISO $resolved")) {
            Set-VMDvdDrive -VMName $VMName -ControllerNumber $dvd.ControllerNumber -ControllerLocation $dvd.ControllerLocation -Path $resolved
        }
        return
    }
    if ($PSCmdlet.ShouldProcess($VMName, "Add seed ISO $resolved")) {
        Add-VMDvdDrive -VMName $VMName -Path $resolved
    }
}

function Ensure-NetworkAdapter {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$VMName,
        [string]$Name,
        [string]$SwitchName
    )

    $adapter = Get-VMNetworkAdapter -VMName $VMName -Name $Name -ErrorAction SilentlyContinue
    if ($adapter) {
        if ($adapter.SwitchName -ne $SwitchName) {
            if ($PSCmdlet.ShouldProcess("$VMName/$Name", "Connect to $SwitchName")) {
                Connect-VMNetworkAdapter -VMName $VMName -Name $Name -SwitchName $SwitchName
            }
        }
        return
    }
    if ($PSCmdlet.ShouldProcess("$VMName/$Name", "Add NIC on $SwitchName")) {
        Add-VMNetworkAdapter -VMName $VMName -Name $Name -SwitchName $SwitchName
    }
}

function Set-LifecycleNetworkTopology {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Ensure-NetworkAdapter -VMName $applianceName -Name 'SiteA' -SwitchName 'Atlaso-SiteA'
    Ensure-NetworkAdapter -VMName $applianceName -Name 'Trunk' -SwitchName 'Atlaso-Trunk'
    Ensure-NetworkAdapter -VMName $applianceName -Name 'WAN-Test' -SwitchName 'Atlaso-SiteB'
    Ensure-NetworkAdapter -VMName $clientAName -Name 'SiteA-Test' -SwitchName 'Atlaso-SiteA'
    Ensure-NetworkAdapter -VMName $clientAName -Name 'VLAN-Test' -SwitchName 'Atlaso-Trunk'
    Ensure-NetworkAdapter -VMName $clientAName -Name 'Appliance-Mgmt-Test' -SwitchName 'Atlaso-Mgmt'
    Ensure-NetworkAdapter -VMName $clientBName -Name 'WAN-Test' -SwitchName 'Atlaso-SiteB'
    Ensure-NetworkAdapter -VMName $pxeClientName -Name 'PXE-SiteA' -SwitchName 'Atlaso-SiteA'

    if ($PSCmdlet.ShouldProcess("$applianceName/Trunk", "Enable trunk VLAN $VlanId")) {
        Set-VMNetworkAdapterVlan -VMName $applianceName -VMNetworkAdapterName 'Trunk' -Trunk -AllowedVlanIdList "$VlanId" -NativeVlanId 0
    }
    if ($PSCmdlet.ShouldProcess("$clientAName/VLAN-Test", "Enable access VLAN $VlanId")) {
        Set-VMNetworkAdapterVlan -VMName $clientAName -VMNetworkAdapterName 'VLAN-Test' -Access -VlanId $VlanId
    }
    if ($SiteInterface -match '\.(\d+)$') {
        $siteTaggedVlanId = [int]$Matches[1]
        if ($SiteVlanId -ne $siteTaggedVlanId) {
            throw "SiteInterface $SiteInterface uses VLAN $siteTaggedVlanId but SiteVlanId is $SiteVlanId."
        }
        if ($PSCmdlet.ShouldProcess("$applianceName/SiteA", "Enable trunk VLAN $SiteVlanId")) {
            Set-VMNetworkAdapterVlan -VMName $applianceName -VMNetworkAdapterName 'SiteA' -Trunk -AllowedVlanIdList "$SiteVlanId" -NativeVlanId 0
        }
        if ($PSCmdlet.ShouldProcess("$clientAName/SiteA-Test", "Enable access VLAN $SiteVlanId")) {
            Set-VMNetworkAdapterVlan -VMName $clientAName -VMNetworkAdapterName 'SiteA-Test' -Access -VlanId $SiteVlanId
        }
        if ($PSCmdlet.ShouldProcess("$pxeClientName/PXE-SiteA", "Enable access VLAN $SiteVlanId")) {
            Set-VMNetworkAdapterVlan -VMName $pxeClientName -VMNetworkAdapterName 'PXE-SiteA' -Access -VlanId $SiteVlanId
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess("$applianceName/SiteA", 'Use untagged SiteA traffic')) {
            Set-VMNetworkAdapterVlan -VMName $applianceName -VMNetworkAdapterName 'SiteA' -Untagged
        }
        if ($PSCmdlet.ShouldProcess("$clientAName/SiteA-Test", 'Use untagged SiteA traffic')) {
            Set-VMNetworkAdapterVlan -VMName $clientAName -VMNetworkAdapterName 'SiteA-Test' -Untagged
        }
        if ($PSCmdlet.ShouldProcess("$pxeClientName/PXE-SiteA", 'Use untagged SiteA traffic')) {
            Set-VMNetworkAdapterVlan -VMName $pxeClientName -VMNetworkAdapterName 'PXE-SiteA' -Untagged
        }
    }
}

function Wait-VMRunning {
    param([string]$Name)

    $deadline = (Get-Date).AddMinutes(5)
    while ((Get-Date) -lt $deadline) {
        $vm = Get-VM -Name $Name -ErrorAction Stop
        if ($vm.State -eq 'Running') {
            return
        }
        Start-Sleep -Seconds 3
    }
    throw "VM did not reach Running state: $Name"
}

function Get-GuestIPv4 {
    param(
        [string]$Name,
        [string]$AdapterName = ''
    )

    $addresses = Get-VMNetworkAdapter -VMName $Name |
    Select-Object -ExpandProperty IPAddresses |
    Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notlike '169.254.*' }
    return $addresses | Select-Object -First 1
}

function ConvertTo-HyphenMac {
    param([string]$MacAddress)

    $clean = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($clean.Length -ne 12) {
        return $MacAddress.ToUpperInvariant()
    }
    $pairs = for ($index = 0; $index -lt 12; $index += 2) { $clean.Substring($index, 2) }
    return ($pairs -join '-')
}

function ConvertTo-ColonMac {
    param([string]$MacAddress)

    $clean = ($MacAddress -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
    if ($clean.Length -ne 12) {
        return $MacAddress.ToLowerInvariant()
    }
    $pairs = for ($index = 0; $index -lt 12; $index += 2) { $clean.Substring($index, 2) }
    return ($pairs -join ':')
}

function ConvertTo-ShellSingleQuoted {
    param([string]$Value)

    $safe = $Value.Replace("'", "")
    return "'$safe'"
}

function New-LifecyclePxeVm {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$Name,
        [string]$SwitchName,
        [string]$DiskPath
    )

    Assert-SafeLifecycleName -Name $Name
    $existing = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if ($existing -and -not $AllowExistingLifecycleLab) {
        throw "Lifecycle PXE VM already exists: $Name. Use a new -LabName or pass -AllowExistingLifecycleLab to reuse it."
    }
    if ($existing) {
        Write-Host "Reusing lifecycle PXE VM: $Name"
    }
    elseif ($PSCmdlet.ShouldProcess($Name, 'Create lifecycle PXE-only Hyper-V VM')) {
        New-VM -Name $Name -Generation 2 -MemoryStartupBytes 1GB -SwitchName $SwitchName | Out-Null
        Set-VMProcessor -VMName $Name -Count 1
        Set-VMFirmware -VMName $Name -EnableSecureBoot Off
        New-VHD -Path $DiskPath -Dynamic -SizeBytes 1GB | Out-Null
        Add-VMHardDiskDrive -VMName $Name -Path $DiskPath
        if (-not $createdVms.Contains($Name)) {
            $createdVms.Add($Name)
        }
        Write-Host "Created lifecycle PXE VM: $Name"
    }

    $adapter = Get-VMNetworkAdapter -VMName $Name | Select-Object -First 1
    if ($adapter -and $adapter.Name -ne 'PXE-SiteA' -and -not (Get-VMNetworkAdapter -VMName $Name -Name 'PXE-SiteA' -ErrorAction SilentlyContinue)) {
        Rename-VMNetworkAdapter -VMName $Name -Name $adapter.Name -NewName 'PXE-SiteA'
        $adapter = Get-VMNetworkAdapter -VMName $Name -Name 'PXE-SiteA'
    }
    if ($adapter -and $PSCmdlet.ShouldProcess($Name, 'Prefer network adapter for PXE boot')) {
        Set-VMFirmware -VMName $Name -FirstBootDevice $adapter -EnableSecureBoot Off
    }
}

function Get-PxeClientMac {
    param([string]$Name)

    $adapter = Get-VMNetworkAdapter -VMName $Name | Select-Object -First 1
    if (-not $adapter) {
        throw "PXE VM has no network adapter: $Name"
    }
    return ConvertTo-ColonMac -MacAddress $adapter.MacAddress
}

function Copy-EsxIsoToAppliance {
    param([string]$Path)

    if (-not $Path) {
        return ''
    }
    if (-not (Get-Command plink -ErrorAction SilentlyContinue) -or -not (Get-Command pscp -ErrorAction SilentlyContinue)) {
        throw "Staging -EsxIsoPath requires plink and pscp in PATH."
    }
    $fileName = [System.IO.Path]::GetFileName($Path)
    $remoteRoot = '/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST'
    $remoteTmp = "/tmp/$fileName"
    $remotePath = "$remoteRoot/$fileName"
    $quotedRoot = ConvertTo-ShellSingleQuoted -Value $remoteRoot
    $quotedTmp = ConvertTo-ShellSingleQuoted -Value $remoteTmp
    $quotedPath = ConvertTo-ShellSingleQuoted -Value $remotePath
    $quotedPassword = ConvertTo-ShellSingleQuoted -Value $SshPassword

    & plink -batch -ssh -pw $SshPassword "$ApplianceSshUser@$ApplianceIPAddress" "printf '%s\n' $quotedPassword | sudo -S mkdir -p $quotedRoot"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create remote ESX ISO directory on the appliance."
    }
    & pscp -batch -pw $SshPassword $Path "$ApplianceSshUser@${ApplianceIPAddress}:$remoteTmp"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to copy ESX ISO to appliance staging path."
    }
    & plink -batch -ssh -pw $SshPassword "$ApplianceSshUser@$ApplianceIPAddress" "printf '%s\n' $quotedPassword | sudo -S mv $quotedTmp $quotedPath"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install ESX ISO under $remoteRoot on the appliance."
    }
    & plink -batch -ssh -pw $SshPassword "$ApplianceSshUser@$ApplianceIPAddress" "printf '%s\n' $quotedPassword | sudo -S chmod 0644 $quotedPath"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to chmod ESX ISO under $remoteRoot on the appliance."
    }
    & plink -batch -ssh -pw $SshPassword "$ApplianceSshUser@$ApplianceIPAddress" "printf '%s\n' $quotedPassword | sudo -S chown atlaso:atlaso $quotedPath"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to chown ESX ISO under $remoteRoot on the appliance."
    }
    return $remotePath
}

function Invoke-PxeBootSmoke {
    param(
        [string]$Name,
        [string]$MacAddress,
        [string]$OutputPath
    )

    $leaseSeen = $false
    $leaseOutput = ''
    if ((Get-VM -Name $Name).State -ne 'Off') {
        Stop-VM -Name $Name -Force -TurnOff -ErrorAction SilentlyContinue
    }
    if ($PSCmdlet.ShouldProcess($Name, 'Start PXE boot smoke VM')) {
        Start-VM -Name $Name
    }
    Wait-VMRunning -Name $Name
    Start-Sleep -Seconds 45

    if ((Get-Command plink -ErrorAction SilentlyContinue) -and $SshPassword) {
        $quotedPassword = ConvertTo-ShellSingleQuoted -Value $SshPassword
        $quotedMac = ConvertTo-ShellSingleQuoted -Value $MacAddress
        $leaseCommand = "printf '%s\n' $quotedPassword | sudo -S grep -i $quotedMac /var/lib/atlaso/dnsmasq/dhcp.leases 2>/dev/null || true"
        $plinkArgs = @('-batch', '-ssh')
        if ($script:applianceHostKey) {
            $plinkArgs += @('-hostkey', $script:applianceHostKey)
        }
        $plinkArgs += @('-pw', $SshPassword, "$ApplianceSshUser@$ApplianceIPAddress", $leaseCommand)
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $leaseOutput = (& plink @plinkArgs 2>&1 | Out-String).Trim()
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $leaseSeen = $leaseOutput -match [regex]::Escape($MacAddress)
    }

    $adapter = Get-VMNetworkAdapter -VMName $Name | Select-Object -First 1
    [pscustomobject]@{
        vm_name          = $Name
        started          = ((Get-VM -Name $Name).State -eq 'Running')
        mac_address      = $MacAddress
        switch_name      = $adapter.SwitchName
        appliance_ip     = $ApplianceIPAddress
        lease_seen       = $leaseSeen
        lease_observation = if ($leaseSeen) { 'dnsmasq lease file contains the PXE VM MAC.' } else { 'PXE VM started; lease observation was not available.' }
        lease_output     = $leaseOutput
        observed_at      = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Host "PXE boot smoke result: $OutputPath"
}

function Invoke-NetworkBootInventoryProof {
    param(
        [string]$Name,
        [string]$MacAddress,
        [string]$OutputPath
    )

    $before = (Get-VM -Name $Name).Uptime
    try {
        $env:ATLASO_LIFECYCLE_ADMIN_PASSWORD = $AdminPassword
        python (Join-Path $repoRoot 'scripts\interop\network_boot_lifecycle.py') `
            --appliance-url $ApplianceUrl `
            --username $AdminUsername `
            --mac $MacAddress `
            --output $OutputPath
        if ($LASTEXITCODE -ne 0) {
            throw "Network Boot inventory proof failed with exit code $LASTEXITCODE."
        }
    } finally {
        Remove-Item Env:\ATLASO_LIFECYCLE_ADMIN_PASSWORD -ErrorAction SilentlyContinue
    }
    $deadline = (Get-Date).AddSeconds(90)
    do {
        Start-Sleep -Seconds 2
        $current = (Get-VM -Name $Name).Uptime
        if ($current -lt $before) {
            Write-Host "Inventory Linux reboot proof: VM uptime reset from $before to $current."
            return
        }
    } while ((Get-Date) -lt $deadline)
    throw "Inventory Linux acknowledged reboot, but Hyper-V VM uptime did not reset."
}

function Get-NeighborIPv4ForAdapter {
    param(
        [string]$VMName,
        [string]$AdapterName
    )

    $adapter = Get-VMNetworkAdapter -VMName $VMName -Name $AdapterName -ErrorAction SilentlyContinue
    if (-not $adapter) {
        return ''
    }
    $mac = ConvertTo-HyphenMac -MacAddress $adapter.MacAddress
    $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.LinkLayerAddress -eq $mac -and
        $_.IPAddress -match '^\d+\.\d+\.\d+\.\d+$' -and
        $_.IPAddress -notlike '169.254.*' -and
        $_.State -ne 'Unreachable'
    } |
    Sort-Object -Property State, IPAddress
    return $neighbors | Select-Object -ExpandProperty IPAddress -First 1
}

function Wait-GuestIPv4 {
    param(
        [string]$Name,
        [string]$AdapterName = 'Network Adapter'
    )

    $deadline = (Get-Date).AddMinutes(4)
    while ((Get-Date) -lt $deadline) {
        $address = Get-GuestIPv4 -Name $Name -AdapterName $AdapterName
        if ($address) {
            return $address
        }
        $address = Get-NeighborIPv4ForAdapter -VMName $Name -AdapterName $AdapterName
        if ($address) {
            return $address
        }
        Start-Sleep -Seconds 5
    }
    return ''
}

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMilliseconds = 1000
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return $false
        }
        $client.EndConnect($connect)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Get-PlinkHostKey {
    param(
        [string]$HostName,
        [string]$UserName,
        [string]$Password
    )

    if (-not $HostName -or -not $Password -or -not (Get-Command plink -ErrorAction SilentlyContinue)) {
        return ''
    }

    $deadline = (Get-Date).AddMinutes(4)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-TcpPort -HostName $HostName -Port 22 -TimeoutMilliseconds 1000)) {
            Start-Sleep -Seconds 5
            continue
        }

        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & plink -batch -ssh -pw $Password "$UserName@$HostName" 'hostname' 2>&1
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $text = ($output | Out-String)
        if ($text -match '(ssh-[A-Za-z0-9-]+\s+\d+\s+SHA256:[A-Za-z0-9+/=]+)') {
            return $Matches[1]
        }
        if ($exitCode -eq 0) {
            return ''
        }
        Start-Sleep -Seconds 5
    }
    Write-Warning "Timed out waiting for SSH host key from $UserName@$HostName; continuing without host key pinning."
    return ''
}

function Resolve-SafeChildPath {
    param(
        [string]$Path,
        [string]$Root
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = "$rootFull\"
    if (-not ($pathFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase))) {
        throw "Refusing to operate on path outside lifecycle artifact root: $pathFull"
    }
    return $pathFull
}

function Reset-LifecycleApplianceVm {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    Assert-SafeLifecycleName -Name $applianceName
    $safeApplianceDisk = Resolve-SafeChildPath -Path $applianceDisk -Root $diskRoot

    $existing = Get-VM -Name $applianceName -ErrorAction SilentlyContinue
    if ($existing) {
        if ($PSCmdlet.ShouldProcess($applianceName, 'Remove lifecycle appliance VM before restore validation redeploy')) {
            Stop-VM -Name $applianceName -Force -TurnOff -ErrorAction SilentlyContinue
            Remove-VM -Name $applianceName -Force
        }
    }
    if (Test-Path -LiteralPath $safeApplianceDisk) {
        if ($PSCmdlet.ShouldProcess($safeApplianceDisk, 'Remove lifecycle appliance differencing disk before restore validation redeploy')) {
            Remove-Item -LiteralPath $safeApplianceDisk -Force
        }
    }

    New-LifecycleDifferencingDisk -ParentPath $ApplianceVhdxPath -ChildPath $safeApplianceDisk -Label 'restored appliance'
    New-LifecycleVm -Name $applianceName -VhdxPath $safeApplianceDisk -SwitchName 'Atlaso-Mgmt' -MemoryStartupBytes $ApplianceMemoryStartupBytes -ProcessorCount $ApplianceProcessorCount
    Set-LifecycleNetworkTopology
    if ((Get-VM -Name $applianceName).State -ne 'Running') {
        if ($PSCmdlet.ShouldProcess($applianceName, 'Start redeployed lifecycle appliance VM')) {
            Start-VM -Name $applianceName
        }
    }
    Wait-VMRunning -Name $applianceName
    Start-Sleep -Seconds 20
    return Get-PlinkHostKey -HostName $ApplianceIPAddress -UserName $ApplianceSshUser -Password $SshPassword
}

$applianceName = "$LabName-Appliance"
$clientAName = "$LabName-ClientA"
$clientBName = "$LabName-ClientB"
$pxeClientName = "$LabName-PxeBoot"

foreach ($name in @($applianceName, $clientAName, $clientBName, $pxeClientName)) {
    Assert-SafeLifecycleName -Name $name
    if ((Get-VM -Name $name -ErrorAction SilentlyContinue) -and -not $AllowExistingLifecycleLab) {
        throw "Lifecycle VM already exists: $name. Use a new -LabName or pass -AllowExistingLifecycleLab to reuse it."
    }
}

Assert-InputVhdx -Path $ApplianceVhdxPath -Label 'Appliance'
Assert-InputVhdx -Path $ClientVhdxPath -Label 'Client'
if ($EsxIsoPath) {
    if (-not (Test-Path -LiteralPath $EsxIsoPath)) {
        throw "ESX ISO not found: $EsxIsoPath"
    }
    if ([System.IO.Path]::GetExtension($EsxIsoPath).ToLowerInvariant() -ne '.iso') {
        throw "-EsxIsoPath must point to an .iso file."
    }
}

if (-not $VcfBackupPassword) {
    $VcfBackupPassword = 'VMware01!Test'
}

if ($PlanOnly) {
    [pscustomobject]@{
        lab_name                 = $LabName
        appliance_vm             = $applianceName
        client_a_vm              = $clientAName
        client_b_vm              = $clientBName
        pxe_boot_vm              = $pxeClientName
        appliance_vhdx           = (Resolve-Path -LiteralPath $ApplianceVhdxPath).Path
        client_vhdx              = (Resolve-Path -LiteralPath $ClientVhdxPath).Path
        pxe_boot_test            = $true
        pxe_boot_mode            = if ($EsxIsoPath) { 'esxi' } else { 'linux' }
        esx_iso_path             = if ($EsxIsoPath) { (Resolve-Path -LiteralPath $EsxIsoPath).Path } else { '' }
        site_interface           = $SiteInterface
        site_cidr                = $SiteCidr
        site_vlan_id             = $SiteVlanId
        tagged_vlan_id           = $VlanId
        tagged_vlan_cidr         = $TaggedVlanCidr
        wan_cidr                 = $WanCidr
        result_root              = $resultRoot
        appliance_url            = $ApplianceUrl
        signed_release_repository = $SignedReleaseRepositoryUrl
        backup_restore_test      = -not [bool]$SkipBackupRestoreTest
        cleanup_created_lab      = [bool]$CleanupCreatedLab
        reserved_vms_not_touched = @('Atlaso', 'Atlaso-Photon-Builder')
    } | ConvertTo-Json -Depth 5
    return
}

$existingPrimary = Get-VM -Name 'Atlaso' -ErrorAction SilentlyContinue
if ($existingPrimary -and $existingPrimary.State -eq 'Running' -and $ApplianceIPAddress -eq '192.168.49.1') {
    throw "Existing VM 'Atlaso' is running and may already own $ApplianceIPAddress. Stop it or choose a different lifecycle management topology. This script will not modify that VM."
}

$runningLifecycleAppliances = Get-VM -ErrorAction SilentlyContinue |
Where-Object {
    $_.Name -like 'AtlasoLifecycle*-Appliance' -and
    $_.Name -ne $applianceName -and
    $_.State -eq 'Running'
}
if ($runningLifecycleAppliances -and $ApplianceIPAddress -eq '192.168.49.1') {
    $names = ($runningLifecycleAppliances | Select-Object -ExpandProperty Name) -join ', '
    throw "Running lifecycle appliance VM(s) may already own ${ApplianceIPAddress}: $names. Run scripts/windows/hyperv/invoke-lifecycle-test.ps1 -CleanupVmsOnly or stop those VMs before starting a new lifecycle lab."
}

New-Item -ItemType Directory -Path $diskRoot -Force | Out-Null
New-Item -ItemType Directory -Path $seedRoot -Force | Out-Null

& (Join-Path $PSScriptRoot 'create-switches.ps1')

$clientPublicKey = Ensure-ClientSshKey

$applianceDisk = Join-Path $diskRoot "$applianceName.vhdx"
$clientADisk = Join-Path $diskRoot "$clientAName.vhdx"
$clientBDisk = Join-Path $diskRoot "$clientBName.vhdx"
$clientASeedIso = Join-Path $seedRoot "$clientAName-seed.iso"
$clientBSeedIso = Join-Path $seedRoot "$clientBName-seed.iso"

if (-not $AllowExistingLifecycleLab) {
    New-LifecycleDifferencingDisk -ParentPath $ApplianceVhdxPath -ChildPath $applianceDisk -Label 'appliance'
    New-LifecycleDifferencingDisk -ParentPath $ClientVhdxPath -ChildPath $clientADisk -Label 'client A'
    New-LifecycleDifferencingDisk -ParentPath $ClientVhdxPath -ChildPath $clientBDisk -Label 'client B'
}
else {
    if (-not (Test-Path -LiteralPath $applianceDisk)) { New-LifecycleDifferencingDisk -ParentPath $ApplianceVhdxPath -ChildPath $applianceDisk -Label 'appliance' }
    if (-not (Test-Path -LiteralPath $clientADisk)) { New-LifecycleDifferencingDisk -ParentPath $ClientVhdxPath -ChildPath $clientADisk -Label 'client A' }
    if (-not (Test-Path -LiteralPath $clientBDisk)) { New-LifecycleDifferencingDisk -ParentPath $ClientVhdxPath -ChildPath $clientBDisk -Label 'client B' }
}

New-CloudInitSeedIso -Path $clientASeedIso -HostName ($clientAName.ToLowerInvariant()) -PublicKey $clientPublicKey
New-CloudInitSeedIso -Path $clientBSeedIso -HostName ($clientBName.ToLowerInvariant()) -PublicKey $clientPublicKey

try {
    New-LifecycleVm -Name $applianceName -VhdxPath $applianceDisk -SwitchName 'Atlaso-Mgmt' -MemoryStartupBytes $ApplianceMemoryStartupBytes -ProcessorCount $ApplianceProcessorCount
    New-LifecycleVm -Name $clientAName -VhdxPath $clientADisk -SwitchName $ClientManagementSwitch -MemoryStartupBytes $ClientMemoryStartupBytes -ProcessorCount $ClientProcessorCount
    New-LifecycleVm -Name $clientBName -VhdxPath $clientBDisk -SwitchName $ClientManagementSwitch -MemoryStartupBytes $ClientMemoryStartupBytes -ProcessorCount $ClientProcessorCount
    New-LifecyclePxeVm -Name $pxeClientName -SwitchName 'Atlaso-SiteA' -DiskPath (Join-Path $diskRoot 'pxe-inventory.vhdx')

    Ensure-DvdDrive -VMName $clientAName -Path $clientASeedIso
    Ensure-DvdDrive -VMName $clientBName -Path $clientBSeedIso

    Set-LifecycleNetworkTopology

    foreach ($name in @($applianceName, $clientAName, $clientBName)) {
        if ((Get-VM -Name $name).State -ne 'Running') {
            if ($PSCmdlet.ShouldProcess($name, 'Start lifecycle VM')) {
                Start-VM -Name $name
            }
        }
        Wait-VMRunning -Name $name
    }

    Start-Sleep -Seconds 20
    $applianceHostKey = Get-PlinkHostKey -HostName $ApplianceIPAddress -UserName $ApplianceSshUser -Password $SshPassword
    $clientAHost = Wait-GuestIPv4 -Name $clientAName
    $clientBHost = Wait-GuestIPv4 -Name $clientBName
    $clientAHostKey = Get-PlinkHostKey -HostName $clientAHost -UserName $ClientSshUser -Password $SshPassword
    $clientBHostKey = Get-PlinkHostKey -HostName $clientBHost -UserName $ClientSshUser -Password $SshPassword
    $pxeClientMac = Get-PxeClientMac -Name $pxeClientName
    $remoteEsxIsoPath = Copy-EsxIsoToAppliance -Path $EsxIsoPath

    $basePythonArgs = @(
        (Join-Path $repoRoot 'scripts\interop\lifecycle_test.py'),
        '--appliance-url', $ApplianceUrl,
        '--appliance-ssh-host', $ApplianceIPAddress,
        '--username', $AdminUsername,
        '--password', $AdminPassword,
        '--appliance-ssh-user', $ApplianceSshUser,
        '--client-ssh-user', $ClientSshUser,
        '--vcf-backup-password', $VcfBackupPassword,
        '--site-interface', $SiteInterface,
        '--site-cidr', $SiteCidr,
        '--vlan-id', "$VlanId",
        '--vlan-cidr', $TaggedVlanCidr,
        '--wan-cidr', $WanCidr,
        '--pxe-test-mode', $(if ($EsxIsoPath) { 'esxi' } else { 'linux' }),
        '--pxe-client-mac', $pxeClientMac
    )
    if ($remoteEsxIsoPath) { $basePythonArgs += @('--pxe-installer-iso-path', $remoteEsxIsoPath) }
    if ($SshUser) { $basePythonArgs += @('--ssh-user', $SshUser) }
    if ($SshKeyPath) { $basePythonArgs += @('--ssh-key', $SshKeyPath) }
    if ($SshPassword) { $basePythonArgs += @('--ssh-password', $SshPassword) }
    if ($AllowDryRunApply) { $basePythonArgs += '--allow-dry-run' }
    if ($SignedReleaseRepositoryUrl) {
        $basePythonArgs += @('--signed-release-repository-url', $SignedReleaseRepositoryUrl)
    }

    function New-LifecyclePythonArgs {
        param(
            [string]$RunResultRoot,
            [string]$CurrentApplianceHostKey,
            [string]$CurrentClientAHost,
            [string]$CurrentClientBHost,
            [string]$CurrentClientAHostKey,
            [string]$CurrentClientBHostKey
        )

        $runnerArgs = @($basePythonArgs)
        $runnerArgs += @('--result-dir', $RunResultRoot)
        if ($CurrentApplianceHostKey) { $runnerArgs += @('--appliance-ssh-hostkey', $CurrentApplianceHostKey) }
        if ($CurrentClientAHost) { $runnerArgs += @('--client-a-host', $CurrentClientAHost) }
        if ($CurrentClientBHost) { $runnerArgs += @('--client-b-host', $CurrentClientBHost) }
        if ($CurrentClientAHostKey) { $runnerArgs += @('--client-a-hostkey', $CurrentClientAHostKey) }
        if ($CurrentClientBHostKey) { $runnerArgs += @('--client-b-hostkey', $CurrentClientBHostKey) }
        return $runnerArgs
    }

    $initialResultRoot = if ($SkipBackupRestoreTest) { $resultRoot } else { Join-Path $resultRoot 'initial' }
    $restoredResultRoot = Join-Path $resultRoot 'restored'
    $backupArchivePath = Join-Path $resultRoot 'settings-backup.json'
    $initialResultPath = Join-Path $initialResultRoot 'result.json'

    $initialPythonArgs = New-LifecyclePythonArgs `
        -RunResultRoot $initialResultRoot `
        -CurrentApplianceHostKey $applianceHostKey `
        -CurrentClientAHost $clientAHost `
        -CurrentClientBHost $clientBHost `
        -CurrentClientAHostKey $clientAHostKey `
        -CurrentClientBHostKey $clientBHostKey
    if (-not $SkipBackupRestoreTest) {
        $initialPythonArgs += @('--export-settings-backup', $backupArchivePath)
    }

    if ($PSCmdlet.ShouldProcess($LabName, 'Run lifecycle interop scenario')) {
        python @initialPythonArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Lifecycle interop runner failed with exit code $LASTEXITCODE"
        }
        Invoke-PxeBootSmoke -Name $pxeClientName -MacAddress $pxeClientMac -OutputPath (Join-Path $resultRoot 'pxe-boot-smoke.json')
        if (-not $EsxIsoPath) {
            Invoke-NetworkBootInventoryProof -Name $pxeClientName -MacAddress $pxeClientMac -OutputPath (Join-Path $resultRoot 'network-boot-inventory.json')
        }
        if (-not $SkipBackupRestoreTest) {
            if (-not (Test-Path -LiteralPath $backupArchivePath)) {
                throw "Lifecycle backup archive was not created: $backupArchivePath"
            }
            Write-Host "Lifecycle settings backup: $backupArchivePath"
            Write-Host 'Redeploying lifecycle appliance VM for restore validation...'
            $applianceHostKey = Reset-LifecycleApplianceVm
            $clientAHost = Wait-GuestIPv4 -Name $clientAName
            $clientBHost = Wait-GuestIPv4 -Name $clientBName
            $clientAHostKey = Get-PlinkHostKey -HostName $clientAHost -UserName $ClientSshUser -Password $SshPassword
            $clientBHostKey = Get-PlinkHostKey -HostName $clientBHost -UserName $ClientSshUser -Password $SshPassword

            $restoredPythonArgs = New-LifecyclePythonArgs `
                -RunResultRoot $restoredResultRoot `
                -CurrentApplianceHostKey $applianceHostKey `
                -CurrentClientAHost $clientAHost `
                -CurrentClientBHost $clientBHost `
                -CurrentClientAHostKey $clientAHostKey `
                -CurrentClientBHostKey $clientBHostKey
            $restoredPythonArgs += @(
                '--restore-settings-backup', $backupArchivePath,
                '--restored-state-run',
                '--certificate-baseline-result', $initialResultPath
            )
            python @restoredPythonArgs
            if ($LASTEXITCODE -ne 0) {
                throw "Lifecycle restore interop runner failed with exit code $LASTEXITCODE"
            }
        }
    }
}
finally {
    if ($CleanupCreatedLab) {
        foreach ($name in ($createdVms | Select-Object -Unique)) {
            Assert-SafeLifecycleName -Name $name
            if ($PSCmdlet.ShouldProcess($name, 'Remove lifecycle VM created by this run')) {
                Stop-VM -Name $name -Force -TurnOff -ErrorAction SilentlyContinue
                if (Get-VM -Name $name -ErrorAction SilentlyContinue) {
                    Remove-VM -Name $name -Force
                }
            }
        }
    }
    else {
        Write-Host 'Lifecycle VMs were left in place. Cleanup requires -CleanupCreatedLab and only touches lifecycle-created VM names.'
    }
}

Write-Host "Lifecycle artifacts: $resultRoot"
