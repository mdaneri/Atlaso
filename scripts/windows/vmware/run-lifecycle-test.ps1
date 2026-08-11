[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$LabName = 'AtlasoWorkstationLifecycle',
    [Parameter(Mandatory = $true)]
    [string]$ApplianceVmxPath,
    [Parameter(Mandatory = $true)]
    [string]$ClientVmdkPath,
    [string]$VmrunPath = '',
    [string]$ManagementNetwork = 'VMnet8',
    [string]$SiteANetwork = 'VMnet2',
    [string]$SiteBNetwork = 'VMnet3',
    [string]$TrunkNetwork = 'VMnet4',
    [string]$ApplianceIPAddress = '',
    [string]$ApplianceUrl = '',
    [string]$SiteInterface = 'eth1',
    [string]$SiteCidr = '192.168.12.1/24',
    [string]$AdminUsername = 'admin',
    [string]$AdminPassword = 'VMware01!Test',
    [string]$ApplianceSshUser = 'admin',
    [string]$ClientSshUser = 'alpine',
    [string]$SshPassword = '',
    [string]$VcfBackupPassword = 'VMware01!Test',
    [int]$VlanId = 50,
    [string]$TaggedVlanCidr = '192.168.60.1/24',
    [string]$WanCidr = '172.31.50.1/24',
    [switch]$AllowDryRunApply,
    [switch]$SkipBackupRestoreTest,
    [switch]$OidcOnly,
    [switch]$RoutingWanOnly,
    [switch]$FullEsxiPxeInstall,
    [string]$PxeInstallerIsoPath = '',
    [string]$PxeClientIPAddress = '',
    [int]$EsxiInstallTimeoutSeconds = 3600,
    [int]$EsxiInstallProbeDelaySeconds = 300,
    [switch]$CleanupCreatedLab,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
if (-not $SshPassword) {
    $SshPassword = $AdminPassword
}
$ApplianceGuestPassword = $AdminPassword
if ($RoutingWanOnly) {
    $SkipBackupRestoreTest = $true
}
if ($OidcOnly) {
    $SkipBackupRestoreTest = $true
}

$resultStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultRoot = Join-Path $repoRoot "test-results\vmware-workstation-lifecycle\$resultStamp"
$vmRoot = Join-Path $resultRoot 'vms'
$seedRoot = Join-Path $resultRoot 'seed'
$createdVmxPaths = New-Object System.Collections.Generic.List[string]

function Resolve-VmrunPath {
    if ($VmrunPath) {
        if (-not (Test-Path -LiteralPath $VmrunPath)) {
            throw "vmrun.exe not found: $VmrunPath"
        }
        return (Resolve-Path -LiteralPath $VmrunPath).Path
    }
    foreach ($candidate in @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    )) {
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

function Resolve-VdiskManagerPath {
    $vmrunDirectory = Split-Path -Parent $resolvedVmrun
    $candidate = Join-Path $vmrunDirectory 'vmware-vdiskmanager.exe'
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }
    foreach ($path in @(
        'C:\Program Files\VMware\VMware Workstation\vmware-vdiskmanager.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe'
    )) {
        if (Test-Path -LiteralPath $path) {
            return $path
        }
    }
    $command = Get-Command vmware-vdiskmanager -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmware-vdiskmanager.exe was not found. It is required for -FullEsxiPxeInstall.'
}

function Assert-SafeLifecycleName {
    param([string]$Name)

    $reserved = @('Atlaso', 'Atlaso-Photon-Builder', 'Atlaso-Photon-Builder-VMware')
    if ($reserved -contains $Name) {
        throw "Refusing to use reserved VM name '$Name'. Lifecycle tests must use a separate VM set."
    }
    if (-not $Name.StartsWith($LabName)) {
        throw "Refusing VM name '$Name' because it does not start with lifecycle lab prefix '$LabName'."
    }
}

function ConvertTo-GuestShellSingleQuote {
    param([string]$Value)
    return "'" + ($Value -replace "'", "'\''") + "'"
}

function ConvertTo-NativeArgument {
    param([string]$Value)

    if ($null -eq $Value) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-VmrunBounded {
    param(
        [string[]]$Arguments,
        [int]$TimeoutSeconds = 30
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $resolvedVmrun
    $startInfo.Arguments = ($Arguments | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join ' '
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    [void]$process.Start()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try {
            $process.Kill()
        } catch {
        }
        return [pscustomobject]@{
            ExitCode = -1
            TimedOut = $true
            StdOut   = ''
            StdErr   = "vmrun timed out after $TimeoutSeconds seconds: $($Arguments -join ' ')"
        }
    }
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        TimedOut = $false
        StdOut   = $process.StandardOutput.ReadToEnd()
        StdErr   = $process.StandardError.ReadToEnd()
    }
}

function New-StaticVmwareMac {
    $bytes = [guid]::NewGuid().ToByteArray()
    return ('00:50:56:{0:x2}:{1:x2}:{2:x2}' -f (0x20 -bor ($bytes[0] -band 0x1f)), $bytes[1], $bytes[2])
}

function ConvertTo-VmxString {
    param([string]$Value)
    return '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

function Set-VmxValue {
    param(
        [string]$Path,
        [string]$Key,
        [string]$Value
    )

    $line = "$Key = $(ConvertTo-VmxString -Value $Value)"
    $content = if (Test-Path -LiteralPath $Path) {
        @(Get-Content -LiteralPath $Path)
    } else {
        @()
    }
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $updated = $false
    $content = @($content | ForEach-Object {
        if ($_ -match $pattern) {
            $updated = $true
            $line
        } else {
            $_
        }
    })
    if (-not $updated) {
        $content += $line
    }
    [System.IO.File]::WriteAllLines($Path, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}

function Remove-VmxValue {
    param(
        [string]$Path,
        [string]$Key
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $content = @(Get-Content -LiteralPath $Path | Where-Object { $_ -notmatch $pattern })
    [System.IO.File]::WriteAllLines($Path, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}

function New-LanSegmentId {
    param([string]$Name)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("AtlasoWorkstationLifecycle:$Name"))
    } finally {
        $sha.Dispose()
    }
    $idBytes = [byte[]]$bytes[0..15]
    $idBytes[0] = 0x52
    $first = (($idBytes[0..7] | ForEach-Object { $_.ToString('x2') }) -join ' ')
    $second = (($idBytes[8..15] | ForEach-Object { $_.ToString('x2') }) -join ' ')
    return "$first-$second"
}

function Resolve-LanSegmentId {
    param([string]$Name)

    $preferenceDirectory = Join-Path $env:APPDATA 'VMware'
    $preferencePath = Join-Path $preferenceDirectory 'preferences.ini'
    if (-not (Test-Path -LiteralPath $preferenceDirectory)) {
        New-Item -ItemType Directory -Force -Path $preferenceDirectory | Out-Null
    }
    $content = if (Test-Path -LiteralPath $preferencePath) {
        @(Get-Content -LiteralPath $preferencePath)
    } else {
        @()
    }

    $segments = @{}
    for ($index = 0; $index -lt $content.Count; $index++) {
        if ($content[$index] -match '^pref\.namedPVNs(?<id>\d+)\.name\s*=\s*"(?<name>.*)"\s*$') {
            $entry = [int]$matches.id
            if (-not $segments.ContainsKey($entry)) {
                $segments[$entry] = @{}
            }
            $segments[$entry].Name = $matches.name
        } elseif ($content[$index] -match '^pref\.namedPVNs(?<id>\d+)\.pvnID\s*=\s*"(?<pvn>.*)"\s*$') {
            $entry = [int]$matches.id
            if (-not $segments.ContainsKey($entry)) {
                $segments[$entry] = @{}
            }
            $segments[$entry].PvnId = $matches.pvn
        }
    }

    $requiredCount = 0
    if ($segments.Count -gt 0) {
        $requiredCount = (($segments.Keys | Measure-Object -Maximum).Maximum + 1)
    }

    $countUpdated = $false
    $countChanged = $false
    $content = @($content | ForEach-Object {
        if ($_ -match '^pref\.namedPVNs\.count\s*=') {
            $countUpdated = $true
            $desiredLine = "pref.namedPVNs.count = $(ConvertTo-VmxString -Value ([string]$requiredCount))"
            if ($_ -ne $desiredLine) {
                $countChanged = $true
                $desiredLine
            } else {
                $_
            }
        } else {
            $_
        }
    })
    if (-not $countUpdated -and $requiredCount -gt 0) {
        $content += "pref.namedPVNs.count = $(ConvertTo-VmxString -Value ([string]$requiredCount))"
        $countChanged = $true
    }
    if ($countChanged) {
        [System.IO.File]::WriteAllLines($preferencePath, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
    }

    foreach ($entry in $segments.GetEnumerator()) {
        if ($entry.Value.Name -eq $Name -and $entry.Value.PvnId) {
            if ($entry.Value.PvnId -notmatch '^52 ') {
                $pvnId = New-LanSegmentId -Name $Name
                $content = @($content | ForEach-Object {
                    if ($_ -match "^pref\.namedPVNs$($entry.Key)\.pvnID\s*=") {
                        "pref.namedPVNs$($entry.Key).pvnID = $(ConvertTo-VmxString -Value $pvnId)"
                    } else {
                        $_
                    }
                })
                [System.IO.File]::WriteAllLines($preferencePath, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
                return $pvnId
            }
            return $entry.Value.PvnId
        }
    }

    $nextIndex = $requiredCount
    $pvnId = New-LanSegmentId -Name $Name
    $content += "pref.namedPVNs$nextIndex.name = $(ConvertTo-VmxString -Value $Name)"
    $content += "pref.namedPVNs$nextIndex.pvnID = $(ConvertTo-VmxString -Value $pvnId)"
    $content = @($content | ForEach-Object {
        if ($_ -match '^pref\.namedPVNs\.count\s*=') {
            "pref.namedPVNs.count = $(ConvertTo-VmxString -Value ([string]($nextIndex + 1)))"
        } else {
            $_
        }
    })
    if (-not ($content | Where-Object { $_ -match '^pref\.namedPVNs\.count\s*=' })) {
        $content += "pref.namedPVNs.count = $(ConvertTo-VmxString -Value ([string]($nextIndex + 1)))"
    }
    [System.IO.File]::WriteAllLines($preferencePath, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
    return $pvnId
}

function Set-VmxNetworkAdapter {
    param(
        [string]$Path,
        [int]$Index,
        [string]$Vmnet,
        [string]$StaticMac = '',
        [string]$VirtualDev = 'vmxnet3'
    )

    $prefix = "ethernet$Index"
    if ($Vmnet -match '^(?i)vmnet(\d+)$') {
        $Vmnet = "VMnet$($Matches[1])"
    }
    Set-VmxValue -Path $Path -Key "$prefix.present" -Value 'TRUE'
    if ($Vmnet.StartsWith('lan:')) {
        $segmentName = $Vmnet.Substring(4)
        $pvnId = Resolve-LanSegmentId -Name $segmentName
        Set-VmxValue -Path $Path -Key "$prefix.connectionType" -Value 'pvn'
        Set-VmxValue -Path $Path -Key "$prefix.pvnID" -Value $pvnId
        Remove-VmxValue -Path $Path -Key "$prefix.vnet"
    } else {
        Set-VmxValue -Path $Path -Key "$prefix.connectionType" -Value 'custom'
        Set-VmxValue -Path $Path -Key "$prefix.vnet" -Value $Vmnet
        Remove-VmxValue -Path $Path -Key "$prefix.pvnID"
    }
    Set-VmxValue -Path $Path -Key "$prefix.virtualDev" -Value $VirtualDev
    if ($StaticMac) {
        Set-VmxValue -Path $Path -Key "$prefix.addressType" -Value 'static'
        Set-VmxValue -Path $Path -Key "$prefix.address" -Value $StaticMac
    }
    Set-VmxValue -Path $Path -Key "$prefix.startConnected" -Value 'TRUE'
}

function Copy-VmDirectory {
    param(
        [string]$SourceVmx,
        [string]$DestinationDirectory,
        [string]$Name
    )

    Assert-SafeLifecycleName -Name $Name
    if (Test-Path -LiteralPath $DestinationDirectory) {
        throw "Lifecycle VM directory already exists: $DestinationDirectory"
    }
    $sourceDirectory = Split-Path -Parent (Resolve-Path -LiteralPath $SourceVmx)
    if ($PSCmdlet.ShouldProcess($DestinationDirectory, "Copy Workstation VM $Name")) {
        Copy-Item -LiteralPath $sourceDirectory -Destination $DestinationDirectory -Recurse
    }
    $vmx = Get-ChildItem -LiteralPath $DestinationDirectory -Filter '*.vmx' | Select-Object -First 1
    if (-not $vmx) {
        throw "Copied Workstation VM has no VMX: $DestinationDirectory"
    }
    $targetVmx = Join-Path $DestinationDirectory "$Name.vmx"
    Rename-Item -LiteralPath $vmx.FullName -NewName "$Name.vmx"
    Set-VmxValue -Path $targetVmx -Key 'displayName' -Value $Name
    $createdVmxPaths.Add($targetVmx)
    return $targetVmx
}

function New-ClientVm {
    param(
        [string]$Name,
        [string]$Directory,
        [string]$DiskPath,
        [string]$SeedIso,
        [string[]]$Networks
    )

    Assert-SafeLifecycleName -Name $Name
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $diskTarget = Join-Path $Directory "$Name.vmdk"
    if ($PSCmdlet.ShouldProcess($diskTarget, "Copy client VMDK for $Name")) {
        Copy-Item -LiteralPath $DiskPath -Destination $diskTarget
    }
    $vmxPath = Join-Path $Directory "$Name.vmx"
    $lines = @(
        '.encoding = "windows-1252"',
        'config.version = "8"',
        'virtualHW.version = "21"',
        'firmware = "efi"',
        'uefi.secureBoot.enabled = "FALSE"',
        "displayName = $(ConvertTo-VmxString -Value $Name)",
        'guestOS = "other5xlinux-64"',
        'memsize = "1024"',
        'numvcpus = "1"',
        'sata0.present = "TRUE"',
        'sata0:0.present = "TRUE"',
        "sata0:0.fileName = $(ConvertTo-VmxString -Value (Split-Path -Leaf $diskTarget))",
        'sata0:0.deviceType = "disk"',
        'sata0:1.present = "TRUE"',
        "sata0:1.fileName = $(ConvertTo-VmxString -Value $SeedIso)",
        'sata0:1.deviceType = "cdrom-image"',
        'sata0:1.startConnected = "TRUE"'
    )
    [System.IO.File]::WriteAllLines($vmxPath, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
    for ($index = 0; $index -lt $Networks.Count; $index++) {
        Set-VmxNetworkAdapter -Path $vmxPath -Index $index -Vmnet $Networks[$index] -VirtualDev 'e1000'
    }
    $createdVmxPaths.Add($vmxPath)
    return $vmxPath
}

function New-EsxiPxeVm {
    param(
        [string]$Name,
        [string]$Directory,
        [string]$Network,
        [string]$MacAddress
    )

    Assert-SafeLifecycleName -Name $Name
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $diskTarget = Join-Path $Directory "$Name.vmdk"
    $vdiskManager = Resolve-VdiskManagerPath
    if ($PSCmdlet.ShouldProcess($diskTarget, "Create ESXi PXE install disk for $Name")) {
        & $vdiskManager -c -s 32GB -a pvscsi -t 0 $diskTarget | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create ESXi PXE install disk with vmware-vdiskmanager."
        }
    }
    $vmxPath = Join-Path $Directory "$Name.vmx"
    $lines = @(
        '.encoding = "windows-1252"',
        'config.version = "8"',
        'virtualHW.version = "22"',
        'pciBridge0.present = "TRUE"',
        'pciBridge4.present = "TRUE"',
        'pciBridge4.virtualDev = "pcieRootPort"',
        'pciBridge4.functions = "8"',
        'pciBridge5.present = "TRUE"',
        'pciBridge5.virtualDev = "pcieRootPort"',
        'pciBridge5.functions = "8"',
        'pciBridge6.present = "TRUE"',
        'pciBridge6.virtualDev = "pcieRootPort"',
        'pciBridge6.functions = "8"',
        'pciBridge7.present = "TRUE"',
        'pciBridge7.virtualDev = "pcieRootPort"',
        'pciBridge7.functions = "8"',
        'vmci0.present = "TRUE"',
        'virtualHW.productCompatibility = "hosted"',
        'firmware = "efi"',
        'uefi.secureBoot.enabled = "FALSE"',
        "displayName = $(ConvertTo-VmxString -Value $Name)",
        'guestOS = "vmkernel9"',
        'memsize = "8192"',
        'numvcpus = "4"',
        'vhv.enable = "FALSE"',
        'tools.syncTime = "FALSE"',
        'floppy0.present = "FALSE"',
        'scsi0.present = "TRUE"',
        'scsi0.virtualDev = "pvscsi"',
        'scsi0:0.present = "TRUE"',
        "scsi0:0.fileName = $(ConvertTo-VmxString -Value (Split-Path -Leaf $diskTarget))"
    )
    [System.IO.File]::WriteAllLines($vmxPath, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
    Set-VmxNetworkAdapter -Path $vmxPath -Index 0 -Vmnet $Network -StaticMac $MacAddress -VirtualDev 'vmxnet3'
    $createdVmxPaths.Add($vmxPath)
    return $vmxPath
}

function New-CloudInitSeedIso {
    param(
        [string]$Path,
        [string]$HostName
    )

    if ($PSCmdlet.ShouldProcess($Path, "Create NoCloud seed disk for $HostName")) {
        python -c 'import pycdlib' 2>$null
        if ($LASTEXITCODE -ne 0) {
            python -m pip install pycdlib
        }
        $helper = Join-Path $repoRoot 'scripts\interop\create_nocloud_seed_iso.py'
        python $helper --output $Path --hostname $HostName --user $ClientSshUser --password $SshPassword | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create NoCloud seed ISO for $HostName"
        }
    }
}

function Invoke-Vmrun {
    param([string[]]$Arguments)
    & $resolvedVmrun @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "vmrun $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Register-WorkstationVm {
    param([string]$Path)
    if ($PSCmdlet.ShouldProcess($Path, 'Register Workstation VM')) {
        & $resolvedVmrun -T ws register $Path 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Verbose "Workstation VM may already be registered: $Path"
        }
    }
}

function Unregister-WorkstationVm {
    param([string]$Path)
    & $resolvedVmrun -T ws unregister $Path 2>$null | Out-Null
}

function Start-WorkstationVm {
    param([string]$Path)
    if ($PSCmdlet.ShouldProcess($Path, 'Start Workstation VM')) {
        Register-WorkstationVm -Path $Path
        Invoke-Vmrun -Arguments @('-T', 'ws', 'start', $Path, 'nogui')
    }
}

function Stop-WorkstationVm {
    param([string]$Path)
    & $resolvedVmrun -T ws stop $Path hard 2>$null | Out-Null
}

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMilliseconds = 1000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
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
        } finally {
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

function Get-GuestIPv4FromAddressText {
    param([string[]]$Lines)

    foreach ($line in $Lines) {
        foreach ($match in [regex]::Matches($line, '(?<ip>(?:\d{1,3}\.){3}\d{1,3})/\d+')) {
            $ip = $match.Groups['ip'].Value
            if ($ip -notlike '127.*' -and $ip -notlike '169.254.*') {
                return $ip
            }
        }
        if ($line -match '^\s*(?<ip>(?:\d{1,3}\.){3}\d{1,3})\s*$') {
            $ip = $Matches['ip']
            if ($ip -notlike '127.*' -and $ip -notlike '169.254.*') {
                return $ip
            }
        }
    }
    return ''
}

function ConvertTo-HyphenMac {
    param([string]$MacAddress)

    return ($MacAddress -replace '[^0-9A-Fa-f]', '').ToLowerInvariant() -replace '(.{2})(?!$)', '$1-'
}

function Get-VmxEthernetMacAddress {
    param(
        [string]$Path,
        [int]$Index = 0
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return ''
    }
    $content = Get-Content -LiteralPath $Path
    $prefix = "ethernet$Index"
    foreach ($key in @('address', 'generatedAddress')) {
        $pattern = '^\s*' + [regex]::Escape("$prefix.$key") + '\s*=\s*"(?<value>[^"]+)"\s*$'
        $line = $content | Where-Object { $_ -match $pattern } | Select-Object -First 1
        if ($line -and $line -match $pattern) {
            return ConvertTo-HyphenMac -MacAddress $Matches['value']
        }
    }
    return ''
}

function Get-GuestIPv4FromHostNeighbor {
    param(
        [string]$Path,
        [int]$Index = 0
    )

    $mac = Get-VmxEthernetMacAddress -Path $Path -Index $Index
    if (-not $mac) {
        return ''
    }
    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop
    } catch {
        return ''
    }
    foreach ($neighbor in $neighbors) {
        if (($neighbor.LinkLayerAddress -as [string]).ToLowerInvariant() -ne $mac) {
            continue
        }
        $ip = $neighbor.IPAddress -as [string]
        if ($ip -and $ip -notlike '127.*' -and $ip -notlike '169.254.*') {
            return $ip
        }
    }
    return ''
}

function Get-GuestIPv4ViaGuestOps {
    param(
        [string]$Path,
        [string]$GuestUser,
        [string]$GuestPassword,
        [string]$Name
    )

    if (-not $GuestUser -or -not $GuestPassword) {
        return ''
    }
    $safeName = ($Name -replace '[^A-Za-z0-9_.-]', '-')
    $guestOutput = "/tmp/atlaso-ipv4-$safeName.txt"
    $hostOutput = Join-Path $resultRoot "guest-ipv4-$safeName.txt"
    $script = "ip -4 -br addr > $guestOutput 2>/dev/null || /sbin/ip -4 -br addr > $guestOutput 2>/dev/null || ifconfig > $guestOutput 2>/dev/null"
    $runResult = Invoke-VmrunBounded -Arguments @('-T', 'ws', '-gu', $GuestUser, '-gp', $GuestPassword, 'runScriptInGuest', $Path, '/bin/sh', $script) -TimeoutSeconds 15
    if ($runResult.ExitCode -ne 0) {
        return ''
    }
    $copyResult = Invoke-VmrunBounded -Arguments @('-T', 'ws', '-gu', $GuestUser, '-gp', $GuestPassword, 'copyFileFromGuestToHost', $Path, $guestOutput, $hostOutput) -TimeoutSeconds 15
    if ($copyResult.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $hostOutput)) {
        return ''
    }
    return Get-GuestIPv4FromAddressText -Lines @(Get-Content -LiteralPath $hostOutput)
}

function Wait-GuestIPv4 {
    param(
        [string]$Path,
        [int]$TimeoutSeconds = 240,
        [string]$GuestUser = '',
        [string]$GuestPassword = '',
        [string]$Name = 'guest'
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $reported = Invoke-VmrunBounded -Arguments @('-T', 'ws', 'getGuestIPAddress', $Path) -TimeoutSeconds 10
        if ($reported.ExitCode -eq 0) {
            $ip = Get-GuestIPv4FromAddressText -Lines @($reported.StdOut -split "`r?`n")
            if ($ip) {
                return $ip
            }
        }
        $neighborIp = Get-GuestIPv4FromHostNeighbor -Path $Path
        if ($neighborIp) {
            return $neighborIp
        }
        $fallbackIp = Get-GuestIPv4ViaGuestOps -Path $Path -GuestUser $GuestUser -GuestPassword $GuestPassword -Name $Name
        if ($fallbackIp) {
            return $fallbackIp
        }
        Start-Sleep -Seconds 5
    }
    return ''
}

function Invoke-ApplianceGuestScript {
    param(
        [string]$ApplianceVmx,
        [string]$Script
    )

    & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword runScriptInGuest $ApplianceVmx /bin/sh $Script | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Appliance guest operation failed."
    }
}

function Test-ApplianceOpenApi {
    param([string]$Url)

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source -k -f -sS $Url 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    }

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -SkipCertificateCheck -TimeoutSec 10
        return $response.StatusCode -eq 200
    } catch [System.Management.Automation.ParameterBindingException] {
        $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
            return $response.StatusCode -eq 200
        } catch {
            return $false
        } finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
        }
    } catch {
        return $false
    }
}

function Sync-ApplianceHelperScript {
    param([string]$ApplianceVmx)

    $localHelper = Join-Path $repoRoot 'scripts\appliance\atlaso-helper'
    if (-not (Test-Path -LiteralPath $localHelper)) {
        throw "Atlaso helper script not found: $localHelper"
    }
    $guestTemp = "/tmp/atlaso-helper"
    if ($PSCmdlet.ShouldProcess($ApplianceVmx, "Sync Atlaso helper into appliance")) {
        & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromHostToGuest $ApplianceVmx $localHelper $guestTemp | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to copy Atlaso helper into the appliance with VMware guest operations."
        }
        $quotedPassword = ConvertTo-GuestShellSingleQuote -Value $ApplianceGuestPassword
        $quotedTemp = ConvertTo-GuestShellSingleQuote -Value $guestTemp
        $script = "printf '%s\n' $quotedPassword | sudo -S install -o root -g root -m 0755 $quotedTemp /opt/atlaso/bin/atlaso-helper"
        Invoke-ApplianceGuestScript -ApplianceVmx $ApplianceVmx -Script $script
    }
}

function Sync-ApplianceApplicationWheel {
    param([string]$ApplianceVmx)

    $wheelRoot = Join-Path $resultRoot 'wheel'
    if (Test-Path -LiteralPath $wheelRoot) {
        Remove-Item -LiteralPath $wheelRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $wheelRoot | Out-Null
    Write-Host "Building Atlaso wheel from current branch."
    & python -m pip wheel $repoRoot --no-deps -w $wheelRoot | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build Atlaso wheel from $repoRoot."
    }
    $wheel = Get-ChildItem -LiteralPath $wheelRoot -Filter 'atlaso-*.whl' -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $wheel) {
        throw "Built wheel was not found under $wheelRoot."
    }

    $guestWheel = "/tmp/$($wheel.Name)"
    if ($PSCmdlet.ShouldProcess($ApplianceVmx, "Install current Atlaso wheel into appliance")) {
        & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromHostToGuest $ApplianceVmx $wheel.FullName $guestWheel | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to copy Atlaso wheel into the appliance with VMware guest operations."
        }
        $quotedPassword = ConvertTo-GuestShellSingleQuote -Value $ApplianceGuestPassword
        $quotedWheel = ConvertTo-GuestShellSingleQuote -Value $guestWheel
        $script = "printf '%s\n' $quotedPassword | sudo -S /opt/atlaso/.venv/bin/python -m pip install --force-reinstall --no-deps $quotedWheel && printf '%s\n' $quotedPassword | sudo -S find /opt/atlaso/.venv -type d -exec chmod 0755 {} + && printf '%s\n' $quotedPassword | sudo -S find /opt/atlaso/.venv -type f -exec chmod 0644 {} + && printf '%s\n' $quotedPassword | sudo -S find /opt/atlaso/.venv/bin -type f -exec chmod 0755 {} + && printf '%s\n' $quotedPassword | sudo -S systemctl restart atlaso.service"
        Invoke-ApplianceGuestScript -ApplianceVmx $ApplianceVmx -Script $script
    }

    $deadline = (Get-Date).AddMinutes(3)
    do {
        if (Test-ApplianceOpenApi -Url "$ApplianceUrl/openapi.json") {
            return $wheel.FullName
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for Atlaso web service after installing $($wheel.Name)."
}

function Find-ApplianceEsxiIsoPath {
    param([string]$ApplianceVmx)

    $guestOutput = '/tmp/atlaso-esxi-iso.txt'
    $hostOutput = Join-Path $resultRoot 'appliance-esxi-iso.txt'
    $script = "find /mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST -maxdepth 1 -type f -iname '*.iso' | head -n 1 > $guestOutput"
    & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword runScriptInGuest $ApplianceVmx /bin/sh $script 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        return ''
    }
    & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromGuestToHost $ApplianceVmx $guestOutput $hostOutput 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $hostOutput)) {
        return ''
    }
    return ((Get-Content -LiteralPath $hostOutput | Select-Object -First 1) -as [string]).Trim()
}

function Resolve-ApplianceEsxiIsoPath {
    param([string]$ApplianceVmx)

    if (-not $FullEsxiPxeInstall) {
        return ''
    }
    if (-not $PxeInstallerIsoPath) {
        $discovered = Find-ApplianceEsxiIsoPath -ApplianceVmx $ApplianceVmx
        if ($discovered) {
            return $discovered
        }
        throw "-FullEsxiPxeInstall requires -PxeInstallerIsoPath or an existing ESXi ISO under /mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST on the appliance."
    }
    if ($PxeInstallerIsoPath.StartsWith('/')) {
        return $PxeInstallerIsoPath
    }
    $localIso = Resolve-Path -LiteralPath $PxeInstallerIsoPath
    $leaf = Split-Path -Leaf $localIso.Path
    $guestTemp = "/tmp/$leaf"
    $guestTarget = "/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST/$leaf"
    if ($PSCmdlet.ShouldProcess($guestTarget, "Stage ESXi installer ISO into appliance depot")) {
        & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromHostToGuest $ApplianceVmx $localIso.Path $guestTemp | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to copy ESXi installer ISO into the appliance with VMware guest operations."
        }
        $quotedPassword = ConvertTo-GuestShellSingleQuote -Value $ApplianceGuestPassword
        $quotedTemp = ConvertTo-GuestShellSingleQuote -Value $guestTemp
        $quotedTarget = ConvertTo-GuestShellSingleQuote -Value $guestTarget
        $script = "printf '%s\n' $quotedPassword | sudo -S mkdir -p /mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST && printf '%s\n' $quotedPassword | sudo -S mv $quotedTemp $quotedTarget && printf '%s\n' $quotedPassword | sudo -S chmod 0644 $quotedTarget"
        Invoke-ApplianceGuestScript -ApplianceVmx $ApplianceVmx -Script $script
    }
    return $guestTarget
}

function Add-LifecycleResultStep {
    param(
        [string]$ResultDirectory,
        [string]$Name,
        [string]$Status,
        [hashtable]$Evidence,
        [string]$ErrorMessage = ''
    )

    $path = Join-Path $ResultDirectory 'result.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Lifecycle result JSON not found: $path"
    }
    $result = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $step = [ordered]@{
        name        = $Name
        status      = $Status
        started_at  = (Get-Date).ToUniversalTime().ToString('o')
        finished_at = (Get-Date).ToUniversalTime().ToString('o')
        evidence    = $Evidence
        error       = $ErrorMessage
    }
    $result.steps += @($step)
    if ($Status -ne 'passed') {
        $result.status = 'failed'
        if ($result.PSObject.Properties.Name -contains 'error') {
            $result.error = $ErrorMessage
        } else {
            $result | Add-Member -MemberType NoteProperty -Name 'error' -Value $ErrorMessage
        }
    }
    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
}

$resolvedVmrun = Resolve-VmrunPath
if (($RoutingWanOnly -and $FullEsxiPxeInstall) -or ($OidcOnly -and ($RoutingWanOnly -or $FullEsxiPxeInstall))) {
    throw "-OidcOnly, -RoutingWanOnly, and -FullEsxiPxeInstall are mutually exclusive."
}
$applianceName = "$LabName-Appliance"
$clientAName = "$LabName-ClientA"
$clientBName = "$LabName-ClientB"
$esxiName = "$LabName-ESXiPXE"
$esxiMacAddress = if ($FullEsxiPxeInstall) { New-StaticVmwareMac } else { '' }
$planApplianceVmx = if (Test-Path -LiteralPath $ApplianceVmxPath) { (Resolve-Path -LiteralPath $ApplianceVmxPath).Path } else { $ApplianceVmxPath }
$planClientVmdk = if (Test-Path -LiteralPath $ClientVmdkPath) { (Resolve-Path -LiteralPath $ClientVmdkPath).Path } else { $ClientVmdkPath }

$plan = [ordered]@{
    name                  = 'vmware workstation lifecycle interop'
    lab_name              = $LabName
    appliance_vmx         = $planApplianceVmx
    client_vmdk           = $planClientVmdk
    result_root           = $resultRoot
    management_network    = $ManagementNetwork
    site_a_network        = $SiteANetwork
    trunk_network         = $TrunkNetwork
    site_b_network        = $SiteBNetwork
    oidc_only             = [bool]$OidcOnly
    routing_wan_only      = [bool]$RoutingWanOnly
    full_esxi_pxe_install = [bool]$FullEsxiPxeInstall
    pxe_installer_iso     = $PxeInstallerIsoPath
    pxe_client_ip         = $PxeClientIPAddress
    esxi_probe_delay_seconds = $EsxiInstallProbeDelaySeconds
    esxi_pxe_vm           = if ($FullEsxiPxeInstall) { $esxiName } else { '' }
    esxi_pxe_mac          = $esxiMacAddress
    workstation_fidelity  = 'Workstation vmnets are isolated layer-2 segments; Hyper-V access/trunk VLAN port behavior is approximated by separate vmnets.'
}

if ($PlanOnly) {
    New-Item -ItemType Directory -Force -Path $resultRoot | Out-Null
    $plan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $resultRoot 'plan.json') -Encoding UTF8
    $plan | ConvertTo-Json -Depth 5
    return
}

$firstBootOvfEnvironment = New-AtlasoWorkstationOvfEnvironment `
    -Fqdn (New-AtlasoWorkstationFqdn -Name $applianceName) `
    -AdminPassword $AdminPassword `
    -RootPassword $AdminPassword `
    -RootSshEnabled:($ApplianceSshUser -eq 'root')

New-Item -ItemType Directory -Force -Path $vmRoot | Out-Null
New-Item -ItemType Directory -Force -Path $seedRoot | Out-Null

$clientASeedIso = ''
$clientBSeedIso = ''
if (-not $OidcOnly) {
    $clientASeedIso = Join-Path $seedRoot "$clientAName-seed.iso"
    $clientBSeedIso = Join-Path $seedRoot "$clientBName-seed.iso"
    New-CloudInitSeedIso -Path $clientASeedIso -HostName ($clientAName.ToLowerInvariant())
    New-CloudInitSeedIso -Path $clientBSeedIso -HostName ($clientBName.ToLowerInvariant())
}

try {
    $applianceVmx = Copy-VmDirectory -SourceVmx $ApplianceVmxPath -DestinationDirectory (Join-Path $vmRoot $applianceName) -Name $applianceName
    Set-VmxNetworkAdapter -Path $applianceVmx -Index 0 -Vmnet $ManagementNetwork
    Set-AtlasoWorkstationOvfEnvironment -VmxPath $applianceVmx -OvfEnvironment $firstBootOvfEnvironment
    $clientAVmx = ''
    $clientBVmx = ''
    if (-not $OidcOnly) {
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 1 -Vmnet $SiteANetwork
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 2 -Vmnet $TrunkNetwork
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 3 -Vmnet $SiteBNetwork
        $clientAVmx = New-ClientVm -Name $clientAName -Directory (Join-Path $vmRoot $clientAName) -DiskPath $ClientVmdkPath -SeedIso $clientASeedIso -Networks @($ManagementNetwork, $SiteANetwork, $TrunkNetwork)
        $clientBVmx = New-ClientVm -Name $clientBName -Directory (Join-Path $vmRoot $clientBName) -DiskPath $ClientVmdkPath -SeedIso $clientBSeedIso -Networks @($ManagementNetwork, $SiteBNetwork)
    }
    $esxiVmx = ''
    if ($FullEsxiPxeInstall) {
        $esxiVmx = New-EsxiPxeVm -Name $esxiName -Directory (Join-Path $vmRoot $esxiName) -Network $SiteANetwork -MacAddress $esxiMacAddress
    }

    $vmxsToStart = @($applianceVmx)
    if (-not $OidcOnly) {
        $vmxsToStart += @($clientAVmx, $clientBVmx)
    }
    foreach ($vmx in $vmxsToStart) {
        Start-WorkstationVm -Path $vmx
    }

    Start-Sleep -Seconds 20
    if (-not $ApplianceIPAddress) {
        $ApplianceIPAddress = Wait-GuestIPv4 -Path $applianceVmx -TimeoutSeconds 300 -GuestUser $ApplianceSshUser -GuestPassword $ApplianceGuestPassword -Name $applianceName
        if (-not $ApplianceIPAddress) {
            throw "Timed out waiting for VMware Tools to report the appliance management IPv4 address."
        }
    }
    if (-not $ApplianceUrl) {
        $ApplianceUrl = "https://${ApplianceIPAddress}"
    }
    [pscustomobject]@{
        appliance_ip  = $ApplianceIPAddress
        appliance_url = $ApplianceUrl
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $resultRoot 'discovered-appliance.json') -Encoding UTF8
    Sync-ApplianceHelperScript -ApplianceVmx $applianceVmx
    $applianceWheelPath = Sync-ApplianceApplicationWheel -ApplianceVmx $applianceVmx
    $applianceHostKey = Get-PlinkHostKey -HostName $ApplianceIPAddress -UserName $ApplianceSshUser -Password $ApplianceGuestPassword
    $clientAHost = ''
    $clientBHost = ''
    $clientAHostKey = ''
    $clientBHostKey = ''
    if (-not $OidcOnly) {
        $clientAHost = Wait-GuestIPv4 -Path $clientAVmx -GuestUser $ClientSshUser -GuestPassword $SshPassword -Name $clientAName
        $clientBHost = Wait-GuestIPv4 -Path $clientBVmx -GuestUser $ClientSshUser -GuestPassword $SshPassword -Name $clientBName
        $clientAHostKey = Get-PlinkHostKey -HostName $clientAHost -UserName $ClientSshUser -Password $SshPassword
        $clientBHostKey = Get-PlinkHostKey -HostName $clientBHost -UserName $ClientSshUser -Password $SshPassword
    }
    $appliancePxeInstallerIsoPath = if ($FullEsxiPxeInstall) {
        Resolve-ApplianceEsxiIsoPath -ApplianceVmx $applianceVmx
    } else {
        ''
    }

    $basePythonArgs = @(
        (Join-Path $repoRoot 'scripts\interop\lifecycle_test.py'),
        '--appliance-url', $ApplianceUrl,
        '--appliance-ssh-host', $ApplianceIPAddress,
        '--username', $AdminUsername,
        '--password', $AdminPassword,
        '--appliance-ssh-user', $ApplianceSshUser,
        '--client-ssh-user', $ClientSshUser,
        '--appliance-ssh-password', $ApplianceGuestPassword,
        '--ssh-password', $SshPassword,
        '--vcf-backup-password', $VcfBackupPassword,
        '--site-interface', $SiteInterface,
        '--site-cidr', $SiteCidr,
        '--vlan-id', "$VlanId",
        '--vlan-cidr', $TaggedVlanCidr,
        '--wan-cidr', $WanCidr,
        '--pxe-test-mode', $(if ($FullEsxiPxeInstall) { 'esxi' } else { 'linux' })
    )
    if ($FullEsxiPxeInstall) {
        $basePythonArgs += @(
            '--pxe-client-mac', $esxiMacAddress,
            '--pxe-installer-iso-path', $appliancePxeInstallerIsoPath
        )
        if ($PxeClientIPAddress) {
            $basePythonArgs += @('--pxe-client-ip', $PxeClientIPAddress)
        }
    }
    if ($applianceHostKey) { $basePythonArgs += @('--appliance-ssh-hostkey', $applianceHostKey) }
    if ($clientAHost) { $basePythonArgs += @('--client-a-host', $clientAHost) }
    if ($clientBHost) { $basePythonArgs += @('--client-b-host', $clientBHost) }
    if ($clientAHostKey) { $basePythonArgs += @('--client-a-hostkey', $clientAHostKey) }
    if ($clientBHostKey) { $basePythonArgs += @('--client-b-hostkey', $clientBHostKey) }
    if ($AllowDryRunApply) { $basePythonArgs += '--allow-dry-run' }
    if ($OidcOnly) { $basePythonArgs += '--oidc-only' }
    if ($RoutingWanOnly) { $basePythonArgs += '--routing-wan-only' }

    $initialResultRoot = if ($SkipBackupRestoreTest) { $resultRoot } else { Join-Path $resultRoot 'initial' }
    $restoredResultRoot = Join-Path $resultRoot 'restored'
    $backupArchivePath = Join-Path $resultRoot 'settings-backup.json'

    $initialPythonArgs = @($basePythonArgs + @('--result-dir', $initialResultRoot))
    if (-not $SkipBackupRestoreTest) {
        $initialPythonArgs += @('--export-settings-backup', $backupArchivePath)
    }

    if ($PSCmdlet.ShouldProcess($LabName, 'Run Workstation lifecycle interop scenario')) {
        python @initialPythonArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Lifecycle interop runner failed with exit code $LASTEXITCODE"
        }
        if ($FullEsxiPxeInstall) {
            try {
                Start-WorkstationVm -Path $esxiVmx
                if ($EsxiInstallProbeDelaySeconds -gt 0) {
                    Write-Host "Waiting $EsxiInstallProbeDelaySeconds seconds before probing ESXi guest operations."
                    Start-Sleep -Seconds $EsxiInstallProbeDelaySeconds
                }
                $esxiDetectedIp = Wait-GuestIPv4 -Path $esxiVmx -TimeoutSeconds $EsxiInstallTimeoutSeconds -GuestUser 'root' -GuestPassword 'vmware01!' -Name $esxiName
                if (-not $esxiDetectedIp) {
                    throw "Timed out waiting for ESXi PXE install guest IP after $EsxiInstallTimeoutSeconds seconds."
                }
                Add-LifecycleResultStep -ResultDirectory $initialResultRoot -Name 'esxi-pxe-install-check' -Status 'passed' -Evidence @{
                    vmx                = $esxiVmx
                    mac_address        = $esxiMacAddress
                    detected_ip        = $esxiDetectedIp
                    installer_iso_path = $appliancePxeInstallerIsoPath
                }
            } catch {
                Add-LifecycleResultStep -ResultDirectory $initialResultRoot -Name 'esxi-pxe-install-check' -Status 'failed' -Evidence @{
                    vmx                = $esxiVmx
                    mac_address        = $esxiMacAddress
                    installer_iso_path = $appliancePxeInstallerIsoPath
                } -ErrorMessage $_.Exception.Message
                throw
            }
        }
        if (-not $SkipBackupRestoreTest) {
            $restoredPythonArgs = @($basePythonArgs + @(
                '--result-dir', $restoredResultRoot,
                '--restore-settings-backup', $backupArchivePath,
                '--restored-state-run',
                '--certificate-baseline-result', (Join-Path $initialResultRoot 'result.json')
            ))
            python @restoredPythonArgs
            if ($LASTEXITCODE -ne 0) {
                throw "Restored lifecycle interop runner failed with exit code $LASTEXITCODE"
            }
        }
    }
} finally {
    if ($CleanupCreatedLab) {
        foreach ($vmx in @($createdVmxPaths.ToArray())) {
            Stop-WorkstationVm -Path $vmx
            Unregister-WorkstationVm -Path $vmx
        }
        if (Test-Path -LiteralPath $vmRoot) {
            Remove-Item -LiteralPath $vmRoot -Recurse -Force
        }
    } else {
        Write-Host "Workstation lifecycle VMs were left in place under: $vmRoot"
    }
}
