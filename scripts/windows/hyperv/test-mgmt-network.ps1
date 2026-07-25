[CmdletBinding()]
param(
    [string]$Name = 'Atlaso',
    [string]$MgmtHostIPAddress = '192.168.49.254',
    [string]$MgmtGuestIPAddress = '192.168.49.1',
    [string]$MgmtNatName = 'Atlaso-Mgmt-NAT'
)

$ErrorActionPreference = 'Stop'

function Test-TcpPort {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMilliseconds = 1500
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return $false
        }
        $client.EndConnect($connect)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

$switch = Get-VMSwitch -Name 'Atlaso-Mgmt' -ErrorAction SilentlyContinue
$adapterName = 'vEthernet (Atlaso-Mgmt)'
$adapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
$hostAddress = Get-NetIPAddress -InterfaceAlias $adapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq $MgmtHostIPAddress }
$hostPreferredAddress = $hostAddress | Where-Object { $_.AddressState -eq 'Preferred' }
$nat = Get-NetNat -Name $MgmtNatName -ErrorAction SilentlyContinue
$expectedNatPrefix = '192.168.49.0/24'
$vmAdapter = Get-VMNetworkAdapter -VMName $Name -ErrorAction SilentlyContinue
$vmIps = @($vmAdapter | ForEach-Object { $_.IPAddresses } | Where-Object { $_ })
$ping = Test-Connection -ComputerName $MgmtGuestIPAddress -Count 1 -Quiet -ErrorAction SilentlyContinue
$sshTcp = Test-TcpPort -ComputerName $MgmtGuestIPAddress -Port 22
$webTcp = Test-TcpPort -ComputerName $MgmtGuestIPAddress -Port 8000

[pscustomobject]@{
    SwitchPresent = [bool]$switch
    HostAdapterPresent = [bool]$adapter
    HostAddressPresent = [bool]$hostAddress
    HostAddressState = ($hostAddress | Select-Object -First 1 -ExpandProperty AddressState)
    HostAddressPreferred = [bool]$hostPreferredAddress
    NatPresent = [bool]$nat
    NatPrefix = $nat.InternalIPInterfaceAddressPrefix
    NatPrefixMatches = $nat.InternalIPInterfaceAddressPrefix -eq $expectedNatPrefix
    VmAdapterSwitch = ($vmAdapter | Select-Object -First 1 -ExpandProperty SwitchName)
    VmReportedIPs = ($vmIps -join ', ')
    GuestPing = $ping
    GuestSshTcp = $sshTcp
    GuestWebTcp = $webTcp
}
