[CmdletBinding()]
param(
    [string]$Name = 'Atlaso-Photon-Builder',
    [string]$SwitchName,
    [int]$TimeoutSeconds = 120,
    [int]$PollSeconds = 5
)

$ErrorActionPreference = 'Stop'

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$hostIpv4Addresses = @(
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty IPAddress
)

do {
    $adapters = Get-VMNetworkAdapter -VMName $Name
    if ($SwitchName) {
        $adapters = $adapters | Where-Object { $_.SwitchName -eq $SwitchName }
    }

    $addresses = @(
        $adapters |
            ForEach-Object { $_.IPAddresses } |
            Where-Object { $_ } |
            ForEach-Object {
                $parsed = $null
                if ([System.Net.IPAddress]::TryParse($_, [ref]$parsed) -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $_
                }
            } |
            Where-Object {
                $_ -notlike '169.254.*' -and
                $_ -ne '0.0.0.0' -and
                $_ -ne '127.0.0.1' -and
                $_ -notin $hostIpv4Addresses
            }
    )

    if ($addresses.Count -gt 0) {
        $addresses | Select-Object -First 1
        exit 0
    }

    if ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $PollSeconds
    }
} while ((Get-Date) -lt $deadline)

throw "No IPv4 address reported for VM '$Name'$(if ($SwitchName) { " on switch '$SwitchName'" }). Run this from an elevated PowerShell session and confirm Photon has the Hyper-V KVP daemon running."
