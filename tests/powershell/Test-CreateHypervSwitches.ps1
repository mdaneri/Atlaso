param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'

$switchScript = Join-Path $RepositoryRoot 'scripts/windows/hyperv/create-switches.ps1'
if (-not (Test-Path -LiteralPath $switchScript)) {
    throw "Hyper-V switch script not found: $switchScript"
}

$global:AtlasoHypervTestCurrentAddress = ''
$global:AtlasoHypervTestCurrentPrefixLength = 0
$global:AtlasoHypervTestMutations = [System.Collections.Generic.List[string]]::new()
$global:AtlasoHypervTestQueries = [System.Collections.Generic.List[string]]::new()
$global:AtlasoHypervTestCapturedNatPrefixes = [System.Collections.Generic.List[string]]::new()

function Get-VMSwitch {
    param([string]$Name, $ErrorAction)
    $global:AtlasoHypervTestQueries.Add("Get-VMSwitch:$Name")
    return [pscustomobject]@{ Name = $Name }
}

function New-VMSwitch {
    param([string]$Name, [string]$SwitchType)
    $global:AtlasoHypervTestMutations.Add("New-VMSwitch:$Name")
}

function Get-NetAdapter {
    param([string]$Name, $ErrorAction)
    $global:AtlasoHypervTestQueries.Add("Get-NetAdapter:$Name")
    return [pscustomobject]@{ Name = $Name }
}

function Set-NetIPInterface {
    param([string]$InterfaceAlias, [string]$AddressFamily, [string]$Dhcp, [int]$DadTransmits)
    $global:AtlasoHypervTestMutations.Add("Set-NetIPInterface:$InterfaceAlias")
}

function Get-NetIPAddress {
    param([string]$InterfaceAlias, [string]$AddressFamily, $ErrorAction)
    $global:AtlasoHypervTestQueries.Add("Get-NetIPAddress:$InterfaceAlias")
    return [pscustomobject]@{
        IPAddress = $global:AtlasoHypervTestCurrentAddress
        PrefixLength = $global:AtlasoHypervTestCurrentPrefixLength
        AddressState = 'Preferred'
        PrefixOrigin = 'Manual'
    }
}

function Remove-NetIPAddress {
    param([switch]$Confirm, $ErrorAction)
    process {
        $global:AtlasoHypervTestMutations.Add('Remove-NetIPAddress')
    }
}

function New-NetIPAddress {
    param([string]$InterfaceAlias, [string]$IPAddress, [int]$PrefixLength)
    $global:AtlasoHypervTestMutations.Add("New-NetIPAddress:$IPAddress/$PrefixLength")
}

function Get-NetNat {
    param([string]$Name, $ErrorAction)
    $global:AtlasoHypervTestQueries.Add("Get-NetNat:$Name")
    return $null
}

function Remove-NetNat {
    param([string]$Name, [switch]$Confirm)
    $global:AtlasoHypervTestMutations.Add("Remove-NetNat:$Name")
}

function New-NetNat {
    param([string]$Name, [string]$InternalIPInterfaceAddressPrefix)
    $global:AtlasoHypervTestMutations.Add("New-NetNat:$Name")
    $global:AtlasoHypervTestCapturedNatPrefixes.Add($InternalIPInterfaceAddressPrefix)
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Actual -ne $Expected) {
        throw "$Context expected '$Expected', got '$Actual'"
    }
}

$validCases = @(
    @{ Address = '10.20.30.129'; PrefixLength = 16; Expected = '10.20.0.0/16' },
    @{ Address = '10.20.31.129'; PrefixLength = 23; Expected = '10.20.30.0/23' },
    @{ Address = '192.168.49.254'; PrefixLength = 24; Expected = '192.168.49.0/24' },
    @{ Address = '10.20.30.129'; PrefixLength = 25; Expected = '10.20.30.128/25' },
    @{ Address = '10.20.30.133'; PrefixLength = 30; Expected = '10.20.30.132/30' }
)

foreach ($case in $validCases) {
    $global:AtlasoHypervTestCurrentAddress = $case.Address
    $global:AtlasoHypervTestCurrentPrefixLength = $case.PrefixLength
    $global:AtlasoHypervTestMutations.Clear()
    $global:AtlasoHypervTestQueries.Clear()
    $global:AtlasoHypervTestCapturedNatPrefixes.Clear()

    try {
        & $switchScript `
            -MgmtHostIPAddress $case.Address `
            -MgmtPrefixLength $case.PrefixLength `
            -Confirm:$false
    } catch {
        throw "Valid case $($case.Address)/$($case.PrefixLength) failed: $($_.Exception.Message)`n$($_.ScriptStackTrace)"
    }

    Assert-Equal `
        -Actual $global:AtlasoHypervTestCapturedNatPrefixes.Count `
        -Expected 1 `
        -Context "$($case.Address)/$($case.PrefixLength) NAT creation count"
    Assert-Equal `
        -Actual $global:AtlasoHypervTestCapturedNatPrefixes[0] `
        -Expected $case.Expected `
        -Context "$($case.Address)/$($case.PrefixLength) NAT prefix"
}

$invalidCases = @(
    @{ Address = 'not-an-address'; PrefixLength = 24 },
    @{ Address = '10.20.30.999'; PrefixLength = 24 },
    @{ Address = '2001:db8::1'; PrefixLength = 24 },
    @{ Address = '10.20.30.129'; PrefixLength = -1 },
    @{ Address = '10.20.30.129'; PrefixLength = 33 }
)

foreach ($case in $invalidCases) {
    $global:AtlasoHypervTestMutations.Clear()
    $global:AtlasoHypervTestQueries.Clear()
    $global:AtlasoHypervTestCapturedNatPrefixes.Clear()

    $failed = $false
    try {
        & $switchScript `
            -MgmtHostIPAddress $case.Address `
            -MgmtPrefixLength $case.PrefixLength `
            -Confirm:$false
    } catch {
        $failed = $true
    }

    Assert-Equal `
        -Actual $failed `
        -Expected $true `
        -Context "$($case.Address)/$($case.PrefixLength) validation"
    Assert-Equal `
        -Actual $global:AtlasoHypervTestQueries.Count `
        -Expected 0 `
        -Context "$($case.Address)/$($case.PrefixLength) preflight query count"
    Assert-Equal `
        -Actual $global:AtlasoHypervTestMutations.Count `
        -Expected 0 `
        -Context "$($case.Address)/$($case.PrefixLength) mutation count"
}

Write-Output 'Hyper-V management NAT prefix tests passed.'
