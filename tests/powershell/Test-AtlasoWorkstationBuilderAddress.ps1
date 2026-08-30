<#
.SYNOPSIS
Validate VMware builder-address pool admission and reservation behavior.

.PARAMETER RepositoryRoot
Atlaso repository root containing the module and wrapper under test.
#>
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationBuilderAddress.psm1'
$wrapperPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\build-photon-image.ps1'
Import-Module $modulePath -Force

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-builder-address-test-$([guid]::NewGuid().ToString('N'))"
)
[void][System.IO.Directory]::CreateDirectory($testRoot)
try {
    $dhcpPath = Join-Path $testRoot 'vmnetdhcp.conf'
    [System.IO.File]::WriteAllText(
        $dhcpPath,
        @'
subnet 192.0.2.0 netmask 255.255.255.0 {
range 192.0.2.128 192.0.2.254;
}
host VMnet8 {
fixed-address 192.0.2.1;
}
'@,
        [System.Text.UTF8Encoding]::new($false)
    )
    $dhcp = Get-AtlasoVmwareDhcpExclusions `
        -Subnet '192.0.2.0' `
        -Netmask '255.255.255.0' `
        -DhcpEnabled $true `
        -ConfigPath $dhcpPath
    if ($dhcp.Ranges.Count -ne 1 -or $dhcp.FixedAddresses.Count -ne 1) {
        throw 'VMware DHCP exclusions did not preserve the exact dynamic range and fixed address.'
    }

    $invalidDhcpPath = Join-Path $testRoot 'invalid-vmnetdhcp.conf'
    [System.IO.File]::WriteAllText(
        $invalidDhcpPath,
        "subnet 192.0.2.0 netmask 255.255.255.0 {`nrange 192.0.2.128 192.0.2.256;`n}`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    try {
        $null = Get-AtlasoVmwareDhcpExclusions `
            -Subnet '192.0.2.0' `
            -Netmask '255.255.255.0' `
            -DhcpEnabled $true `
            -ConfigPath $invalidDhcpPath
        throw 'An invalid VMware DHCP range endpoint was accepted.'
    }
    catch {
        if ($_.Exception.Message -eq 'An invalid VMware DHCP range endpoint was accepted.') { throw }
    }

    $vmrunPath = Join-Path $testRoot 'fake-vmrun.ps1'
    [System.IO.File]::WriteAllText(
        $vmrunPath,
        @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
if ($Arguments[-1] -ceq 'list') {
    'Total running VMs: 0'
    exit 0
}
exit 1
'@,
        [System.Text.UTF8Encoding]::new($false)
    )
    $stateRoot = Join-Path $testRoot 'state'
    $outputOne = Join-Path $testRoot 'output-one'
    $outputTwo = Join-Path $testRoot 'output-two'
    $common = @{
        NetworkName                = 'VMnet8'
        Subnet                     = '192.0.2.0'
        Netmask                    = '255.255.255.0'
        DhcpEnabled                = $true
        PoolStartOffset            = 30
        PoolEndOffset              = 31
        AdditionalExcludedAddresses = @('192.0.2.2')
        DhcpConfigPath             = $dhcpPath
        StateRoot                  = $stateRoot
        VmrunPath                  = $vmrunPath
        VmName                     = 'Atlaso-Photon-Builder-VMware'
        RepositoryRoot             = $RepositoryRoot
    }
    $first = Enter-AtlasoVmwareBuilderAddressReservation @common -OutputDirectory $outputOne
    $second = Enter-AtlasoVmwareBuilderAddressReservation @common -OutputDirectory $outputTwo
    if ($first.Address -cne '192.0.2.30' -or $second.Address -cne '192.0.2.31') {
        throw 'Concurrent reservations did not allocate distinct deterministic builder addresses.'
    }

    $runningVmrunPath = Join-Path $testRoot 'fake-running-vmrun.ps1'
    $runningVmrunSource = @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
if ($Arguments[-1] -ceq 'list') {
    'Total running VMs: 1'
    '__VMX__'
    exit 0
}
exit 1
'@.Replace('__VMX__', $second.VmxPath.Replace("'", "''"))
    [System.IO.File]::WriteAllText(
        $runningVmrunPath,
        $runningVmrunSource,
        [System.Text.UTF8Encoding]::new($false)
    )
    try {
        Exit-AtlasoVmwareBuilderAddressReservation `
            -Reservation $second `
            -VmrunPath $runningVmrunPath `
            -StateRoot $stateRoot
        throw 'A running builder VM released its address reservation.'
    }
    catch {
        if ($_.Exception.Message -eq 'A running builder VM released its address reservation.') { throw }
    }

    $truncatedVmrunPath = Join-Path $testRoot 'fake-truncated-vmrun.ps1'
    [System.IO.File]::WriteAllText(
        $truncatedVmrunPath,
        "param([Parameter(ValueFromRemainingArguments = `$true)][string[]]`$Arguments)`n'Total running VMs: 1'`nexit 0`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    try {
        Exit-AtlasoVmwareBuilderAddressReservation `
            -Reservation $first `
            -VmrunPath $truncatedVmrunPath `
            -StateRoot $stateRoot
        throw 'A truncated vmrun inventory released its builder address.'
    }
    catch {
        if ($_.Exception.Message -eq 'A truncated vmrun inventory released its builder address.') { throw }
    }

    try {
        $null = Enter-AtlasoVmwareBuilderAddressReservation `
            @common `
            -OutputDirectory (Join-Path $testRoot 'output-three') `
            -PreferredAddress '192.0.2.128'
        throw 'A builder address inside VMware DHCP was accepted.'
    }
    catch {
        if ($_.Exception.Message -eq 'A builder address inside VMware DHCP was accepted.') { throw }
    }

    Exit-AtlasoVmwareBuilderAddressReservation -Reservation $first -VmrunPath $vmrunPath -StateRoot $stateRoot
    $replacement = Enter-AtlasoVmwareBuilderAddressReservation @common -OutputDirectory $outputOne
    if ($replacement.Address -cne '192.0.2.30') {
        throw 'A normally released builder address did not return to the pool.'
    }
    Exit-AtlasoVmwareBuilderAddressReservation -Reservation $replacement -VmrunPath $vmrunPath -StateRoot $stateRoot
    Exit-AtlasoVmwareBuilderAddressReservation -Reservation $second -VmrunPath $vmrunPath -StateRoot $stateRoot

    $activeStateRoot = Join-Path $testRoot 'active-owner-state'
    $activeCommon = $common.Clone()
    $activeCommon.StateRoot = $activeStateRoot
    $activeOwnerReservation = Enter-AtlasoVmwareBuilderAddressReservation `
        @activeCommon `
        -OutputDirectory (Join-Path $testRoot 'active-owner-output')
    $sleeper = Start-Process `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @('-NoLogo', '-NoProfile', '-Command', 'Start-Sleep -Seconds 30') `
        -WindowStyle Hidden `
        -PassThru
    try {
        $sleeper.Refresh()
        $activeOwnerReservation.OwnerPid = $sleeper.Id
        $activeOwnerReservation.OwnerStartTimeUtcTicks = $sleeper.StartTime.ToUniversalTime().Ticks
        $activeLedgerPath = Join-Path $activeStateRoot 'reservations.json'
        $activeLedger = [ordered]@{ Schema = 1; Reservations = @($activeOwnerReservation) }
        [System.IO.File]::WriteAllText(
            $activeLedgerPath,
            (($activeLedger | ConvertTo-Json -Depth 6) + "`n"),
            [System.Text.UTF8Encoding]::new($false)
        )
        try {
            Exit-AtlasoVmwareBuilderAddressReservation `
                -Reservation $activeOwnerReservation `
                -VmrunPath $vmrunPath `
                -StateRoot $activeStateRoot
            throw 'A live foreign owner released its builder address.'
        }
        catch {
            if ($_.Exception.Message -eq 'A live foreign owner released its builder address.') { throw }
        }
    }
    finally {
        Stop-Process -Id $sleeper.Id -Force -ErrorAction SilentlyContinue
        $sleeper.WaitForExit()
        $sleeper.Dispose()
    }
    try {
        Exit-AtlasoVmwareBuilderAddressReservation `
            -Reservation $activeOwnerReservation `
            -VmrunPath $vmrunPath `
            -StateRoot $activeStateRoot
        throw 'A dead same-boot foreign owner released without whole-tree termination proof.'
    }
    catch {
        if ($_.Exception.Message -eq 'A dead same-boot foreign owner released without whole-tree termination proof.') { throw }
    }
    Exit-AtlasoVmwareBuilderAddressReservation `
        -Reservation $activeOwnerReservation `
        -VmrunPath $vmrunPath `
        -StateRoot $activeStateRoot `
        -ProcessTreeTerminationProven

    $ledgerPath = Join-Path $stateRoot 'reservations.json'
    $currentBootIdentity = ([DateTimeOffset](
            Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop |
                Select-Object -First 1
        ).LastBootUpTime).ToUniversalTime().Ticks.ToString(
        [Globalization.CultureInfo]::InvariantCulture
    )
    $stale = [ordered]@{
        Schema = 1
        Reservations = @([ordered]@{
                Id                     = '0123456789abcdef0123456789abcdef'
                Address                = '192.0.2.30'
                Cidr                   = '192.0.2.30/24'
                NetworkName            = 'vmnet8'
                Subnet                 = '192.0.2.0'
                Netmask                = '255.255.255.0'
                OwnerPid               = 2147483647
                OwnerStartTimeUtcTicks = 1
                HostBootIdentity       = $currentBootIdentity
                RepositoryRoot         = $RepositoryRoot
                SourceCommit           = ('0' * 40)
                SourceBranch           = 'bug/stale-test'
                OutputDirectory        = (Join-Path $testRoot 'stale-output')
                VmName                 = 'Atlaso-Photon-Builder-VMware'
                VmxPath                = (Join-Path $testRoot 'stale-output\Atlaso-Photon-Builder-VMware.vmx')
                CreatedUtc             = '2026-01-01T00:00:00.0000000Z'
            })
    }
    [System.IO.File]::WriteAllText(
        $ledgerPath,
        (($stale | ConvertTo-Json -Depth 5) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $sameBoot = Enter-AtlasoVmwareBuilderAddressReservation @common -OutputDirectory $outputOne
    if ($sameBoot.Address -cne '192.0.2.31') {
        throw 'A same-boot orphaned reservation was recovered without whole-tree termination proof.'
    }
    Exit-AtlasoVmwareBuilderAddressReservation -Reservation $sameBoot -VmrunPath $vmrunPath -StateRoot $stateRoot

    $stale.Reservations[0].HostBootIdentity = '1'
    [System.IO.File]::WriteAllText(
        $ledgerPath,
        (($stale | ConvertTo-Json -Depth 5) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $recovered = Enter-AtlasoVmwareBuilderAddressReservation @common -OutputDirectory $outputOne
    if ($recovered.Address -cne '192.0.2.30') {
        throw 'Prior-boot stale reservation recovery did not return the address to the pool.'
    }
    Exit-AtlasoVmwareBuilderAddressReservation -Reservation $recovered -VmrunPath $vmrunPath -StateRoot $stateRoot

    $wrapper = [System.IO.File]::ReadAllText($wrapperPath)
    foreach ($required in @(
            'Atlaso.WorkstationBuilderAddress.psm1',
            'Enter-AtlasoVmwareBuilderAddressReservation',
            'Exit-AtlasoVmwareBuilderAddressReservation',
            'BuilderAddressPoolStartOffset',
            'BuilderAddressPoolEndOffset',
            'VmwareDhcpConfigPath',
            'builder-address-reservation-'
            'pending-releases'
            'Complete-AtlasoBuilderAddressReservationHandoff'
            'ProcessTreeTerminationProven'
            'Builder-address handoff publication failed and exact reservation rollback also failed'
            'SkipNetworkCheck suppresses topology preparation, not allocator safety'
            'HostAddresses'
            '(@($BuilderStaticGateway) + $managementHostAddresses)'
        )) {
        if (-not $wrapper.Contains($required, [StringComparison]::Ordinal)) {
            throw "The Photon wrapper is missing builder reservation integration marker: $required"
        }
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Write-Host 'VMware builder-address reservation checks passed.'
