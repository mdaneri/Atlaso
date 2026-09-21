<#
.SYNOPSIS
Validate VMware builder-address pool admission and reservation behavior.

.PARAMETER RepositoryRoot
Atlaso repository root containing the module and wrapper under test.
.PARAMETER RetainedTestRoot
Existing empty task-owned validation root whose cleanup is managed by the caller.
#>
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [string]$RetainedTestRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationBuilderAddress.psm1'
$wrapperPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\build-photon-image.ps1'
Import-Module $modulePath -Force

$testRoot = if ($RetainedTestRoot) { [IO.Path]::GetFullPath($RetainedTestRoot) } else { Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-builder-address-test-$([guid]::NewGuid().ToString('N'))"
) }
if ($RetainedTestRoot -and (-not (Test-Path -LiteralPath $testRoot -PathType Container) -or
    @(Get-ChildItem -LiteralPath $testRoot -Force).Count -ne 0)) {
    throw 'The retained validation root must already exist and be empty.'
}
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
    $sourceCommit = [string](& git -C $RepositoryRoot rev-parse HEAD)
    $sourceBranch = [string](& git -C $RepositoryRoot branch --show-current)
    if ($LASTEXITCODE -ne 0 -or $sourceCommit.Trim() -notmatch '^[0-9a-f]{40}$' -or
        [string]::IsNullOrWhiteSpace($sourceBranch)) {
        throw 'Could not resolve the builder-address test source identity.'
    }
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
        VmName                     = 'Atlaso-PR-653-Photon-Builder-VMware'
        RepositoryRoot             = $RepositoryRoot
        SourceCommit               = $sourceCommit.Trim()
        SourceBranch               = $sourceBranch.Trim()
    }
    $localCommon = $common.Clone()
    $localCommon.StateRoot = Join-Path $testRoot 'local-state'
    $localCommon.VmName = "Atlaso-Local-$($sourceCommit.Trim().Substring(0, 12))-Photon-Builder-VMware-run-02"
    $localReservation = Enter-AtlasoVmwareBuilderAddressReservation `
        @localCommon `
        -OutputDirectory (Join-Path $testRoot 'local-output')
    if ($localReservation.VmName -cne $localCommon.VmName) {
        throw 'A canonical local/test builder identity did not retain its address reservation ownership.'
    }
    Exit-AtlasoVmwareBuilderAddressReservation `
        -Reservation $localReservation `
        -VmrunPath $vmrunPath `
        -StateRoot $localCommon.StateRoot
    $first = Enter-AtlasoVmwareBuilderAddressReservation @common -OutputDirectory $outputOne
    $second = Enter-AtlasoVmwareBuilderAddressReservation @common -OutputDirectory $outputTwo
    if ($first.Address -cne '192.0.2.30' -or $second.Address -cne '192.0.2.31') {
        throw 'Concurrent reservations did not allocate distinct deterministic builder addresses.'
    }

    $excludedStateRoot = Join-Path $testRoot 'ordinary-exclusion-state'
    $excludedCommon = $common.Clone()
    $excludedCommon.StateRoot = $excludedStateRoot
    $excludedCommon.AdditionalExcludedAddresses = @('192.0.2.30')
    $skipped = Enter-AtlasoVmwareBuilderAddressReservation `
        @excludedCommon `
        -OutputDirectory (Join-Path $testRoot 'ordinary-exclusion-output')
    if ($skipped.Address -cne '192.0.2.31') {
        throw 'Automatic allocation did not skip an ordinary host or network exclusion.'
    }
    Exit-AtlasoVmwareBuilderAddressReservation -Reservation $skipped -VmrunPath $vmrunPath -StateRoot $excludedStateRoot
    try {
        $null = Enter-AtlasoVmwareBuilderAddressReservation `
            @excludedCommon `
            -OutputDirectory (Join-Path $testRoot 'preferred-exclusion-output') `
            -PreferredAddress '192.0.2.30'
        throw 'An explicitly preferred ordinary exclusion was accepted.'
    }
    catch {
        if ($_.Exception.Message -eq 'An explicitly preferred ordinary exclusion was accepted.') { throw }
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
    $completedReplacement = $replacement | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $completedReplacement.OwnerPid = 2147483647
    $completedReplacement.OwnerStartTimeUtcTicks = 1
    Exit-AtlasoVmwareBuilderAddressReservation `
        -Reservation $completedReplacement `
        -VmrunPath $vmrunPath `
        -StateRoot $stateRoot
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

    $reusedPidStateRoot = Join-Path $testRoot 'reused-pid-state'
    $reusedPidCommon = $common.Clone()
    $reusedPidCommon.StateRoot = $reusedPidStateRoot
    $reusedPidReservation = Enter-AtlasoVmwareBuilderAddressReservation `
        @reusedPidCommon `
        -OutputDirectory (Join-Path $testRoot 'reused-pid-output')
    $reusedPidReservation.OwnerStartTimeUtcTicks = 1
    $reusedPidLedger = [ordered]@{ Schema = 1; Reservations = @($reusedPidReservation) }
    [System.IO.File]::WriteAllText(
        (Join-Path $reusedPidStateRoot 'reservations.json'),
        (($reusedPidLedger | ConvertTo-Json -Depth 6) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    try {
        Exit-AtlasoVmwareBuilderAddressReservation `
            -Reservation $reusedPidReservation `
            -VmrunPath $vmrunPath `
            -StateRoot $reusedPidStateRoot
        throw 'A reused PID released a dead same-boot reservation as its own.'
    }
    catch {
        if ($_.Exception.Message -eq 'A reused PID released a dead same-boot reservation as its own.') { throw }
    }
    Exit-AtlasoVmwareBuilderAddressReservation `
        -Reservation $reusedPidReservation `
        -VmrunPath $vmrunPath `
        -StateRoot $reusedPidStateRoot `
        -ProcessTreeTerminationProven

    $preHandoffStateRoot = Join-Path $testRoot 'pre-handoff-state'
    # Keep this fixture comfortably below Win32's legacy path limit so the
    # test isolates handoff ordering rather than host long-path configuration.
    $preHandoffBuildRoot = Join-Path $testRoot 'phb'
    $preHandoffTaskRoot = Join-Path $preHandoffBuildRoot 'ba'
    $preHandoffPendingRoot = Join-Path $preHandoffTaskRoot 'pending-releases'
    $preHandoffIdentity = Initialize-AtlasoBuilderHandoffRoot `
        -BuildStateRoot $preHandoffBuildRoot `
        -HandoffStateRoot $preHandoffTaskRoot `
        -PendingRoot $preHandoffPendingRoot
    $preHandoffPath = Join-Path $preHandoffPendingRoot (
        "builder-address-reservation-$([guid]::NewGuid().ToString('N')).json"
    )
    $preHandoffCommon = $common.Clone()
    $preHandoffCommon.StateRoot = $preHandoffStateRoot
    try {
        $preHandoffReservation = Enter-AtlasoVmwareBuilderAddressReservation `
            @preHandoffCommon `
            -HandoffStateRoot $preHandoffTaskRoot `
            -HandoffBuildStateRoot $preHandoffBuildRoot `
            -HandoffStateIdentity ([string]$preHandoffIdentity.StateIdentity) `
            -HandoffPendingIdentity ([string]$preHandoffIdentity.PendingIdentity) `
            -ReservationHandoffPath $preHandoffPath `
            -OutputDirectory (Join-Path $testRoot 'pre-handoff-output')
    }
    catch {
        throw "Pre-ledger handoff publication failed with existing roots build=$(Test-Path -LiteralPath $preHandoffBuildRoot), state=$(Test-Path -LiteralPath $preHandoffTaskRoot), pending=$(Test-Path -LiteralPath $preHandoffPendingRoot): $($_.Exception.Message)"
    }
    if (-not (Test-Path -LiteralPath $preHandoffPath -PathType Leaf)) {
        throw 'Reservation admission returned before its durable release handoff was published.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $preHandoffStateRoot 'reservations.json') -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $preHandoffTaskRoot 'reservations.json'))) {
        throw 'Reservation admission did not keep the shared ledger separate from the task-owned handoff.'
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $preHandoffStateRoot 'reservations.json'),
        (([ordered]@{ Schema = 1; Reservations = @() } | ConvertTo-Json -Depth 6) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    try {
        Exit-AtlasoVmwareBuilderAddressReservation `
            -Reservation $preHandoffReservation `
            -VmrunPath $vmrunPath `
            -StateRoot $preHandoffStateRoot
        throw 'A pre-ledger handoff was retired while its exact owner remained active.'
    }
    catch {
        if ($_.Exception.Message -notmatch 'remains pending because its exact owner process is still active') { throw }
    }
    $completedPreHandoff = $preHandoffReservation | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $completedPreHandoff.OwnerPid = 2147483647
    $completedPreHandoff.OwnerStartTimeUtcTicks = 1
    Exit-AtlasoVmwareBuilderAddressReservation `
        -Reservation $completedPreHandoff `
        -VmrunPath $vmrunPath `
        -StateRoot $preHandoffStateRoot

    $swappedStateRoot = Join-Path $testRoot 'shs'
    $swappedBuildRoot = Join-Path $testRoot 'shb'
    $swappedTaskRoot = Join-Path $swappedBuildRoot 'ba'
    $swappedPendingRoot = Join-Path $swappedTaskRoot 'pending-releases'
    $swappedEscapeRoot = Join-Path $testRoot 'she'
    [void][System.IO.Directory]::CreateDirectory($swappedEscapeRoot)
    $swappedIdentity = Initialize-AtlasoBuilderHandoffRoot `
        -BuildStateRoot $swappedBuildRoot `
        -HandoffStateRoot $swappedTaskRoot `
        -PendingRoot $swappedPendingRoot
    Move-Item `
        -LiteralPath $swappedPendingRoot `
        -Destination "$swappedPendingRoot-original" `
        -ErrorAction Stop
    [void](New-Item `
            -ItemType Junction `
            -Path $swappedPendingRoot `
            -Target $swappedEscapeRoot `
            -ErrorAction Stop)
    $swappedHandoffName = "builder-address-reservation-$([guid]::NewGuid().ToString('N')).json"
    $swappedHandoffPath = Join-Path $swappedPendingRoot $swappedHandoffName
    $swappedCommon = $common.Clone()
    $swappedCommon.StateRoot = $swappedStateRoot
    $swappedError = ''
    try {
        $null = Enter-AtlasoVmwareBuilderAddressReservation `
            @swappedCommon `
            -HandoffStateRoot $swappedTaskRoot `
            -HandoffBuildStateRoot $swappedBuildRoot `
            -HandoffStateIdentity ([string]$swappedIdentity.StateIdentity) `
            -HandoffPendingIdentity ([string]$swappedIdentity.PendingIdentity) `
            -ReservationHandoffPath $swappedHandoffPath `
            -OutputDirectory (Join-Path $testRoot 'swapped-handoff-output')
    }
    catch {
        $swappedError = $_.Exception.Message
    }
    if ($swappedError -notmatch 'reparse point|ancestry changed' -or
        (Test-Path -LiteralPath (Join-Path $swappedEscapeRoot $swappedHandoffName)) -or
        (Test-Path -LiteralPath (Join-Path $swappedStateRoot 'reservations.json'))) {
        throw "A replaced pending-release directory did not block publication and ledger admission: $swappedError"
    }
    Remove-Item -LiteralPath $swappedPendingRoot -Force

    $postRenameStateRoot = Join-Path $testRoot 'post-rename-sync-state'
    [void][System.IO.Directory]::CreateDirectory($postRenameStateRoot)
    $postRenameLedgerPath = Join-Path $postRenameStateRoot 'reservations.json'
    $module = Get-Module -Name Atlaso.WorkstationBuilderAddress -ErrorAction Stop
    & $module {
        param($LedgerPath)
        function Sync-AtlasoBuilderLedgerDirectory {
            <#
            .SYNOPSIS
            Inject a post-rename directory synchronization failure.
            #>
            throw 'Injected post-rename directory synchronization failure.'
        }
        Write-AtlasoBuilderReservationLedger -Path $LedgerPath -Reservations @()
    } $postRenameLedgerPath
    $postRenameLedger = Get-Content -LiteralPath $postRenameLedgerPath -Raw | ConvertFrom-Json
    if ([int]$postRenameLedger.Schema -ne 1 -or @($postRenameLedger.Reservations).Count -ne 0) {
        throw 'Post-rename synchronization reconciliation did not preserve the published ledger.'
    }
    Import-Module $modulePath -Force

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
                VmName                 = 'Atlaso-PR-653-Photon-Builder-VMware'
                VmxPath                = (Join-Path $testRoot 'stale-output\Atlaso-PR-653-Photon-Builder-VMware.vmx')
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
    $staleRunningVmrunPath = Join-Path $testRoot 'fake-stale-running-vmrun.ps1'
    $staleRunningVmrunSource = @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
if ($Arguments[-1] -ceq 'list') {
    'Total running VMs: 1'
    '__VMX__'
    exit 0
}
exit 1
'@.Replace('__VMX__', $stale.Reservations[0].VmxPath.Replace("'", "''"))
    [System.IO.File]::WriteAllText(
        $staleRunningVmrunPath,
        $staleRunningVmrunSource,
        [System.Text.UTF8Encoding]::new($false)
    )
    $staleRunningCommon = $common.Clone()
    $staleRunningCommon.VmrunPath = $staleRunningVmrunPath
    $retainedStale = Enter-AtlasoVmwareBuilderAddressReservation `
        @staleRunningCommon `
        -OutputDirectory $outputOne
    if ($retainedStale.Address -cne '192.0.2.31') {
        throw 'An occupied prior-boot reservation prevented allocation of another safe pool address.'
    }
    Exit-AtlasoVmwareBuilderAddressReservation `
        -Reservation $retainedStale `
        -VmrunPath $vmrunPath `
        -StateRoot $stateRoot

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

    # A completed controller retains proof when checked VM deletion fails.
    $recoveryState = Join-Path $testRoot 'recovery-state'
    $pending = Join-Path $testRoot 'recovery/pending-releases'
    [void][IO.Directory]::CreateDirectory($recoveryState)
    [void][IO.Directory]::CreateDirectory($pending)
    [IO.File]::WriteAllText((Join-Path $recoveryState 'reservations.lock'), '')
    $handoffPath = Join-Path $pending 'builder-address-reservation-0123456789abcdef0123456789abcdef.json'
    $record = $stale.Reservations[0] | ConvertTo-Json | ConvertFrom-Json
    $record.HostBootIdentity = $currentBootIdentity
    $unrelated = $record | ConvertTo-Json | ConvertFrom-Json
    $unrelated.Id = '1123456789abcdef0123456789abcdef'
    $unrelated.Address = '192.0.2.31'
    $recoveryLedger = Join-Path $recoveryState 'reservations.json'
    [IO.File]::WriteAllText($handoffPath, ($record | ConvertTo-Json))
    [IO.File]::WriteAllText($recoveryLedger, (@{Schema=1;Reservations=@($record,$unrelated)} | ConvertTo-Json -Depth 8))
    $before = (Get-FileHash $recoveryLedger).Hash
    $blocked = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $vmrunPath -StateRoot $recoveryState
    if ($blocked.Status -ne 'blocked' -or (Get-FileHash $recoveryLedger).Hash -cne $before) {
        throw 'Legacy same-boot verification mutated state or invented process proof.'
    }
    $publisher = Join-Path $testRoot 'publish-proof.ps1'
    $failedChild = Join-Path $testRoot 'failed-builder.ps1'
    [IO.File]::WriteAllText($failedChild, @'
param($HandoffPath, $LedgerPath)
$record = Get-Content $HandoffPath -Raw | ConvertFrom-Json
$record.PSObject.Properties.Remove('TerminationProof')
$record.OwnerPid = $PID
$record.OwnerStartTimeUtcTicks = (Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks
$ledger = Get-Content $LedgerPath -Raw | ConvertFrom-Json
$ledger.Reservations = @($record) + @($ledger.Reservations | Where-Object Id -ne $record.Id)
$record | ConvertTo-Json -Depth 8 | Set-Content $HandoffPath
$ledger | ConvertTo-Json -Depth 8 | Set-Content $LedgerPath
exit 1
'@)
    [IO.File]::WriteAllText($publisher, @'
param($ModulePath, $HandoffPath, $ChildPath, $LedgerPath)
Import-Module $ModulePath -Force
. (Join-Path (Split-Path -Parent $ModulePath) 'Atlaso.WorkstationFirstBoot.ps1')
$identity = @{}
try {
    Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @('-NoProfile', '-File', $ChildPath, $HandoffPath, $LedgerPath) `
        -TimeoutSeconds 20 -Action 'Inert builder fixture' `
        -ProcessJobName ('Local\Atlaso-Receipt-Test-' + [guid]::NewGuid().ToString('N')) `
        -ProcessOwnershipPublisher {
            param($Job)
            $identity.Id = $Job.RootProcess.Id
            $identity.Ticks = $Job.RootProcess.StartTime.ToUniversalTime().Ticks
        }
    throw 'The failed child unexpectedly succeeded.'
}
catch {
    if (-not $_.Exception.Data['AtlasoProcessTreeTerminationProven']) { throw }
    Save-AtlasoBuilderTerminationProof -HandoffPath $HandoffPath `
        -ExpectedOwnerPid $identity.Id -ExpectedOwnerStartTimeUtcTicks $identity.Ticks
}
'@)
    & (Get-Process -Id $PID).Path -NoProfile -File $publisher $modulePath $handoffPath $failedChild $recoveryLedger
    if ($LASTEXITCODE -ne 0) { throw 'Completed controller did not durably preserve termination proof.' }
    $before = (Get-FileHash $recoveryLedger).Hash
    $receiptBytes = [IO.File]::ReadAllText($handoffPath)
    $verified = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $vmrunPath -StateRoot $recoveryState
    if ($verified.Status -ne 'releasable' -or (Get-FileHash $recoveryLedger).Hash -cne $before -or
        [IO.File]::ReadAllText($handoffPath) -cne $receiptBytes) {
        throw "A later caller could not verify unchanged same-boot recovery: $($verified.Reason)"
    }
    & (Join-Path $RepositoryRoot 'scripts/windows/vmware/manage-builder-reservation.ps1') `
        -HandoffPath $handoffPath -VmrunPath $vmrunPath -ReservationStateRoot $recoveryState -Cleanup -WhatIf -Json
    if ((Get-FileHash $recoveryLedger).Hash -cne $before -or [IO.File]::ReadAllText($handoffPath) -cne $receiptBytes) {
        throw 'The operator WhatIf path changed reservation state.'
    }
    $linkedHandoff = Join-Path $pending 'builder-address-reservation-1123456789abcdef0123456789abcdef.json'
    New-Item -ItemType HardLink -Path $linkedHandoff -Target $handoffPath | Out-Null
    $linked = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $vmrunPath -StateRoot $recoveryState -Execute
    if ($linked.Status -ne 'blocked' -or (Get-FileHash $recoveryLedger).Hash -cne $before) {
        throw 'A hard-linked handoff was accepted for mutation.'
    }
    Remove-Item -LiteralPath $linkedHandoff
    # A wall-clock rollback invalidates same-boot proof, but cannot invalidate
    # the independent process-termination boundary supplied by a later boot.
    $clockSkew = $receiptBytes | ConvertFrom-Json
    $clockSkew.TerminationProof.CompletedUtc = [DateTime]::UtcNow.AddDays(1).ToString('o')
    [IO.File]::WriteAllText($handoffPath, ($clockSkew | ConvertTo-Json -Depth 8))
    $sameBootSkew = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $vmrunPath -StateRoot $recoveryState
    if ($sameBootSkew.Status -ne 'blocked') { throw 'Future-dated same-boot proof was accepted.' }
    $ledgerBytes = [IO.File]::ReadAllText($recoveryLedger)
    $priorBootLedger = $ledgerBytes | ConvertFrom-Json
    $priorBootLedger.Reservations[0].HostBootIdentity = '1'
    $clockSkew.HostBootIdentity = '1'
    [IO.File]::WriteAllText($recoveryLedger, ($priorBootLedger | ConvertTo-Json -Depth 8))
    [IO.File]::WriteAllText($handoffPath, ($clockSkew | ConvertTo-Json -Depth 8))
    $priorBootSkew = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $vmrunPath -StateRoot $recoveryState
    if ($priorBootSkew.Status -ne 'releasable') {
        throw "Prior-boot recovery incorrectly depended on its stale receipt: $($priorBootSkew.Reason)"
    }
    [IO.File]::WriteAllText($recoveryLedger, $ledgerBytes)
    [IO.File]::WriteAllText($handoffPath, $receiptBytes)
    $altered = $receiptBytes | ConvertFrom-Json
    $altered.SourceBranch = 'changed'
    [IO.File]::WriteAllText($handoffPath, ($altered | ConvertTo-Json -Depth 8))
    $rejected = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $vmrunPath -StateRoot $recoveryState -Execute
    if ($rejected.Status -ne 'blocked' -or (Get-FileHash $recoveryLedger).Hash -cne $before) {
        throw 'Changed receipt identity released an allocation.'
    }
    [IO.File]::WriteAllText($handoffPath, $receiptBytes)
    $running = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $staleRunningVmrunPath -StateRoot $recoveryState -Execute
    if ($running.Status -ne 'blocked' -or (Get-FileHash $recoveryLedger).Hash -cne $before) {
        throw 'Termination proof bypassed running-VM protection.'
    }
    $badReceipt = $receiptBytes | ConvertFrom-Json
    $badReceipt.TerminationProof.ReservationSha256 = '0' * 64
    [IO.File]::WriteAllText($handoffPath, ($badReceipt | ConvertTo-Json -Depth 8))
    $mismatch = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $vmrunPath -StateRoot $recoveryState -Execute
    if ($mismatch.Status -ne 'blocked' -or $mismatch.Reason -notlike '*receipt does not match*') {
        throw 'A mismatched receipt was accepted.'
    }
    $activeController = $receiptBytes | ConvertFrom-Json
    $activeController.TerminationProof.ControllerPid = $PID
    $activeController.TerminationProof.ControllerStartTimeUtcTicks = (Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks
    [IO.File]::WriteAllText($handoffPath, ($activeController | ConvertTo-Json -Depth 8))
    $controller = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $vmrunPath -StateRoot $recoveryState -Execute
    if ($controller.Status -ne 'blocked' -or $controller.Reason -notlike '*controller is still active*') {
        throw 'Recovery bypassed an active controller.'
    }
    [IO.File]::WriteAllText($handoffPath, $receiptBytes)

    # Exercise successful bounded completion using the production receipt block.
    # The following release fails on a reachable observation, then a later caller
    # must reach the address check instead of losing the process proof.
    [IO.File]::WriteAllText($failedChild, ([IO.File]::ReadAllText($failedChild).Replace('exit 1', 'exit 0')))
    [IO.File]::WriteAllText($publisher, @'
param($ModulePath, $HandoffPath, $ChildPath, $LedgerPath)
Import-Module $ModulePath -Force
. (Join-Path (Split-Path -Parent $ModulePath) 'Atlaso.WorkstationFirstBoot.ps1')
$processOwnershipPayload = @{}
Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoProfile', '-File', $ChildPath, $HandoffPath, $LedgerPath) `
    -TimeoutSeconds 20 -Action 'Successful inert builder fixture' `
    -ProcessJobName ('Local\Atlaso-Receipt-Test-' + [guid]::NewGuid().ToString('N')) `
    -ProcessOwnershipPublisher {
        param($Job)
        $processOwnershipPayload.ChildProcessId = $Job.RootProcess.Id
        $processOwnershipPayload.ChildProcessStartFileTimeUtc = $Job.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    }
$childBuilderAddressReservationPath = $HandoffPath
$wrapperPath = Join-Path (Split-Path -Parent $ModulePath) 'build-photon-image.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($wrapperPath, [ref]$null, [ref]$null)
$receiptBlock = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
    $node.Clauses[0].Item1.Extent.Text -ceq '$isolatedBuildSucceeded' -and
    $node.Clauses[0].Item2.Extent.Text.Contains('Save-AtlasoBuilderTerminationProof')
}, $true))
if ($receiptBlock.Count -ne 1) { throw 'Missing unique successful-completion receipt block.' }
$body = $receiptBlock[0].Clauses[0].Item2.Extent.Text
& ([scriptblock]::Create($body.Substring(1, $body.Length - 2)))
$module = Get-Module Atlaso.WorkstationBuilderAddress
& $module {
    param($HandoffPath, $LedgerPath)
    function Get-NetNeighbor {
        [pscustomobject]@{ IPAddress = '192.0.2.30'; State = 'Stale'; LinkLayerAddress = '00-0C-29-D3-54-B3' }
    }
    # The normal parent completion path must accept stale-only evidence while
    # still running in its original controller. VerifyOnly preserves this fixture
    # for the failure-and-recovery checks that follow.
    Exit-AtlasoVmwareBuilderAddressReservation -Reservation (Get-Content $HandoffPath -Raw | ConvertFrom-Json) `
        -VmrunPath (Join-Path (Split-Path -Parent (Split-Path -Parent $LedgerPath)) 'fake-vmrun.ps1') `
        -StateRoot (Split-Path -Parent $LedgerPath) -ProcessTreeTerminationProven -VerifyOnly
    function Get-NetNeighbor {
        [pscustomobject]@{ IPAddress = '192.0.2.30'; State = 'Reachable'; LinkLayerAddress = '00-0C-29-D3-54-B3' }
    }
    try {
        Exit-AtlasoVmwareBuilderAddressReservation -Reservation (Get-Content $HandoffPath -Raw | ConvertFrom-Json) `
            -VmrunPath (Join-Path (Split-Path -Parent (Split-Path -Parent $LedgerPath)) 'fake-vmrun.ps1') `
            -StateRoot (Split-Path -Parent $LedgerPath) -ProcessTreeTerminationProven
        throw 'Reachable-address release unexpectedly succeeded.'
    } catch {
        if ($_.Exception.Message -notlike '*non-stale Windows*') { throw }
    }
} $HandoffPath $LedgerPath
'@)
    & (Get-Process -Id $PID).Path -NoProfile -File $publisher $modulePath $handoffPath $failedChild $recoveryLedger
    if ($LASTEXITCODE -ne 0) { throw 'Successful build did not retain proof before failed release.' }
    $receiptBytes = [IO.File]::ReadAllText($handoffPath)
    $before = (Get-FileHash $recoveryLedger).Hash
    $module = Get-Module Atlaso.WorkstationBuilderAddress
    & $module {
        param($HandoffPath, $VmrunPath, $StateRoot, $Before, $ReceiptBytes)
        foreach ($state in @('Reachable', 'Permanent', 'Delay', 'Probe', 'Unknown')) {
            function Get-NetNeighbor {
                <#
                .SYNOPSIS
                Supply one controlled Windows neighbor observation.
                #>
                [pscustomobject]@{ IPAddress = '192.0.2.30'; State = $state; LinkLayerAddress = '00-0C-29-D3-54-B3' }
            }
            if (-not (Test-AtlasoVmwareAddressObservedInUse -Address '192.0.2.30' -VmrunPath $VmrunPath)) {
                throw 'Allocation safety ignored cached address evidence.'
            }
            $result = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $HandoffPath -VmrunPath $VmrunPath -StateRoot $StateRoot -Execute
            if ($result.Status -ne 'blocked' -or $result.Reason -notlike '*non-stale Windows*' -or
                (Get-FileHash (Join-Path $StateRoot 'reservations.json')).Hash -cne $Before -or
                [IO.File]::ReadAllText($HandoffPath) -cne $ReceiptBytes) {
                throw "Recovery did not preserve and classify $state evidence: $($result.Reason)"
            }
        }
        function Get-NetNeighbor {
            <#
            .SYNOPSIS
            Inject an unavailable Windows neighbor provider.
            #>
            throw 'Injected neighbor read failure.'
        }
        $result = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $HandoffPath -VmrunPath $VmrunPath -StateRoot $StateRoot
        if ($result.Status -ne 'blocked' -or $result.Reason -notlike '*inactivity is unknown*') {
            throw 'Unavailable neighbor evidence was treated as inactivity.'
        }
        function Get-NetNeighbor {
            <#
            .SYNOPSIS
            Supply stale and reachable entries on different interfaces for the same IP.
            #>
            [pscustomobject]@{ IPAddress = '192.0.2.30'; State = 'Stale'; LinkLayerAddress = '00-0C-29-D3-54-B3' }
            [pscustomobject]@{ IPAddress = '192.0.2.30'; State = 'Reachable'; LinkLayerAddress = '00-0C-29-11-22-33' }
        }
        $mixed = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $HandoffPath -VmrunPath $VmrunPath -StateRoot $StateRoot
        if ($mixed.Status -ne 'blocked' -or $mixed.Reason -notlike '*non-stale Windows*') {
            throw 'A stale observation hid concurrent live address evidence.'
        }
        function Get-NetIPAddress {
            <#
            .SYNOPSIS
            Supply a current host assignment for the reserved address.
            #>
            [pscustomobject]@{ IPAddress = '192.0.2.30' }
        }
        $hostUse = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $HandoffPath -VmrunPath $VmrunPath -StateRoot $StateRoot
        if ($hostUse.Status -ne 'blocked' -or $hostUse.Reason -notlike '*assigned to a Windows host interface*') {
            throw 'A host interface assignment did not block release.'
        }
        function Get-NetIPAddress {
            <#
            .SYNOPSIS
            Inject an unavailable Windows interface provider.
            #>
            throw 'Injected interface read failure.'
        }
        $unknownHost = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $HandoffPath -VmrunPath $VmrunPath -StateRoot $StateRoot
        if ($unknownHost.Status -ne 'blocked' -or $unknownHost.Reason -notlike '*inactivity is unknown*') {
            throw 'Unavailable host address evidence allowed release.'
        }
    } $handoffPath $vmrunPath $recoveryState $before $receiptBytes
    $foreignVmrun = Join-Path $testRoot 'foreign-vmrun.ps1'
    [IO.File]::WriteAllText($foreignVmrun, @'
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
if ($Arguments[-1] -ceq 'list') { 'Total running VMs: 1'; 'C:\foreign\guest.vmx'; exit 0 }
'192.0.2.30'
exit 0
'@)
    $foreign = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $foreignVmrun -StateRoot $recoveryState
    if ($foreign.Status -ne 'blocked' -or $foreign.Reason -notlike '*reported by a running VMware VM*') {
        throw 'Current foreign VMware address use was not identified.'
    }
    $foreignSource = [IO.File]::ReadAllText($foreignVmrun)
    [IO.File]::WriteAllText($foreignVmrun, $foreignSource.Replace("'192.0.2.30'", 'exit 1'))
    $unknown = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $foreignVmrun -StateRoot $recoveryState
    if ($unknown.Status -ne 'blocked' -or $unknown.Reason -notlike '*inactivity is unknown*') {
        throw 'Guest provider failure allowed release or lost its classification.'
    }
    [IO.File]::WriteAllText($foreignVmrun, $foreignSource.Replace("'192.0.2.30'", "'Not an address'"))
    $malformed = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $foreignVmrun -StateRoot $recoveryState
    if ($malformed.Status -ne 'blocked' -or $malformed.Reason -notlike '*inactivity is unknown*') {
        throw 'Malformed guest provider output allowed release.'
    }
    $released = & $module {
        param($HandoffPath, $VmrunPath, $StateRoot, $Before, $ReceiptBytes, $Common, $TestRoot)
        function Get-NetNeighbor {
            <#
            .SYNOPSIS
            Retain a stale observation without making any MAC ownership assumption.
            #>
            [pscustomobject]@{ IPAddress = '192.0.2.30'; State = 'Stale'; LinkLayerAddress = '00-0C-29-D3-54-B3' }
        }
        $verification = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $HandoffPath -VmrunPath $VmrunPath -StateRoot $StateRoot
        if ($verification.Status -ne 'releasable' -or
            (Get-FileHash (Join-Path $StateRoot 'reservations.json')).Hash -cne $Before -or
            [IO.File]::ReadAllText($HandoffPath) -cne $ReceiptBytes) {
            throw 'Stale-only verification failed or changed durable evidence.'
        }
        $result = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $HandoffPath -VmrunPath $VmrunPath -StateRoot $StateRoot -Execute
        if ($result.Status -ne 'released') { throw "Stale-only release failed: $($result.Reason)" }
        # The ledger lock is now available to a different build. Address .30 must
        # still be excluded; .31 belongs to the unrelated allocation fixture.
        $next = $Common.Clone()
        $next.StateRoot = $StateRoot
        $next.PoolEndOffset = 32
        $allocation = Enter-AtlasoVmwareBuilderAddressReservation @next -OutputDirectory (Join-Path $TestRoot 'next-output')
        if ($allocation.Address -cne '192.0.2.32') { throw 'Allocation reused the stale address after release.' }
        try {
            $null = Enter-AtlasoVmwareBuilderAddressReservation @next -OutputDirectory (Join-Path $TestRoot 'explicit-output') -PreferredAddress '192.0.2.30'
            throw 'Explicit allocation reused the stale address after release.'
        }
        catch {
            if ($_.Exception.Message -eq 'Explicit allocation reused the stale address after release.') { throw }
        }
        Exit-AtlasoVmwareBuilderAddressReservation -Reservation $allocation -VmrunPath $VmrunPath -StateRoot $StateRoot
        return $result
    } $handoffPath $vmrunPath $recoveryState $before $receiptBytes $common $testRoot
    $remaining = (Get-Content $recoveryLedger -Raw | ConvertFrom-Json).Reservations
    if ($released.Status -ne 'released' -or (Test-Path $handoffPath) -or @($remaining).Count -ne 1 -or
        ($remaining[0] | ConvertTo-Json -Compress) -cne ($unrelated | ConvertTo-Json -Compress)) {
        throw "Exact same-boot recovery did not preserve unrelated allocations: $($released.Reason)"
    }
    # Simulate interruption after ledger commit but before handoff retirement.
    [IO.File]::WriteAllText($handoffPath, $receiptBytes)
    $retry = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $handoffPath -VmrunPath $vmrunPath -StateRoot $recoveryState -Execute
    if ($retry.Status -ne 'released' -or (Test-Path $handoffPath)) {
        throw 'Interrupted handoff retirement was not idempotent.'
    }

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
            '-ReservationHandoffPath $resolvedBuilderAddressReservationPath'
            '-RepositoryRoot $TaskRepositoryRoot'
            '-SourceCommit $SourceCommit'
            '-SourceBranch $SourceBranch'
            'was not paired with its durable release handoff'
            'SkipNetworkCheck suppresses topology preparation, not allocator safety'
            '$requiresBuilderReservation = -not $ValidateOnly -and -not $PrepareIsoOnly'
            'BuilderStaticIp must not be empty for a VMware Photon image build.'
            'HostAddresses'
            '(@($BuilderStaticGateway) + $managementHostAddresses)'
        )) {
        if (-not $wrapper.Contains($required, [StringComparison]::Ordinal)) {
            throw "The Photon wrapper is missing builder reservation integration marker: $required"
        }
    }
    $builderAddressModule = [System.IO.File]::ReadAllText($modulePath)
    if ($builderAddressModule.Contains(
            'git -C $resolvedRepository rev-parse HEAD',
            [StringComparison]::Ordinal
        )) {
        throw 'Builder reservation admission still requires Git metadata from its recorded root.'
    }
}
finally {
    if (-not $RetainedTestRoot -and (Test-Path -LiteralPath $testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Write-Host 'VMware builder-address reservation checks passed.'
