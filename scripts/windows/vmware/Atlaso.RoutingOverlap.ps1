<#
.SYNOPSIS
Provide private lifecycle topology and guest-operation helpers from an admitted immutable snapshot.
#>

<#
.SYNOPSIS
Observe public guest identities and optionally install the admitted controller.
.PARAMETER Vmx
Original owned VMX path.
.PARAMETER Role
Canonical appliance or client role.
.PARAMETER Phase
Unique observation phase used for retained evidence filenames.
.PARAMETER InstallController
Upload and verify the immutable fixture controller on a client.
#>
function Get-RoutingOverlapGuest {
    param([string]$Vmx, [ValidateSet('appliance', 'client-a', 'client-b')][string]$Role,
        [ValidatePattern('^[a-z-]+$')][string]$Phase, [switch]$InstallController)

    Assert-LifecycleSourcePins -Pins $runtimeConsumerPins
    $guestUser = if ($Role -eq 'appliance') { 'root' } else { $ClientSshUser }
    $guestPassword = if ($Role -eq 'appliance') { $RootGuestPassword } else { $SshPassword }
    $python = if ($Role -eq 'appliance') { '/opt/atlaso/.venv/bin/python' } else { '/usr/bin/python3' }
    $nonce = [guid]::NewGuid().ToString('N')
    $guestScript = "/tmp/atlaso-inventory-$nonce.py"
    $guestOutput = "/tmp/atlaso-inventory-$nonce.json"
    $hostOutput = Join-Path $resultRoot "$Role-$Phase.json"
    if (Test-Path -LiteralPath $hostOutput) { throw 'Guest observation output already exists.' }
    $prefix = @('-T', 'ws', '-gu', $guestUser, '-gp', $guestPassword)
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(3)
    do {
        try {
            $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
                'runScriptInGuest', $Vmx, '/bin/sh', 'true'
            )) -TimeoutSeconds 15 -Action 'Private guest-operation readiness'
            break
        } catch {
            $failure = $_.Exception
            while ($null -ne $failure) {
                if ($failure.Data['AtlasoProcessTreeTerminationUnproven']) {
                    $script:diagnosticTerminationUnproven = $true
                    throw 'Private guest-operation termination is unproven; preserve the fixture.'
                }
                $failure = $failure.InnerException
            }
            if ([DateTimeOffset]::UtcNow -ge $deadline) { throw 'Private guest credentials or Tools readiness were not established.' }
            Start-Sleep -Seconds 3
        }
    } while ($true)
    if ($InstallController) {
        $readinessPath = Join-Path $runtimeSourceRoot 'scripts/interop/routing_fixture_cloud_init_ready.py'
        $guestReadiness = "/tmp/atlaso-cloud-init-ready-$nonce.py"
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
            'copyFileFromHostToGuest', $Vmx, $readinessPath, $guestReadiness
        )) -TimeoutSeconds 30 -Action 'Private fixture provisioning checker upload'
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
            'runScriptInGuest', $Vmx, '/bin/sh', "/usr/bin/python3 -I '$guestReadiness'"
        )) -TimeoutSeconds 300 -Action 'Private fixture client provisioning readiness'
    }
    $inspector = Join-Path $runtimeSourceRoot 'scripts/interop/routing_guest_inventory.py'
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
        'copyFileFromHostToGuest', $Vmx, $inspector, $guestScript
    )) -TimeoutSeconds 30 -Action 'Private guest public inventory upload'
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
        'runScriptInGuest', $Vmx, '/bin/sh', "$python -I '$guestScript' --output '$guestOutput'"
    )) -TimeoutSeconds 30 -Action 'Private guest public inventory observation'
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
        'copyFileFromGuestToHost', $Vmx, $guestOutput, $hostOutput
    )) -TimeoutSeconds 30 -Action 'Private guest public inventory readback'
    $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($hostOutput, $true))
    if ((Get-Item -LiteralPath $hostOutput).Length -gt 262144) { throw 'Guest public inventory exceeds its bound.' }
    $observation = Get-Content -LiteralPath $hostOutput -Raw | ConvertFrom-Json
    if ($observation.schema -ne 1 -or -not $observation.links -or -not $observation.ssh_public_key) {
        throw 'Guest public inventory has an invalid envelope.'
    }
    $controllerPath = ''
    if ($InstallController) {
        if ($Role -eq 'appliance') { throw 'The fixture controller belongs only on client VMs.' }
        $controller = Join-Path $runtimeSourceRoot 'scripts/interop/routing_overlap_guest.py'
        $controllerPath = "/tmp/atlaso-overlap-$nonce.py"
        $digest = (Get-FileHash -LiteralPath $controller -Algorithm SHA256).Hash.ToLowerInvariant()
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
            'copyFileFromHostToGuest', $Vmx, $controller, $controllerPath
        )) -TimeoutSeconds 30 -Action 'Private fixture controller upload'
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
            'runScriptInGuest', $Vmx, '/bin/sh',
            "printf '%s  %s\n' '$digest' '$controllerPath' | sha256sum -c - && sudo -n chown root:root '$controllerPath' && sudo -n chmod 0500 '$controllerPath'"
        )) -TimeoutSeconds 30 -Action 'Private fixture controller immutable-byte verification'
    }
    return [pscustomobject]@{ Inventory = $observation; Path = $hostOutput; Controller = $controllerPath }
}

<#
.SYNOPSIS
Wait for first-boot HTTPS to publish a CA before pinning private fixture trust.
.PARAMETER Vmx
Original owned appliance VMX path.
#>
function Wait-RoutingOverlapTrust {
    param([string]$Vmx)

    Assert-LifecycleSourcePins -Pins $runtimeConsumerPins
    $prefix = @('-T', 'ws', '-gu', 'root', '-gp', $RootGuestPassword)
    $guestScript = "/tmp/atlaso-firstboot-retry-$([guid]::NewGuid().ToString('N')).py"
    $retrySource = Join-Path $runtimeSourceRoot 'scripts/interop/routing_appliance_firstboot_retry.py'
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
        'copyFileFromHostToGuest', $Vmx, $retrySource, $guestScript
    )) -TimeoutSeconds 30 -Action 'Private first-boot review helper upload'
    $retrySubmitted = $false
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(5)
    do {
        try {
            $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
                'runScriptInGuest', $Vmx, '/bin/sh', 'test -s /etc/atlaso/ca/root.crt'
            )) -TimeoutSeconds 15 -Action 'Private appliance CA readiness'
            break
        } catch {
            $failure = $_.Exception
            while ($null -ne $failure) {
                if ($failure.Data['AtlasoProcessTreeTerminationUnproven']) {
                    $script:diagnosticTerminationUnproven = $true
                    throw 'Private appliance CA readiness termination is unproven; preserve the fixture.'
                }
                $failure = $failure.InnerException
            }
            if (-not $retrySubmitted) {
                try {
                    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList ($prefix + @(
                        'runScriptInGuest', $Vmx, '/bin/sh',
                        "set -a; . /etc/atlaso/atlaso.env; set +a; /opt/atlaso/.venv/bin/python -I '$guestScript'"
                    )) -TimeoutSeconds 20 -Action 'Private first-boot DHCP review retry'
                    $retrySubmitted = $true
                } catch {
                    $retryFailure = $_.Exception
                    while ($null -ne $retryFailure) {
                        if ($retryFailure.Data['AtlasoProcessTreeTerminationUnproven']) {
                            $script:diagnosticTerminationUnproven = $true
                            throw 'Private first-boot retry termination is unproven; preserve the fixture.'
                        }
                        $retryFailure = $retryFailure.InnerException
                    }
                }
            }
            if ([DateTimeOffset]::UtcNow -ge $deadline) {
                throw 'Private appliance CA was not published by first-boot HTTPS; preserve the fixture.'
            }
            Start-Sleep -Seconds 3
        }
    } while ($true)
    $trust = Get-RoutingOverlapGuest -Vmx $Vmx -Role appliance -Phase trust
    if ($trust.Inventory.ca_pem -isnot [string] -or -not $trust.Inventory.ca_pem.Trim()) {
        throw 'Private appliance CA observation is absent; preserve the fixture.'
    }
    return $trust.Path
}

<#
.SYNOPSIS
Read actual enabled provider NIC mappings without inferring them from the plan.
.PARAMETER Vmx
Exact owned VMX path whose current adapter mapping is observed.
.PARAMETER Role
Canonical lifecycle role.
#>
function Get-RoutingOverlapProviderNics {
    param([string]$Vmx, [string]$Role)

    $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Vmx, $true)
    try {
        $values = @{}
        foreach ($line in Get-Content -LiteralPath $Vmx) {
            if ($line -match '^\s*(ethernet\d+\.[A-Za-z]+)\s*=\s*"([^"]*)"\s*$') {
                if ($values.ContainsKey($Matches[1])) { throw 'Duplicate VMX adapter property prevents admission.' }
                $values[$Matches[1]] = $Matches[2]
            }
        }
        $rows = @()
        foreach ($key in @($values.Keys)) {
            if ($key -match '^ethernet(\d+)\.present$' -and $values[$key] -ieq 'TRUE') {
                $index = [int]$Matches[1]
                $prefix = "ethernet$index"
                $kind = $values["$prefix.connectionType"]
                $network = if ($kind -ceq 'pvn') { $values["$prefix.pvnID"] } else { $values["$prefix.vnet"] }
                if ($values["$prefix.addressType"] -cne 'static' -or -not $values["$prefix.address"] -or
                    $values["$prefix.startConnected"] -ine 'TRUE') { throw 'Private adapter lacks static connected identity.' }
                $rows += @{ role = $Role; adapter = $index; mac = $values["$prefix.address"].ToLowerInvariant()
                    network_type = $kind; network_id = $network }
            }
        }
        return $rows
    } finally { $pin.Dispose() }
}

<#
.SYNOPSIS
Publish original LAN receipts, provider mappings, and actual guest identities.
.PARAMETER Guests
Three role-keyed public guest observations.
.PARAMETER VmxPaths
Three role-keyed original VMX paths.
.PARAMETER ControlNetwork
Existing client-only management VMnet selected by the maintainer.
#>
function New-RoutingOverlapDescriptor {
    param([hashtable]$Guests, [hashtable]$VmxPaths, [string]$ControlNetwork)

    if (-not $externalOwnershipEnabled) { throw 'Private lifecycle requires original external resource ownership.' }
    $segments = @{}
    $receipts = @{}
    foreach ($entry in @(@{ Purpose = 'management'; Name = "$LabName-OverlapManagement" },
            @{ Purpose = 'lab'; Name = "$LabName-OverlapLab" })) {
        $match = @($ownedLanSegments | Where-Object {
            $_.ReceiptPath -and (Get-Content -LiteralPath $_.ReceiptPath -Raw | ConvertFrom-Json).name -ceq $entry.Name
        })
        if ($match.Count -ne 1 -or -not $match[0].ReceiptPath -or -not $match[0].ReceiptSha256) {
            throw 'Private topology requires original task-created LAN receipts.'
        }
        $segment = $match[0]
        $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($segment.ReceiptPath, $true))
        $raw = [IO.File]::ReadAllBytes($segment.ReceiptPath)
        $segments[$entry.Purpose] = @{ name = $entry.Name; id = $segment.Id; receipt_sha256 = $segment.ReceiptSha256.ToLowerInvariant() }
        $receipts[$entry.Purpose] = [Convert]::ToBase64String($raw)
    }
    $provider = @()
    $links = @()
    $peers = @{}
    $controlPrefixes = @()
    foreach ($role in @('appliance', 'client-a', 'client-b')) {
        $native = @(Get-RoutingOverlapProviderNics -Vmx $VmxPaths[$role] -Role $role)
        $provider += $native
        $guest = $Guests[$role]
        foreach ($link in $guest.Inventory.links) {
            $links += @{ role = $role; interface = $link.interface; mac = $link.mac; addresses = @($link.addresses) }
        }
        if ($role -ne 'appliance') {
            $control = @($native | Where-Object { $_.adapter -eq 0 })
            if ($control.Count -ne 1) { throw 'Client provider control adapter is ambiguous.' }
            $observed = @($guest.Inventory.links | Where-Object { $_.mac -ceq $control[0].mac })
            if ($observed.Count -ne 1) { throw 'Client guest control adapter is ambiguous.' }
            $ipv4 = @($observed[0].addresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+/\d+$' -and $_ -notmatch '^(127|169\.254)\.' })
            if ($ipv4.Count -ne 1) { throw 'Client control IPv4 ownership is ambiguous.' }
            $controlPrefixes += @($observed[0].addresses)
            $peers[$role] = @{ host = $ipv4[0].Split('/')[0]; ssh_public_key = $guest.Inventory.ssh_public_key
                controller = $guest.Controller }
        }
    }
    $descriptor = @{ schema = 1; segments = $segments; receipt_bytes = $receipts; provider_nics = $provider
        guest_links = $links; peers = $peers; control_network = $ControlNetwork; control_prefixes = $controlPrefixes
        appliance_ssh_public_key = $Guests.appliance.Inventory.ssh_public_key }
    $path = Join-Path $resultRoot 'routing-overlap-topology.json'
    if (Test-Path -LiteralPath $path) { throw 'Private topology evidence already exists.' }
    [IO.File]::WriteAllText($path, ($descriptor | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true))
    return [pscustomobject]@{ Path = $path; Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}

<#
.SYNOPSIS
Run one private-fixture phase with pinned public bindings and stdin credentials.
.PARAMETER Phase
Explicit bootstrap, scenario or restoration phase.
.PARAMETER Descriptor
Pinned descriptor path and SHA256 returned by the canonical publisher.
.PARAMETER Trust
Optional pinned public guest CA observation required by HTTPS phases.
#>
function Invoke-RoutingOverlapPhase {
    param([ValidateSet('bootstrap', 'probe', 'scenario', 'stop')][string]$Phase, [object]$Descriptor, [string]$Trust = '')

    $arguments = @('-B', (Join-Path $runtimeSourceRoot 'scripts/interop/routing_overlap_runner.py'),
        '--action', $Phase, '--descriptor', $Descriptor.Path, '--descriptor-sha256', $Descriptor.Sha256,
        '--output', (Join-Path $resultRoot "routing-overlap-$Phase.json"), '--task-id', $lifecycleTaskId,
        '--source-commit', $sourceCommit, '--pr', "$PullRequestNumber", '--lab-root', $resultRoot,
        '--client-user', $ClientSshUser, '--admin-user', $AdminUsername)
    if ($Trust) { $arguments += @('--trust', $Trust) }
    $exitCode = Invoke-LifecyclePython -Arguments $arguments -SourcePins $runtimeConsumerPins `
        -AdminPassword $adminPasswordSecure -SshPassword $sshPasswordSecure -RootPassword $rootPasswordSecure
    if ($exitCode -eq 3) { $script:overlapRecoveryUncertain = $true }
    if ($exitCode -ne 0) { throw "Private lifecycle phase '$Phase' failed; retain its original ownership evidence." }
}
