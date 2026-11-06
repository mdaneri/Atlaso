<#
.SYNOPSIS
Source-pinned private NTP acceptance fixture helpers for run-lifecycle-test.ps1.
.DESCRIPTION
This separate mode retains the lifecycle's original VM/LAN ownership and cleanup.
It never relaxes CertificateDhcpPeer's PR 871 guard or adopts ISO/certificate labs.
#>

if (-not $NtpColdStartOnly) { throw 'NTP fixture helpers require their explicit lifecycle mode.' }
if ($CertificatePeerCidr -cne '192.168.77.1/24' -or $CertificateLeaseAddress -cne '192.168.77.10') {
    throw 'NTP cold-start acceptance currently admits only its documented private IPv4 /24 fixture.'
}
$ntpBaselineAddress = '192.168.77.30'
$ntpCandidateAddress = '192.168.77.40'
$ntpNegativeAddress = '192.168.77.11'
$ntpConsoleReceipts = @{}

<#
.SYNOPSIS
Admit the peer disk from its original, external creation and prepared receipts.
#>
function Assert-NtpPeerSourceOwnership {
    $references = @(
        @{ Path = $NtpPeerSourceReceiptPath; Sha = $NtpPeerSourceReceiptSha256 },
        @{ Path = $NtpPeerPreparedReceiptPath; Sha = $NtpPeerPreparedReceiptSha256 }
    )
    foreach ($reference in $references) {
        # Keep source leaves read-only and every ancestor pinned against replacement,
        # while sibling roots can still publish original ownership receipts.
        $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $reference.Path), $false, $true))
        $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($reference.Path, $true))
        if ((Get-FileHash -LiteralPath $reference.Path -Algorithm SHA256).Hash -ine $reference.Sha) {
            throw 'NTP peer original source receipt digest mismatch.'
        }
        $resolvedReceipt = [IO.Path]::GetFullPath($reference.Path)
        $configuredPrefix = [IO.Path]::GetFullPath($durableOwnershipRoot).TrimEnd('\') + '\'
        # The lifecycle has already independently admitted its durable ownership root.
        # Receipts must remain outside the removable lab and source directories.
        if ($resolvedReceipt.StartsWith(([string]$repoRoot).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not $resolvedReceipt.StartsWith($configuredPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'NTP source provenance must be durable beneath the admitted root and outside the lab.'
        }
    }
    $original = Get-Content -LiteralPath $NtpPeerSourceReceiptPath -Raw | ConvertFrom-Json
    $prepared = Get-Content -LiteralPath $NtpPeerPreparedReceiptPath -Raw | ConvertFrom-Json
    if ($original.schema -ne 1 -or $prepared.schema -ne 1 -or
        $original.task_id -cne $lifecycleTaskId -or $prepared.task_id -cne $lifecycleTaskId -or
        $original.repository -cne 'mdaneri/Atlaso' -or $original.pr -ne $PullRequestNumber -or $prepared.pr -ne $PullRequestNumber -or
        $original.source_commit -cne $prepared.source_commit -or $original.source_commit -notmatch '^[0-9a-f]{40}$' -or
        $prepared.path -cne [IO.Path]::GetFullPath($ClientVmdkPath) -or
        -not $original.path.StartsWith((Join-Path ([string]$repoRoot) 'test-results') + '\', [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Parent $prepared.path) -cne $original.path -or
        $prepared.original_root_receipt -cne (Split-Path -Leaf $NtpPeerSourceReceiptPath) -or
        $prepared.prepared_before_use -ne $true -or @($prepared.consumer_vms).Count -ne 0 -or
        $prepared.format -cne 'monolithicSparse' -or $prepared.parent_cid -ne 4294967295 -or
        $prepared.virtual_size_bytes -ne 2GB -or $prepared.sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'NTP peer source ownership or original preparation binding is invalid.'
    }
    & git -C $repoRoot merge-base --is-ancestor $original.source_commit $sourceCommit
    if ($LASTEXITCODE -ne 0) { throw 'NTP peer creation source is not an ancestor of the reviewed harness.' }
    $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($original.path, $false, $true))
    $identity = @($original.root_identity)
    if ($identity.Count -ne 3 -or (Get-AtlasoPathIdentity -Path $original.path -Description 'original NTP peer source') -cne
        ('{0:X8}:{1:X8}{2:X8}' -f [uint32]$identity[0], [uint32]$identity[1], [uint32]$identity[2])) {
        throw 'NTP peer source directory original identity changed.'
    }
    $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($ClientVmdkPath, $true))
    if ((Get-FileHash -LiteralPath $ClientVmdkPath -Algorithm SHA256).Hash -ine $prepared.sha256) {
        throw 'NTP peer source disk changed since original preparation.'
    }
}

<#
.SYNOPSIS
Bind a new VM's public-identity serial console before its first boot.
.PARAMETER Vmx
Exact original task-owned VMX.
.PARAMETER Role
Appliance or peer identity.
#>
function Initialize-NtpFixtureConsole {
    param([Parameter(Mandatory)][string]$Vmx, [Parameter(Mandatory)][ValidateSet('appliance', 'peer')][string]$Role)
    if (Test-WorkstationVmRunning -Path $Vmx) { throw 'NTP console admission requires the original VM powered off.' }
    $serial = Join-Path (Split-Path -Parent $Vmx) 'ntp-public-identity.serial'
    if (Test-Path -LiteralPath $serial) { throw 'NTP public console path already exists; preserve original evidence.' }
    $owner = if ($Role -ceq 'appliance') { $certificateOwnership } else { $peerOwnership }
    $intent = Write-CertificateLabReceipt -Name "$Role-console-intent.json" -Value ([ordered]@{
        schema = 1; kind = 'ntp-public-console-intent'; task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'
        pr = $PullRequestNumber; source_commit = $sourceCommit; vmx = $Vmx; vm_ownership_sha256 = $owner.Sha256
        serial_path = $serial; observation = 'original-vmx-bound-public-serial-console'
    })
    foreach ($entry in @(@('serial0.present', 'TRUE'), @('serial0.fileType', 'file'), @('serial0.fileName', $serial),
            @('serial0.startConnected', 'TRUE'), @('serial0.yieldOnMsrRead', 'TRUE'), @('tools.syncTime', 'FALSE'),
            @('time.synchronize.continue', 'FALSE'), @('time.synchronize.restore', 'FALSE'),
            @('time.synchronize.resume.disk', 'FALSE'), @('time.synchronize.shrink', 'FALSE'),
            @('time.synchronize.tools.startup', 'FALSE'), @('time.synchronize.tools.enable', 'FALSE'),
            @('time.synchronize.resume.host', 'FALSE'))) {
        Set-VmxValue -Path $Vmx -Key $entry[0] -Value $entry[1]
    }
    $ntpConsoleReceipts[$Role] = @{ Intent = $intent; Vmx = $Vmx; Path = $serial; Ownership = $owner }
}

<#
.SYNOPSIS
Read only a bounded public Ed25519 marker from the exact admitted serial console.
.PARAMETER Role
Appliance or peer original console binding.
#>
function Get-NtpConsolePublicKey {
    param([Parameter(Mandatory)][ValidateSet('appliance', 'peer')][string]$Role)
    $console = $ntpConsoleReceipts[$Role]
    if (-not $console -or -not (Test-WorkstationVmRunning -Path $console.Vmx)) { throw 'NTP original console VM is unavailable.' }
    $deadline = (Get-Date).AddSeconds(300)
    do {
        if (Test-Path -LiteralPath $console.Path -PathType Leaf) {
            $file = Get-Item -LiteralPath $console.Path -Force
            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 8192) {
                throw 'NTP public console is replaced or exceeds its public-only bound.'
            }
            $bytes = [IO.File]::ReadAllText($console.Path)
            $marker = if ($Role -ceq 'appliance') { 'NTP_APPLIANCE' } else { 'CERTIFICATE_PEER' }
            $keyMatches = [regex]::Matches($bytes, "(?m)^ATLASO_$($marker)_ED25519_HOST_KEY_V1 (ssh-ed25519 [A-Za-z0-9+/]+={0,2})\r?`$")
            if ($keyMatches.Count -gt 0) {
                $keys = @($keyMatches | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
                if ($keys.Count -ne 1) { throw 'NTP console reports conflicting public host keys.' }
                return ConvertTo-AtlasoWorkstationSshHostKeyEvidence -PublicKey $keys[0]
            }
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw 'NTP original public-key console observation timed out.'
}

<#
.SYNOPSIS
Establish the peer host key from its serial console before any SSH connection.
#>
function Initialize-NtpPeerConsolePin {
    $key = Get-NtpConsolePublicKey -Role peer
    $stream = [IO.File]::Open($certificatePeerKnownHostsPath, 'CreateNew', 'Write', 'None')
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes("$clientAName $($key.PublicKey)`n")
        $stream.Write($bytes); $stream.Flush($true)
    } finally { $stream.Dispose() }
    $ntpConsoleReceipts['peer']['Observation'] = Write-CertificateLabReceipt -Name 'peer-console-identity.json' -Value ([ordered]@{
        schema = 1; kind = 'ntp-original-console-identity'; task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'
        pr = $PullRequestNumber; source_commit = $sourceCommit; console_intent_sha256 = $ntpConsoleReceipts['peer'].Intent.Sha256
        vmx = $certificatePeerVmx; ssh_host_key = $key.Fingerprint; ssh_public_key = $key.PublicKey
    })
}

<#
.SYNOPSIS
Publish the appliance public host key through its original VMX-bound console.
#>
function Save-NtpApplianceConsoleIdentity {
    $script = "printf 'ATLASO_NTP_APPLIANCE_ED25519_HOST_KEY_V1 ' > /dev/ttyS0; awk '{print `$1, `$2}' /etc/ssh/ssh_host_ed25519_key.pub > /dev/ttyS0"
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList @(
        '-T', 'ws', '-gu', 'root', '-gp', $RootGuestPassword, 'runScriptInGuest', $applianceVmx, '/bin/sh', $script
    ) -TimeoutSeconds 30 -Action 'Publish original NTP appliance public console identity'
    $key = Get-NtpConsolePublicKey -Role appliance
    $receipt = Write-CertificateLabReceipt -Name 'appliance-console-identity.json' -Value ([ordered]@{
        schema = 1; kind = 'ntp-original-console-identity'; task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'
        pr = $PullRequestNumber; source_commit = $sourceCommit; console_intent_sha256 = $ntpConsoleReceipts['appliance'].Intent.Sha256
        vmx = $applianceVmx; ssh_host_key = $key.Fingerprint; ssh_public_key = $key.PublicKey
    })
    $ntpConsoleReceipts['appliance']['Observation'] = $receipt
}

<#
.SYNOPSIS
Capture public CA bytes from the original VM channel, then launch the pinned consumer.
#>
function Invoke-NtpColdStartAcceptance {
    Save-NtpApplianceConsoleIdentity
    $caPath = Join-Path $resultRoot 'ntp-public-root-ca.pem'
    if (Test-Path -LiteralPath $caPath) { throw 'NTP public CA observation already exists.' }
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList @(
        '-T', 'ws', '-gu', 'root', '-gp', $RootGuestPassword, 'copyFileFromGuestToHost', $applianceVmx,
        '/etc/atlaso/ca/root.crt', $caPath
    ) -TimeoutSeconds 30 -Action 'Read original NTP appliance public CA'
    if ((Get-Item -LiteralPath $caPath).Length -gt 16384) { throw 'NTP public CA exceeds its bound.' }
    $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($caPath, $true))
    $peerAddress = ($CertificatePeerCidr -split '/')[0]
    $applianceIdentity = Get-Content -LiteralPath $ntpConsoleReceipts['appliance'].Observation.Path -Raw | ConvertFrom-Json
    $peerIdentity = Get-Content -LiteralPath $ntpConsoleReceipts['peer'].Observation.Path -Raw | ConvertFrom-Json
    if ($peerIdentity.ssh_host_key -cne $peerIdentityReadback.ssh_host_key) { throw 'NTP peer key differs from original console.' }
    $reference = { param($value) @{ path = $value.Path; sha256 = $value.Sha256.ToLowerInvariant() } }
    $hostRoot = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'VMware'
    $nativePlan = [ordered]@{
        schema = 1; kind = 'ntp-cold-start-native-plan'; trust_model = 'trusted-host'
        task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber
        source_commit = $sourceCommit; resource_source_commit = $sourceCommit; worktree = [string]$repoRoot
        appliance_intent = (& $reference $certificateIntent); appliance_ownership = (& $reference $certificateOwnership)
        peer_intent = (& $reference $peerIntent); peer_ownership = (& $reference $peerOwnership)
        peer_fixture = (& $reference $peerFixture); peer_identity = (& $reference $certificatePeerIdentity)
        appliance_console = (& $reference $ntpConsoleReceipts['appliance'].Observation)
        peer_console = (& $reference $ntpConsoleReceipts['peer'].Observation)
        deployed_runtime = (& $reference $certificateRuntime); rewired_runtime = (& $reference $rewiredRuntime)
        source_creation = @{ path = $NtpPeerSourceReceiptPath; sha256 = $NtpPeerSourceReceiptSha256.ToLowerInvariant() }
        source_prepared = @{ path = $NtpPeerPreparedReceiptPath; sha256 = $NtpPeerPreparedReceiptSha256.ToLowerInvariant() }
        current_address = $CertificateLeaseAddress; baseline_address = $ntpBaselineAddress; static_candidate_address = $ntpCandidateAddress
        negative_address = $ntpNegativeAddress; peer_address = $peerAddress; private_subnet = '192.168.77.0/24'
        username = $AdminUsername; appliance_user = $ApplianceSshUser; appliance_ssh_host_key = $applianceIdentity.ssh_host_key
        ca_path = $caPath; ca_sha256 = (Get-FileHash -LiteralPath $caPath -Algorithm SHA256).Hash.ToLowerInvariant()
        helper_sha256 = $installedHelperSha256; wheel_sha256 = $applianceWheel.Sha256.ToLowerInvariant()
        wheel_name = $applianceWheel.Name
        deployment_measurement = @{ path = (Join-Path $resultRoot 'deployed-runtime-identity.json')
            sha256 = (Get-FileHash -LiteralPath (Join-Path $resultRoot 'deployed-runtime-identity.json') -Algorithm SHA256).Hash.ToLowerInvariant() }
        peer_transport = @{ host = $peerIdentityReadback.management_address; user = $ClientSshUser; ssh_public_key = $certificatePeerPublicKey
            ssh_host_key = $peerIdentity.ssh_host_key; private_subnet = '192.168.77.0/24' }
        trusted_host = @{ host_administrator_trusted = $true; vmrun_path = $resolvedVmrun
            inventory_path = (Join-Path $hostRoot 'inventory.vmls'); preferences_path = (Join-Path $hostRoot 'preferences.ini')
            segment_name = $SiteANetwork.Substring(4); segment_id = $ownedLanSegments[0].Id
            segment_receipt = @{ path = $ownedLanSegments[0].ReceiptPath; sha256 = $ownedLanSegments[0].ReceiptSha256.ToLowerInvariant() }
            appliance_vmx = $applianceVmx; peer_vmx = $certificatePeerVmx
            appliance_management_mac = $certificateAppliancePeerMac
            appliance_service_mac = (Get-VmxEthernetMacAddress -Path $applianceVmx -Index 1).Replace('-', ':')
            peer_private_mac = (Get-VmxEthernetMacAddress -Path $certificatePeerVmx -Index 1).Replace('-', ':')
            peer_control_mac = (Get-VmxEthernetMacAddress -Path $certificatePeerVmx -Index 0).Replace('-', ':')
            control_network = $ManagementNetwork
        }
    }
    $planReceipt = Write-CertificateLabReceipt -Name 'ntp-native-plan.json' -Value $nativePlan
    $exitCode = Invoke-LifecyclePython -Arguments @((Join-Path $runtimeSourceRoot 'scripts/interop/ntp_cold_start_native.py'),
        '--plan', $planReceipt.Path, '--output', $resultRoot) -SourcePins $runtimeConsumerPins `
        -AdminPassword $adminPasswordSecure -RootPassword $rootPasswordSecure -SshPassword $sshPasswordSecure
    if ($exitCode -ne 0) { throw 'NTP cold-start native acceptance failed; preserve immutable journals and reconcile before another Apply.' }
}
