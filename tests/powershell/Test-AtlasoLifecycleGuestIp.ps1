<#
.SYNOPSIS
Exercise lifecycle guest-address selection without VMware or network access.
.PARAMETER RepositoryRoot
Checkout containing the lifecycle runner.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'
$runner = Join-Path $RepositoryRoot 'scripts/windows/vmware/run-lifecycle-test.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($runner, [ref]$null, [ref]$null)
$wait = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Wait-GuestIPv4'
}, $true))
if ($wait.Count -ne 1) { throw 'Expected exactly one lifecycle guest-address waiter.' }
. ([scriptblock]::Create($wait[0].Extent.Text))

$script:reportedAddresses = [Collections.Generic.Queue[string]]::new()
$script:guestOpsAddresses = [Collections.Generic.Queue[string]]::new()
$script:neighborCalls = 0

<#
.SYNOPSIS
Return fixture VMware Tools observations in sequence.
.PARAMETER Arguments
Ignored VMware command arguments.
.PARAMETER TimeoutSeconds
Ignored bounded timeout.
#>
function Invoke-VmrunBounded {
    param($Arguments, $TimeoutSeconds)
    if ($script:reportedAddresses.Count -eq 0) { throw 'Unexpected VMware Tools poll.' }
    return @{ ExitCode = 0; StdOut = $script:reportedAddresses.Dequeue() }
}

<#
.SYNOPSIS
Return the fixture IPv4 text supplied by VMware Tools.
.PARAMETER Lines
Reported output lines.
#>
function Get-GuestIPv4FromAddressText {
    param($Lines)
    return [string]$Lines[0]
}

<#
.SYNOPSIS
Record an attempted host-neighbor lookup.
.PARAMETER Path
Ignored VMX path.
#>
function Get-GuestIPv4FromHostNeighbor {
    param($Path)
    $script:neighborCalls++
    return '192.0.2.172'
}

<#
.SYNOPSIS
Return fixture guest-operation observations in sequence.
.PARAMETER Path
Ignored VMX path.
.PARAMETER GuestUser
Ignored user.
.PARAMETER GuestPassword
Ignored password.
.PARAMETER Name
Ignored VM name.
#>
function Get-GuestIPv4ViaGuestOps {
    param($Path, $GuestUser, [SecureString]$GuestPassword, $Name)
    if ($script:guestOpsAddresses.Count -eq 0) { throw 'Unexpected guest-ops poll.' }
    return $script:guestOpsAddresses.Dequeue()
}

$script:reportedAddresses.Enqueue('192.0.2.172')
$script:reportedAddresses.Enqueue('192.0.2.172')
$script:guestOpsAddresses.Enqueue('192.0.2.172')
$script:guestOpsAddresses.Enqueue('198.51.100.23')
$address = Wait-GuestIPv4 -Path 'fixture.vmx' -TimeoutSeconds 30 -ExpectedAddress '198.51.100.23' -SkipHostNeighbor
if ($address -cne '198.51.100.23' -or $script:neighborCalls -ne 0 -or
    $script:reportedAddresses.Count -ne 0 -or $script:guestOpsAddresses.Count -ne 0) {
    throw 'Private handoff accepted a stale address or consulted the host neighbor cache.'
}

$script:reportedAddresses.Enqueue('192.0.2.172')
$address = Wait-GuestIPv4 -Path 'fixture.vmx' -TimeoutSeconds 30
if ($address -cne '192.0.2.172') { throw 'Ordinary guest-address lookup changed.' }

Write-Host 'Lifecycle guest IPv4 fixture passed.'
