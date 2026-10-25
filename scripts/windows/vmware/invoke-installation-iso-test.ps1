<#
.SYNOPSIS
Drive an isolated development installer through a private serial console.
.DESCRIPTION
The bounded child owns the local pipe server and never records raw console bytes.
Only the current Windows user and SYSTEM can connect. Credentials remain inside
the supported 1Password consumer and are sent only to concealed installer fields.
.PARAMETER IsoPath
Verified development installation ISO.
.PARAMETER IsoSha256
Independently retained ISO digest.
.PARAMETER OutputDirectory
Absent task-owned VM output directory.
.PARAMETER PullRequestNumber
Exact owning pull request.
.PARAMETER Scenario
Probe the native UI, cancel at disk/layout review, reject insufficient capacity, run Auto, or install and boot without media.
.PARAMETER TimeoutSeconds
Whole test and console deadline.
.PARAMETER Child
Internal bounded-child selector.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$IsoPath,
    [Parameter(Mandatory = $true)][string]$IsoSha256,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$PullRequestNumber,
    [ValidateSet('Probe', 'Cancel', 'CancelReview', 'Insufficient', 'Auto', 'AutoReboot')][string]$Scenario = 'Probe',
    [ValidateRange(60, 14400)][int]$TimeoutSeconds = 3600,
    [switch]$Child
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
if (-not $Child) {
    Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path -ArgumentList @(
        '-NoProfile', '-File', $PSCommandPath, '-Child', '-IsoPath', $IsoPath,
        '-IsoSha256', $IsoSha256, '-OutputDirectory', $OutputDirectory,
        '-PullRequestNumber', [string]$PullRequestNumber, '-Scenario', $Scenario,
        '-TimeoutSeconds', [string]$TimeoutSeconds
    ) -TimeoutSeconds $TimeoutSeconds -Action 'Private installation serial-console test'
    return
}

<#
.SYNOPSIS
Write public console control bytes without logging the console stream.
.PARAMETER Pipe
Connected private serial pipe.
.PARAMETER Text
Public keystrokes or control characters.
#>
function Send-InstallationConsoleText {
    param([IO.Pipes.NamedPipeServerStream]$Pipe, [string]$Text)
    $bytes = [Text.Encoding]::ASCII.GetBytes($Text)
    try { $Pipe.Write($bytes, 0, $bytes.Length); $Pipe.Flush() }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

<#
.SYNOPSIS
Send a concealed account value only at its expected masked installer field.
.PARAMETER Pipe
Connected private serial pipe.
.PARAMETER Value
Concealed account password from the supported credential bridge.
#>
function Send-InstallationConsoleSecret {
    param([IO.Pipes.NamedPipeServerStream]$Pipe, [Security.SecureString]$Value)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    $bytes = $null
    try {
        $length = [Runtime.InteropServices.Marshal]::ReadInt32($pointer, -4) / 2
        $bytes = [byte[]]::new($length + 1)
        for ($index = 0; $index -lt $length; $index++) {
            $character = [Runtime.InteropServices.Marshal]::ReadInt16($pointer, $index * 2)
            if ($character -lt 32 -or $character -gt 126) { throw 'Installer credential must satisfy the ASCII account policy.' }
            $bytes[$index] = [byte]$character
        }
        $bytes[$length] = 10
        $Pipe.Write($bytes, 0, $bytes.Length)
        $Pipe.Flush()
    }
    finally {
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

<#
.SYNOPSIS
Read only fixed public stage labels from the admitted provisioning source.
.PARAMETER Text
Trusted provisioner source text; interpolated labels are excluded.
#>
function Get-InstallationProvisioningStages {
    param([string]$Text)
    if ($Text.Length -gt 1048576) { throw 'Provisioning source exceeds its bounded stage-label size.' }
    $stages = foreach ($match in [regex]::Matches($Text,
        '(?m)^\s*log_step "(?<stage>[A-Za-z][A-Za-z0-9 ()/.,:-]{1,159})"\r?$')) {
        $match.Groups['stage'].Value
    }
    return @($stages | Sort-Object -Unique)
}

<#
.SYNOPSIS
Decode the bounded initial installation menu from a terminal text stream.
.DESCRIPTION
Replays the supported terminal controls into a fixed 25-row by 80-column frame.
This adapter is limited to the public disk-selection screen before credentials.
.PARAMETER Text
Public terminal text collected before any credential input.
#>
function ConvertFrom-InstallationConsoleFrame {
    param([string]$Text)
    if ($null -eq $Text) { throw 'The public installer frame is unavailable.' }
    if ($Text.Length -gt 131072) { throw 'The public installer frame exceeds its bounded input size.' }

    $rowCount = 25
    $columnCount = 80
    $frame = [char[,]]::new($rowCount, $columnCount)
    for ($rowIndex = 0; $rowIndex -lt $rowCount; $rowIndex++) {
        for ($columnIndex = 0; $columnIndex -lt $columnCount; $columnIndex++) {
            $frame[$rowIndex, $columnIndex] = ' '
        }
    }
    $row = 0
    $column = 0
    $savedRow = 0
    $savedColumn = 0
    $position = 0

    while ($position -lt $Text.Length) {
        $character = $Text[$position]
        $code = [int]$character
        if ($code -eq 27) {
            $position++
            if ($position -ge $Text.Length) { break }
            $escapeKind = $Text[$position]
            if ($escapeKind -eq '[') {
                $position++
                $sequenceStart = $position
                while ($position -lt $Text.Length -and $position - $sequenceStart -le 64) {
                    $candidate = [int]$Text[$position]
                    if ($candidate -ge 0x40 -and $candidate -le 0x7E) { break }
                    $position++
                }
                if ($position -ge $Text.Length) { break }
                if ($position - $sequenceStart -gt 64) {
                    while ($position -lt $Text.Length) {
                        $candidate = [int]$Text[$position]
                        $position++
                        if ($candidate -ge 0x40 -and $candidate -le 0x7E) { break }
                    }
                    continue
                }
                $final = [string]$Text[$position]
                $parameterText = $Text.Substring($sequenceStart, $position - $sequenceStart)
                $position++
                if ($parameterText -notmatch '^[0-9;]*$') { continue }
                $parameters = @()
                if ($parameterText.Length -gt 0) {
                    $parameters = @($parameterText.Split(';') | ForEach-Object {
                        if ($_ -ceq '') { 0 } else { [int]::Parse($_, [Globalization.CultureInfo]::InvariantCulture) }
                    })
                }
                $first = if ($parameters.Count -gt 0) { [int]$parameters[0] } else { 0 }
                $second = if ($parameters.Count -gt 1) { [int]$parameters[1] } else { 0 }
                switch -CaseSensitive ($final) {
                    { $_ -in 'H', 'f' } {
                        $row = [Math]::Clamp($(if ($first -le 0) { 0 } else { $first - 1 }), 0, $rowCount - 1)
                        $column = [Math]::Clamp($(if ($second -le 0) { 0 } else { $second - 1 }), 0, $columnCount - 1)
                    }
                    'A' { $row = [Math]::Max(0, $row - $(if ($first -le 0) { 1 } else { $first })) }
                    'B' { $row = [Math]::Min($rowCount - 1, $row + $(if ($first -le 0) { 1 } else { $first })) }
                    'C' { $column = [Math]::Min($columnCount - 1, $column + $(if ($first -le 0) { 1 } else { $first })) }
                    'D' { $column = [Math]::Max(0, $column - $(if ($first -le 0) { 1 } else { $first })) }
                    'E' {
                        $row = [Math]::Min($rowCount - 1, $row + $(if ($first -le 0) { 1 } else { $first }))
                        $column = 0
                    }
                    'F' {
                        $row = [Math]::Max(0, $row - $(if ($first -le 0) { 1 } else { $first }))
                        $column = 0
                    }
                    'G' { $column = [Math]::Clamp($(if ($first -le 0) { 0 } else { $first - 1 }), 0, $columnCount - 1) }
                    'd' { $row = [Math]::Clamp($(if ($first -le 0) { 0 } else { $first - 1 }), 0, $rowCount - 1) }
                    'J' {
                        $mode = if ($parameters.Count -eq 0) { 0 } else { $first }
                        if ($mode -eq 2 -or $mode -eq 3) {
                            for ($clearRow = 0; $clearRow -lt $rowCount; $clearRow++) {
                                for ($clearColumn = 0; $clearColumn -lt $columnCount; $clearColumn++) { $frame[$clearRow, $clearColumn] = ' ' }
                            }
                        }
                        elseif ($mode -eq 0) {
                            for ($clearColumn = $column; $clearColumn -lt $columnCount; $clearColumn++) { $frame[$row, $clearColumn] = ' ' }
                            for ($clearRow = $row + 1; $clearRow -lt $rowCount; $clearRow++) {
                                for ($clearColumn = 0; $clearColumn -lt $columnCount; $clearColumn++) { $frame[$clearRow, $clearColumn] = ' ' }
                            }
                        }
                        elseif ($mode -eq 1) {
                            for ($clearRow = 0; $clearRow -lt $row; $clearRow++) {
                                for ($clearColumn = 0; $clearColumn -lt $columnCount; $clearColumn++) { $frame[$clearRow, $clearColumn] = ' ' }
                            }
                            for ($clearColumn = 0; $clearColumn -le $column; $clearColumn++) { $frame[$row, $clearColumn] = ' ' }
                        }
                    }
                    'K' {
                        $mode = if ($parameters.Count -eq 0) { 0 } else { $first }
                        if ($mode -eq 2) { $startColumn = 0; $endColumn = $columnCount - 1 }
                        elseif ($mode -eq 1) { $startColumn = 0; $endColumn = $column }
                        else { $startColumn = $column; $endColumn = $columnCount - 1 }
                        for ($clearColumn = $startColumn; $clearColumn -le $endColumn; $clearColumn++) { $frame[$row, $clearColumn] = ' ' }
                    }
                    'X' {
                        $count = if ($first -le 0) { 1 } else { $first }
                        $endColumn = [Math]::Min($columnCount - 1, $column + $count - 1)
                        for ($clearColumn = $column; $clearColumn -le $endColumn; $clearColumn++) { $frame[$row, $clearColumn] = ' ' }
                    }
                    's' { $savedRow = $row; $savedColumn = $column }
                    'u' { $row = $savedRow; $column = $savedColumn }
                    default { } # Includes SGR and terminal mode changes, which do not alter visible cells.
                }
                continue
            }
            if ($escapeKind -in @('(', ')', '*', '+')) {
                $position += [Math]::Min(2, $Text.Length - $position)
                continue
            }
            $position++
            switch -CaseSensitive ($escapeKind) {
                '7' { $savedRow = $row; $savedColumn = $column }
                '8' { $row = $savedRow; $column = $savedColumn }
                'D' { $row = [Math]::Min($rowCount - 1, $row + 1) }
                'E' { $row = [Math]::Min($rowCount - 1, $row + 1); $column = 0 }
                default { }
            }
            continue
        }

        $position++
        switch ($code) {
            8 { $column = [Math]::Max(0, $column - 1); continue }
            9 { $column = [Math]::Min($columnCount - 1, (($column + 8) -band -8)); continue }
            10 { $row = [Math]::Min($rowCount - 1, $row + 1); continue }
            13 { $column = 0; continue }
            default { }
        }
        if ($code -ge 32 -and $code -ne 127) {
            $frame[$row, $column] = $character
            $column = [Math]::Min($columnCount - 1, $column + 1)
        }
    }

    $visibleRows = [Collections.Generic.List[string]]::new()
    for ($rowIndex = 0; $rowIndex -lt $rowCount; $rowIndex++) {
        $builder = [Text.StringBuilder]::new($columnCount)
        for ($columnIndex = 0; $columnIndex -lt $columnCount; $columnIndex++) {
            [void]$builder.Append($frame[$rowIndex, $columnIndex])
        }
        $visibleRows.Add($builder.ToString().TrimEnd())
    }
    return $visibleRows.ToArray()
}

<#
.SYNOPSIS
Parse every public disk row before admitting the fixed two-disk test fixture.
.PARAMETER Text
Public native disk-menu text, before any credential input.
#>
function Get-InstallationConsoleDiskOptions {
    param([string]$Text)
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $index = 0
    $visibleText = (ConvertFrom-InstallationConsoleFrame -Text $Text) -join "`n"
    foreach ($match in [regex]::Matches($visibleText, '(?<size>[0-9]+) GiB @ (?<path>/dev/[a-zA-Z0-9_./-]+)(?=\s|$)')) {
        $diskPath = $match.Groups['path'].Value
        if ($seen.Add($diskPath)) {
            [pscustomobject]@{ Index = $index; SizeGiB = [long]$match.Groups['size'].Value; DiskPath = $diskPath }
            $index++
        }
    }
}

<#
.SYNOPSIS
Wait for a known public installer state while retaining console bytes only in memory.
.PARAMETER Pipe
Connected private serial pipe.
.PARAMETER Pattern
Expected public prompt text.
.PARAMETER Deadline
Absolute test deadline.
.PARAMETER ReadDiskSelection
Return the complete fixed-fixture public disk rows instead of returning at its title.
.PARAMETER KnownProvisioningStages
Fixed public stage labels from the admitted provisioner; unknown messages are never reported.
.PARAMETER ReadBootProgress
Report only fixed boot-stage categories while waiting before installed credential entry.
.PARAMETER ReadLoginProgress
Report only fixed PAM and shell categories; never print login-console contents.
.PARAMETER ExpectedCapacityDisk
Exact public fixture disk whose four-GiB capacity refusal is expected before consent.
#>
function Wait-InstallationConsoleState {
    param([IO.Pipes.NamedPipeServerStream]$Pipe, [string]$Pattern, [DateTimeOffset]$Deadline, [switch]$ReadDiskSelection, [string[]]$KnownProvisioningStages = @(), [switch]$ReadBootProgress, [switch]$ReadLoginProgress, [string]$ExpectedCapacityDisk = '')
    $buffer = [byte[]]::new(4096)
    $text = ''
    $failureDeadline = $null
    $bootFailureDeadline = $null
    $lastProvisioningStage = $null
    $knownStages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenBootStages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenLoginStages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($stage in $KnownProvisioningStages) { [void]$knownStages.Add($stage) }
    try {
        while ([DateTimeOffset]::UtcNow -lt $Deadline) {
            if ($failureDeadline -and [DateTimeOffset]::UtcNow -ge $failureDeadline) {
                throw 'The installer reported a Python failure before the expected console state.'
            }
            if ($bootFailureDeadline -and [DateTimeOffset]::UtcNow -ge $bootFailureDeadline) {
                throw 'The installed system reported a kernel panic before login.'
            }
            $readDeadline = if ($failureDeadline -and $failureDeadline -lt $Deadline) { $failureDeadline } else { $Deadline }
            if ($bootFailureDeadline -and $bootFailureDeadline -lt $readDeadline) { $readDeadline = $bootFailureDeadline }
            $remaining = [int][Math]::Min(30000, ($readDeadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
            if ($remaining -le 0) { break }
            $cancel = [Threading.CancellationTokenSource]::new($remaining)
            try {
                $count = $Pipe.ReadAsync($buffer, 0, $buffer.Length, $cancel.Token).GetAwaiter().GetResult()
            }
            catch [OperationCanceledException] { continue }
            finally { $cancel.Dispose() }
            if ($count -eq 0) { throw 'The owned VM serial console disconnected before the expected state.' }
            $text += [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
            $plain = [regex]::Replace($text, '\x1b\[[0-?]*[ -/]*[@-~]|\x1b[()][A-Z0-9]|\x1b[=>]', '')
            if ($ReadLoginProgress) {
                # Match only fixed diagnostics, including fragmented messages.
                # Console bytes may contain credentials, hostnames or history;
                # none of those bytes become log output or authentication proof.
                foreach ($stage in @(
                    @{ Token = 'Last login:'; Name = 'session-last-login' },
                    @{ Token = 'You are required to change your password'; Name = 'password-change-required' },
                    @{ Token = 'Your password has expired'; Name = 'password-expired' },
                    @{ Token = 'Current password:'; Name = 'current-password-request' },
                    @{ Token = '(current) UNIX password:'; Name = 'current-password-request' },
                    @{ Token = 'New password:'; Name = 'new-password-request' },
                    @{ Token = 'Retype new password:'; Name = 'password-confirmation-request' },
                    @{ Token = 'Authentication failure'; Name = 'authentication-failure' },
                    @{ Token = 'Your account has expired'; Name = 'account-expired' },
                    @{ Token = 'This account is currently not available'; Name = 'shell-unavailable' },
                    @{ Token = 'PowerShell 7.'; Name = 'powershell-startup' },
                    @{ Token = 'PS '; Name = 'powershell-prompt' },
                    @{ Token = ']#'; Name = 'bracketed-root-prompt' }
                )) {
                    if ($plain.Contains($stage.Token, [StringComparison]::Ordinal) -and $seenLoginStages.Add($stage.Name)) {
                        Write-Host ('Public installed login stage: ' + $stage.Name)
                    }
                }
            }
            if ($ReadBootProgress) {
                foreach ($stage in @(
                    @{ Token = 'GNU GRUB'; Name = 'grub-console' },
                    @{ Token = 'Linux version '; Name = 'linux-kernel' },
                    @{ Token = 'Welcome to '; Name = 'systemd-startup' },
                    @{ Token = 'You are in emergency mode'; Name = 'emergency-mode' },
                    @{ Token = 'Kernel panic'; Name = 'kernel-panic' },
                    @{ Token = 'Unable to mount root fs'; Name = 'root-filesystem-unmountable' },
                    @{ Token = 'Cannot open root device'; Name = 'root-device-unavailable' },
                    @{ Token = 'unknown-block(0,0)'; Name = 'root-device-unresolved' },
                    @{ Token = 'No working init found'; Name = 'init-unavailable' },
                    @{ Token = 'Attempted to kill init!'; Name = 'init-failed' },
                    @{ Token = 'grub rescue>'; Name = 'grub-rescue' },
                    @{ Token = 'grub>'; Name = 'grub-command-line' }
                )) {
                    if ($plain.Contains($stage.Token, [StringComparison]::Ordinal) -and $seenBootStages.Add($stage.Name)) {
                        Write-Host ('Public installed boot stage: ' + $stage.Name)
                    }
                }
                if (-not $bootFailureDeadline -and $seenBootStages.Contains('kernel-panic')) {
                    $bootFailureDeadline = [DateTimeOffset]::UtcNow.AddSeconds(2)
                }
            }
            if ($knownStages.Count -gt 0) {
                foreach ($observed in [regex]::Matches($plain, '(?m)^==> Atlaso appliance: (?<stage>[^\r\n]{1,160})\r?$')) {
                    $candidateStage = $observed.Groups['stage'].Value
                    if ($knownStages.Contains($candidateStage)) { $lastProvisioningStage = $candidateStage }
                }
            }
            if ($Pattern -cne 'Installation cancelled' -and $plain.Contains('Installation cancelled', [StringComparison]::Ordinal)) {
                throw 'The installer cancelled before the expected console state.'
            }
            if ($plain.Contains('Password must ', [StringComparison]::Ordinal)) {
                throw 'The installer rejected the concealed credential under its account policy.'
            }
            if ($plain.Contains('Login incorrect', [StringComparison]::Ordinal)) {
                throw 'Installed password authentication failed.'
            }
            if ($plain.Contains('Traceback (most recent call last):', [StringComparison]::Ordinal)) {
                if (-not $failureDeadline) { $failureDeadline = [DateTimeOffset]::UtcNow.AddSeconds(2) }
                # Wait briefly for fragmented frames, then emit only allowlisted
                # public source identifiers. Never emit paths, code or messages.
                $kind = [regex]::Match($plain, '(?m)^(ValueError|RuntimeError|ImportError|ModuleNotFoundError|FileNotFoundError|AttributeError|TypeError|_curses\.error|subprocess\.CalledProcessError):')
                if ($kind.Success) {
                    $frames = @([regex]::Matches($plain, 'File "[^"\r\n]*/(bootstrap\.py|manifest\.py|installer\.py|disks\.py|window\.py|menu\.py|readtext\.py|progressbar\.py)", line ([0-9]{1,6}),') |
                        Select-Object -Last 8 | ForEach-Object { $_.Groups[1].Value + ':' + $_.Groups[2].Value })
                    if ($lastProvisioningStage) { Write-Host ('Public provisioning stage: ' + $lastProvisioningStage) }
                    $packageCodes = @([regex]::Matches($plain, '(?m)^Error\(([0-9]{1,6})\)') |
                        ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
                    if ($packageCodes.Count -gt 0) {
                        Write-Host ('Public package-manager error codes: ' + ($packageCodes -join ', '))
                    }
                    foreach ($category in @(
                        @{ Token = 'No matching packages'; Name = 'package-not-found' },
                        @{ Token = 'nothing provides'; Name = 'dependency-unavailable' },
                        @{ Token = 'GPG signature'; Name = 'package-signature' },
                        @{ Token = 'No such file or directory'; Name = 'local-input-unavailable' },
                        @{ Token = 'Failed to synchronize cache'; Name = 'repository-metadata' }
                    )) {
                        if ($plain.Contains($category.Token, [StringComparison]::OrdinalIgnoreCase)) {
                            Write-Host ('Public package-manager category: ' + $category.Name)
                        }
                    }
                    $capacity = [regex]::Match($plain,
                        'ValueError: default installation requires a disk of at least 64 GiB; selected (?<disk>/dev/[a-zA-Z0-9_.-]{1,64}) has (?<bytes>[0-9]{1,20}) bytes(?:\r?\n|$)')
                    if ($capacity.Success) {
                        Write-Host ('Public capacity refusal: {0}, {1} bytes; requires 68719476736 bytes.' -f
                            $capacity.Groups['disk'].Value, $capacity.Groups['bytes'].Value)
                    }
                    if ($ExpectedCapacityDisk -and $kind.Groups[1].Value -ceq 'ValueError' -and -not $capacity.Success -and
                        [DateTimeOffset]::UtcNow -lt $failureDeadline) {
                        continue
                    }
                    if ($ExpectedCapacityDisk -and $kind.Groups[1].Value -ceq 'ValueError' -and $capacity.Success -and
                        $capacity.Groups['disk'].Value -ceq $ExpectedCapacityDisk -and $capacity.Groups['bytes'].Value -ceq '4294967296') {
                        Write-Host 'The selected four-GiB disk was refused before erasure consent.'
                        return
                    }
                    throw ('The installer reported a Python failure before the expected console state. Public location: {0}; {1}.' -f $kind.Groups[1].Value, ($frames -join ', '))
                }
            }
            if (-not $ExpectedCapacityDisk -and -not $failureDeadline -and $plain.Contains($Pattern, [StringComparison]::Ordinal)) {
                if ($ReadDiskSelection) {
                    $options = @(Get-InstallationConsoleDiskOptions -Text $text)
                    if ($options.Count -lt 2) { continue }
                    if ($options.Count -ne 2 -or @($options | Where-Object SizeGiB -EQ 64).Count -ne 1 -or
                        @($options | Where-Object SizeGiB -EQ 4).Count -ne 1 -or
                        @($options | Where-Object DiskPath -CNotMatch '^/dev/sd[a-z]+$').Count -ne 0) {
                        throw 'Native disk menu does not match the receipt-bound 64 GiB target and 4 GiB unselected fixture.'
                    }
                    return $options
                }
                return
            }
            if ($text.Length -gt 131072) { $text = $text.Substring($text.Length - 65536) }
        }
        if ($bootFailureDeadline) { throw 'The installed system reported a kernel panic before login.' }
        throw 'The installer did not reach the expected public console state before its deadline.'
    }
    finally { [Array]::Clear($buffer, 0, $buffer.Length); $text = ''; $plain = '' }
}

<#
.SYNOPSIS
Select readiness and identity probes for the installer's standard account shells.
.PARAMETER Account
Fixed installed account whose chosen password is being tested.
#>
function Get-InstallationAccountProbe {
    param([ValidateSet('root', 'admin')][string]$Account)
    if ($Account -eq 'root') {
        return [pscustomobject]@{
            # Photon's login and interactive Bash profiles differ in whether
            # they include the hostname. Both end the root prompt with this
            # suffix; the separate id -u challenge still proves the account.
            Prompt = ' ]# '
            Command = '[ "$(id -u)" = 0 ] && printf ''ATLASO-%s\n'' ''LOGIN-OK'''
        }
    }
    # Shared provisioning selects /usr/bin/pwsh for the administrator. Keep
    # marker fragments separate so terminal echo cannot satisfy the checkpoint.
    [pscustomobject]@{
        Prompt = 'PS '
        Command = 'if ((id -un) -ceq ''admin'') { Write-Output (''ATLASO-'' + ''LOGIN-OK'') }'
    }
}

$worktree = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.TestVmOwnership.ps1')
$commit = ([string](& git -C $worktree rev-parse HEAD)).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not admit the installer console source commit.' }
$branch = ([string](& git -C $worktree branch --show-current)).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not admit the installer console source branch.' }
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareTestIdentity.psm1') -Force
$vmName = (New-AtlasoVmwareTestIdentity -PullRequestNumber $PullRequestNumber -Purpose installation-iso).Name
$sourceContext = New-AtlasoTestVmOwnershipContext -Worktree $worktree -OutputDirectory $OutputDirectory `
    -VmxPath (Join-Path $OutputDirectory "$vmName.vmx") -Name $vmName -SourceCommit $commit `
    -SourceBranch $branch -PullRequestNumber $PullRequestNumber
Assert-AtlasoTestVmCheckoutSource -Context $sourceContext
$knownProvisioningStages = @(Get-InstallationProvisioningStages -Text (Get-Content -LiteralPath `
    (Join-Path $worktree 'image/common/scripts/provision-atlaso.sh') -Raw -Encoding utf8))
$credentials = $null
if ($Scenario -in @('Auto', 'AutoReboot')) {
    Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
    $selector = Resolve-AtlasoOnePasswordEnvironmentId -RepositoryRoot $worktree
    $token = Resolve-AtlasoOnePasswordServiceAccountTokenFile -RepositoryRoot $worktree `
        -TokenFile (Join-Path $worktree '.atlaso-local/onepassword-service-account-token.dpapi')
    $credentials = Get-AtlasoOnePasswordCredentialPair -RepositoryRoot $worktree -EnvironmentId $selector `
        -OnePasswordServiceAccountTokenFile $token -TimeoutSeconds 300 -ConsumerDescription 'development installer console'
}

$pipeName = 'Atlaso-Installation-' + [guid]::NewGuid().ToString('N')
$security = [IO.Pipes.PipeSecurity]::new()
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$security.SetOwner($user)
$security.SetAccessRuleProtection($true, $false)
foreach ($identity in @($user, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
    $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new($identity, [IO.Pipes.PipeAccessRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
}
$pipe = [IO.Pipes.NamedPipeServerStreamAcl]::Create($pipeName, [IO.Pipes.PipeDirection]::InOut, 1,
    [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous, 8192, 8192, $security)
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
try {
    $connection = $pipe.WaitForConnectionAsync()
    $vm = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode Create -Worktree $worktree `
        -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber -IsoPath $IsoPath -IsoSha256 $IsoSha256 `
        -SerialPipePath "\\.\pipe\$pipeName" -Confirm:$false
    Write-Host ('Installation VM ownership: ' + ($vm | ConvertTo-Json -Compress))
    if (-not $connection.Wait(120000)) { throw 'The owned VM did not connect its private serial console.' }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class AtlasoInstallationPipePeer {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder image, ref uint length);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int QueryProcess(SafeProcessHandle process, int informationClass, IntPtr buffer, uint length, out uint returned);
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr allocation);
    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

    // WMI omits these fields for Workstation's protected process. Query only
    // limited process metadata, using one live handle for both identity proofs.
    // Never return or log the command line, and refuse unavailable native APIs.
    public static bool MatchesExpectedProcess(uint processId, string[] allowedImages, string expectedArgument) {
        if (allowedImages == null || allowedImages.Length == 0 || String.IsNullOrEmpty(expectedArgument)) return false;
        using (SafeProcessHandle process = OpenProcess(0x1000, false, processId)) {
            if (process.IsInvalid) return false;
            var image = new StringBuilder(32768);
            uint imageLength = (uint)image.Capacity;
            if (!QueryFullProcessImageNameW(process, 0, image, ref imageLength)) return false;
            if (!Array.Exists(allowedImages, path => String.Equals(path, image.ToString(), StringComparison.OrdinalIgnoreCase))) return false;
            IntPtr library = IntPtr.Zero, buffer = IntPtr.Zero, arguments = IntPtr.Zero;
            try {
                // Restrict dynamic loading to the Windows system directory.
                string nativePath = System.IO.Path.Combine(Environment.SystemDirectory, "ntdll.dll");
                if (!NativeLibrary.TryLoad(nativePath, out library) ||
                    !NativeLibrary.TryGetExport(library, "NtQueryInformationProcess", out IntPtr entry)) return false;
                var query = Marshal.GetDelegateForFunctionPointer<QueryProcess>(entry);
                uint required;
                query(process, 60, IntPtr.Zero, 0, out required);
                int headerSize = Marshal.SizeOf<UnicodeString>();
                if (required < headerSize || required > 1048576) return false;
                buffer = Marshal.AllocHGlobal((int)required);
                if (query(process, 60, buffer, required, out uint returned) != 0 || returned < headerSize || returned > required) return false;
                var value = Marshal.PtrToStructure<UnicodeString>(buffer);
                long offset = checked(value.Buffer.ToInt64() - buffer.ToInt64());
                if ((value.Length & 1) != 0 || value.Length > value.MaximumLength ||
                    offset < headerSize || offset > returned || value.Length > returned - offset) return false;
                string commandLine = Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
                arguments = CommandLineToArgvW(commandLine, out int count);
                if (arguments == IntPtr.Zero || count < 1 || count > 32768) return false;
                for (int index = 1; index < count; index++) {
                    string argument = Marshal.PtrToStringUni(Marshal.ReadIntPtr(arguments, checked(index * IntPtr.Size)));
                    if (String.Equals(argument, expectedArgument, StringComparison.OrdinalIgnoreCase)) return true;
                }
                return false;
            }
            catch (Exception exception) when (exception is ArgumentException || exception is OverflowException ||
                exception is DllNotFoundException || exception is EntryPointNotFoundException) { return false; }
            finally {
                if (arguments != IntPtr.Zero) LocalFree(arguments);
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                if (library != IntPtr.Zero) NativeLibrary.Free(library);
            }
        }
    }
}
'@
    $peerId = [uint32]0
    if (-not [AtlasoInstallationPipePeer]::GetNamedPipeClientProcessId($pipe.SafePipeHandle, [ref]$peerId)) {
        throw 'Could not prove the serial console peer process.'
    }
    $vmxPath = [IO.Path]::GetFullPath([string]$vm.VmxPath)
    $providerImages = @(
        (Join-Path $env:ProgramFiles 'VMware/VMware Workstation/x64/vmware-vmx.exe'),
        (Join-Path $env:ProgramFiles 'VMware/VMware Workstation/vmware-vmx.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'VMware/VMware Workstation/x64/vmware-vmx.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | ForEach-Object { [IO.Path]::GetFullPath($_) }
    if (-not [AtlasoInstallationPipePeer]::MatchesExpectedProcess($peerId, [string[]]$providerImages, $vmxPath)) {
        throw 'The private console peer is not the receipt-bound VMware guest.'
    }
    $diskOptions = @(Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Select a disk' -Deadline $deadline -ReadDiskSelection:($Scenario -in @('Auto', 'AutoReboot', 'CancelReview', 'Insufficient')))
    Write-Host 'Installer reached the native Photon disk selection screen.'
    if ($Scenario -eq 'Cancel') {
        # The pinned serial getty uses TERM=screen with application cursor keys.
        Send-InstallationConsoleText -Pipe $pipe -Text "`eOD`eOD`n"
        Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Installation cancelled' -Deadline $deadline
        Write-Host 'Installer cancellation returned without admitting disk writes.'
    }
    elseif ($Scenario -in @('Auto', 'AutoReboot', 'CancelReview', 'Insufficient')) {
        # Native visual row order can differ from VMX SCSI order.
        $selectedGiB = if ($Scenario -eq 'Insufficient') { 4 } else { 64 }
        $target = @($diskOptions | Where-Object SizeGiB -EQ $selectedGiB)[0]
        Write-Host ('Selecting public native disk row {0}: {1} ({2} GiB).' -f $target.Index, $target.DiskPath, $selectedGiB)
        Send-InstallationConsoleText -Pipe $pipe -Text ("`eOA`eOA" + ("`eOB" * $target.Index) + "`n")
        if ($Scenario -eq 'Insufficient') {
            Wait-InstallationConsoleState -Pipe $pipe -Pattern 'default installation requires a disk of at least 64 GiB' `
                -Deadline $deadline -ExpectedCapacityDisk $target.DiskPath
        } else {
            Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Review planned partitions' -Deadline $deadline
            if ($Scenario -eq 'CancelReview') {
                Send-InstallationConsoleText -Pipe $pipe -Text "CANCEL`n"
                Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Installation cancelled' -Deadline $deadline
                Write-Host 'Planned-layout review cancelled before erasure consent.'
            } else {
                Send-InstallationConsoleText -Pipe $pipe -Text "NEXT`n"
                Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Review Atlaso installation disk' -Deadline $deadline
                Send-InstallationConsoleText -Pipe $pipe -Text ("ERASE {0}`n" -f $target.DiskPath)
                foreach ($account in @('admin', 'root')) {
                    $value = if ($account -eq 'admin') { $credentials.AdminPassword } else { $credentials.RootPassword }
                    foreach ($verb in @('Set', 'Confirm')) {
                        Wait-InstallationConsoleState -Pipe $pipe -Pattern "$verb $account password" -Deadline $deadline
                        Send-InstallationConsoleSecret -Pipe $pipe -Value $value
                    }
                }
                Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Atlaso installation completed.' -Deadline $deadline `
                    -KnownProvisioningStages $knownProvisioningStages
                Write-Host 'Disconnected Auto installation completed; reboot and persistence acceptance remain separate.'
            }
        }
    }
    # Keep checked provider stop and disk comparison inside this runner's existing
    # whole-process-tree deadline, including the shared vmrun inactivity checks.
    $verification = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode Verify -Worktree $worktree `
        -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber `
        -OriginalReceiptPath $vm.ReceiptPath -OriginalReceiptSha256 $vm.ReceiptSha256 `
        -BaselineReceiptPath $vm.BaselineReceiptPath -BaselineReceiptSha256 $vm.BaselineReceiptSha256 `
        -VerifyTarget:($Scenario -notin @('Auto', 'AutoReboot')) -Confirm:$false
    Write-Host ('Installation disk verification: ' + ($verification | ConvertTo-Json -Depth 4 -Compress))
    if ($Scenario -eq 'AutoReboot') {
        $pipe.Disconnect()
        $connection = $pipe.WaitForConnectionAsync()
        $boot = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode BootInstalled -Worktree $worktree `
            -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber `
            -OriginalReceiptPath $vm.ReceiptPath -OriginalReceiptSha256 $vm.ReceiptSha256 `
            -BaselineReceiptPath $vm.BaselineReceiptPath -BaselineReceiptSha256 $vm.BaselineReceiptSha256 -Confirm:$false
        if (-not $connection.Wait(120000)) { throw 'The installed VM did not reconnect its private console.' }
        $peerId = [uint32]0
        if (-not [AtlasoInstallationPipePeer]::GetNamedPipeClientProcessId($pipe.SafePipeHandle, [ref]$peerId) -or
            -not [AtlasoInstallationPipePeer]::MatchesExpectedProcess($peerId, [string[]]$providerImages, $vmxPath)) {
            throw 'The installed console peer is not the receipt-bound VMware guest.'
        }
        foreach ($account in @('root', 'admin')) {
            $accountProbe = Get-InstallationAccountProbe -Account $account
            $loginDeadline = [DateTimeOffset]::UtcNow.AddSeconds(180)
            if ($loginDeadline -gt $deadline) { $loginDeadline = $deadline }
            Write-Host ('Installed console: awaiting {0} login prompt.' -f $account)
            Wait-InstallationConsoleState -Pipe $pipe -Pattern 'login:' -Deadline $loginDeadline -ReadBootProgress:($account -eq 'root') -ReadLoginProgress
            Send-InstallationConsoleText -Pipe $pipe -Text "$account`n"
            Write-Host ('Installed console: awaiting {0} password prompt.' -f $account)
            Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Password:' -Deadline $loginDeadline -ReadLoginProgress
            $value = if ($account -eq 'root') { $credentials.RootPassword } else { $credentials.AdminPassword }
            Send-InstallationConsoleSecret -Pipe $pipe -Value $value
            # PAM/login may flush queued input before starting the shell. Never
            # send the checkpoint command until the ordinary shell prompt appears.
            Write-Host ('Installed console: awaiting {0} shell prompt.' -f $account)
            Wait-InstallationConsoleState -Pipe $pipe -Pattern $accountProbe.Prompt -Deadline $loginDeadline -ReadLoginProgress
            Send-InstallationConsoleText -Pipe $pipe -Text ($accountProbe.Command + "`n")
            Wait-InstallationConsoleState -Pipe $pipe -Pattern 'ATLASO-LOGIN-OK' -Deadline $loginDeadline -ReadLoginProgress
            Write-Host ("Installed password authentication passed for {0}." -f $account)
            Send-InstallationConsoleText -Pipe $pipe -Text "exit`n"
        }
        $verification = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode Verify -Worktree $worktree `
            -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber `
            -OriginalReceiptPath $vm.ReceiptPath -OriginalReceiptSha256 $vm.ReceiptSha256 `
            -BaselineReceiptPath $vm.BaselineReceiptPath -BaselineReceiptSha256 $vm.BaselineReceiptSha256 `
            -BootReceiptPath $boot.BootReceiptPath -BootReceiptSha256 $boot.BootReceiptSha256 -Confirm:$false
        Write-Host ('Post-reboot installation disk verification: ' + ($verification | ConvertTo-Json -Depth 4 -Compress))
    }
}
finally {
    $pipe.Dispose()
    if ($credentials) { $credentials.AdminPassword.Dispose(); $credentials.RootPassword.Dispose() }
    if ($sourceContext.PSObject.Properties['CheckoutSourcePin'] -and $sourceContext.CheckoutSourcePin) {
        $sourceContext.CheckoutSourcePin.Dispose()
    }
}
