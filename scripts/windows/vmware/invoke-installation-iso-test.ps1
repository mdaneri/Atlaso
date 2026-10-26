<#
.SYNOPSIS
Drive an isolated development installer through private console adapters.
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
.PARAMETER CollisionSuffix
Existing canonical identity suffix distinguishing independently installed test VMs.
.PARAMETER Scenario
Probe the native UI, cancel at disk/layout review, reject insufficient capacity, run Auto, or install and boot without media.
LoginInstalled resumes an already installed, receipt-bound VM without repeating installation.
BootInstalled completes a VNC-driven installation by disconnecting media and checking ordinary serial login.
VncCredential submits one SDK account value at an operator-observed concealed installer field.
.PARAMETER OriginalReceiptPath
Original VM creation receipt for LoginInstalled.
.PARAMETER OriginalReceiptSha256
Independently preserved original receipt digest.
.PARAMETER BaselineReceiptPath
Original disk-baseline receipt for LoginInstalled.
.PARAMETER BaselineReceiptSha256
Independently preserved baseline receipt digest.
.PARAMETER BootReceiptPath
Original installed-boot transition receipt for LoginInstalled.
.PARAMETER BootReceiptSha256
Independently preserved installed-boot receipt digest.
.PARAMETER TimeoutSeconds
Whole test and console deadline.
.PARAMETER InspectInstalled
Measure public machine identity and installed application bytes after root authentication.
.PARAMETER InspectionPythonPath
Existing absolute Python executable with the locked ISO inspection dependencies installed.
.PARAMETER Child
Internal bounded-child selector.
.PARAMETER VncAccount
Existing 1Password account field to send at an observed concealed VNC installer prompt.
.PARAMETER VncPort
Loopback-only VNC port owned by the original receipt-bound VM.
.PARAMETER VncScreenPath
Existing task-owned screenshot of the observed empty concealed field.
.PARAMETER VncScreenSha256
Independently retained digest of the observed screenshot.
.PARAMETER VncFieldRectangle
Single input-row rectangle excluded from the complete-frame cursor comparison.
.PARAMETER VncPythonPath
Task-owned isolated Python executable containing the reviewed optional VNC client.
.PARAMETER VncRuntimeSha256
Independently recorded deterministic inventory digest of the isolated client packages.
.PARAMETER VncRuntimeFileCount
Original file count of the isolated client package inventory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$IsoPath,
    [Parameter(Mandatory = $true)][string]$IsoSha256,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$PullRequestNumber,
    [string]$CollisionSuffix = '',
    [ValidateSet('Probe', 'Cancel', 'CancelReview', 'Insufficient', 'Auto', 'AutoReboot', 'BootInstalled', 'LoginInstalled', 'VncCredential')][string]$Scenario = 'Probe',
    [string]$OriginalReceiptPath = '',
    [string]$OriginalReceiptSha256 = '',
    [string]$BaselineReceiptPath = '',
    [string]$BaselineReceiptSha256 = '',
    [string]$BootReceiptPath = '',
    [string]$BootReceiptSha256 = '',
    [ValidateRange(60, 14400)][int]$TimeoutSeconds = 3600,
    [switch]$InspectInstalled,
    [string]$InspectionPythonPath = '',
    [switch]$Child,
    [ValidateSet('', 'admin', 'root')][string]$VncAccount = '',
    [ValidateRange(0, 65535)][int]$VncPort = 0,
    [string]$VncScreenPath = '',
    [string]$VncScreenSha256 = '',
    [string]$VncFieldRectangle = '',
    [string]$VncPythonPath = '',
    [string]$VncRuntimeSha256 = '',
    [ValidateRange(0, 14000)][int]$VncRuntimeFileCount = 0
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
if (-not $Child) {
    $childArguments = @(
        '-NoProfile', '-File', $PSCommandPath, '-Child', '-IsoPath', $IsoPath,
        '-IsoSha256', $IsoSha256, '-OutputDirectory', $OutputDirectory,
        '-PullRequestNumber', [string]$PullRequestNumber, '-CollisionSuffix', $CollisionSuffix, '-Scenario', $Scenario,
        '-TimeoutSeconds', [string]$TimeoutSeconds,
        '-OriginalReceiptPath', $OriginalReceiptPath, '-OriginalReceiptSha256', $OriginalReceiptSha256,
        '-BaselineReceiptPath', $BaselineReceiptPath, '-BaselineReceiptSha256', $BaselineReceiptSha256,
        '-BootReceiptPath', $BootReceiptPath, '-BootReceiptSha256', $BootReceiptSha256,
        '-InspectionPythonPath', $InspectionPythonPath
    )
    if ($InspectInstalled) { $childArguments += '-InspectInstalled' }
    $childArguments += @('-VncAccount', $VncAccount, '-VncPort', [string]$VncPort,
        '-VncScreenPath', $VncScreenPath, '-VncScreenSha256', $VncScreenSha256,
        '-VncFieldRectangle', $VncFieldRectangle, '-VncPythonPath', $VncPythonPath,
        '-VncRuntimeSha256', $VncRuntimeSha256, '-VncRuntimeFileCount', [string]$VncRuntimeFileCount)
    Invoke-AtlasoBoundedStreamingProcess -FilePath (Get-Process -Id $PID).Path -ArgumentList $childArguments `
        -TimeoutSeconds $TimeoutSeconds -Action 'Private installation serial-console test'
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
.PARAMETER JsonRequest
Encode a single JSON field for the contained VNC adapter's private stdin stream.
#>
function Send-InstallationConsoleSecret {
    param([IO.Stream]$Pipe, [Security.SecureString]$Value, [switch]$JsonRequest)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    $bytes = $null
    try {
        $length = [Runtime.InteropServices.Marshal]::ReadInt32($pointer, -4) / 2
        $bytes = [byte[]]::new($(if ($JsonRequest) { 2 * $length + 16 } else { $length + 1 }))
        $offset = 0
        if ($JsonRequest) {
            $prefix = [Text.Encoding]::ASCII.GetBytes('{"password":"')
            $prefix.CopyTo($bytes, 0)
            $offset = $prefix.Length
        }
        for ($index = 0; $index -lt $length; $index++) {
            $character = [Runtime.InteropServices.Marshal]::ReadInt16($pointer, $index * 2)
            if ($character -lt 32 -or $character -gt 126) { throw 'Installer credential must satisfy the ASCII account policy.' }
            if ($JsonRequest -and $character -in @(34, 92)) { $bytes[$offset++] = 92 }
            $bytes[$offset++] = [byte]$character
        }
        if ($JsonRequest) { $bytes[$offset++] = 34; $bytes[$offset++] = 125 }
        $bytes[$offset++] = 10
        $Pipe.Write($bytes, 0, $offset)
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
Decode the initial installer frame or incrementally track a private console cursor.
.DESCRIPTION
One bounded ANSI tokenizer serves both public menu rendering and private cursor tracking.
Private state contains numeric cursor metadata and parser bookkeeping, never terminal text.
.PARAMETER Text
Terminal text chunk to decode.
.PARAMETER CursorState
Per-private-pipe cursor coordinates and bounded parser bookkeeping.
.PARAMETER CursorOnly
Update private cursor state and return cursor-query snapshots without retaining cells.
#>
function ConvertFrom-InstallationConsoleFrame {
    param([string]$Text, [hashtable]$CursorState, [switch]$CursorOnly)
    if ($null -eq $Text -or $Text.Length -gt 131072) {
        throw 'The console parser input is unavailable or exceeds its bounded size.'
    }
    if ($CursorOnly -and $null -eq $CursorState) { throw 'Private console cursor state is required.' }

    <#
    .SYNOPSIS
    Refuse cursor reports after an unsupported movement without retaining console data.
    .PARAMETER State
    Private numeric cursor and parser metadata.
    #>
    function Set-ConsoleCursorUnknown {
        param([hashtable]$State)
        $State.RangeKnown = $false
        $State.ColumnKnown = $false
        $State.Saved = $null
        $State.WrapPending = $false
    }

    <#
    .SYNOPSIS
    Advance within the default viewport and scroll an optional public frame.
    .PARAMETER State
    Numeric cursor metadata with a known default scroll region.
    .PARAMETER Frame
    Optional public frame; private cursor mode supplies no cells.
    #>
    function Move-ConsoleCursorLine {
        param([hashtable]$State, [char[,]]$Frame)
        if (-not $State.MarginsKnown -or -not $State.ModesKnown -or -not $State.RangeKnown) {
            $State.RangeKnown = $false
            return
        }
        if ($null -ne $Frame -and $State.RowMin -eq 24) {
            for ($row = 0; $row -lt 24; $row++) {
                for ($col = 0; $col -lt 80; $col++) { $Frame[$row, $col] = $Frame[($row + 1), $col] }
            }
            for ($col = 0; $col -lt 80; $col++) { $Frame[24, $col] = ' ' }
        }
        # An interval starts unknown and converges after a full viewport of LF.
        $State.RowMin = [Math]::Min(24, $State.RowMin + 1)
        $State.RowMax = [Math]::Min(24, $State.RowMax + 1)
    }

    $state = if ($CursorOnly) { $CursorState } else { @{} }
    if (-not $state.ContainsKey('ParserMode')) {
        $state.ParserMode = 'Ground'
        $state.Csi = ''
        $state.StringEscape = $false
        $state.StringBell = $false
        $state.RowMin = 0
        $state.RowMax = if ($CursorOnly) { 24 } else { 0 }
        $state.RangeKnown = $true
        $state.Column = 0
        $state.ColumnKnown = -not $CursorOnly
        $state.WrapPending = $false
        $state.AutoWrap = $true
        $state.MarginsKnown = $true
        $state.OriginMode = $false
        $state.ModesKnown = $true
        $state.Saved = $null
        $state.QueryCount = 0
    }
    $frame = $null
    $queries = [Collections.Generic.List[object]]::new()
    if (-not $CursorOnly) {
        $frame = [char[,]]::new(25, 80)
        for ($row = 0; $row -lt 25; $row++) {
            for ($col = 0; $col -lt 80; $col++) { $frame[$row, $col] = ' ' }
        }
    }
    try {
        for ($inputOffset = 0; $inputOffset -lt $Text.Length; $inputOffset++) {
            $ch = $Text[$inputOffset]
            $code = [int]$ch
            if ($state.ParserMode -eq 'String') {
                if (($state.StringBell -and $code -eq 7) -or ($state.StringEscape -and $ch -ceq '\')) {
                    $state.ParserMode = 'Ground'
                    $state.StringEscape = $false
                } else { $state.StringEscape = $code -eq 27 }
                continue
            }
            if ($state.ParserMode -eq 'Charset') {
                if ($ch -cnotin @('0', 'A', 'B')) { Set-ConsoleCursorUnknown -State $state }
                $state.ParserMode = 'Ground'
                continue
            }
            if ($state.ParserMode -eq 'Escape') {
                $state.ParserMode = 'Ground'
                switch -CaseSensitive ([string]$ch) {
                    '[' { $state.ParserMode = 'CSI'; $state.Csi = '' }
                    { $_ -cin ']', 'P', '^', '_' } {
                        $state.ParserMode = 'String'
                        $state.StringBell = $ch -ceq ']'
                        $state.StringEscape = $false
                    }
                    { $_ -cin '7', 's' } {
                        $state.Saved = @{
                            RowMin = $state.RowMin; RowMax = $state.RowMax; RangeKnown = $state.RangeKnown
                            Column = $state.Column; ColumnKnown = $state.ColumnKnown; WrapPending = $state.WrapPending
                        }
                    }
                    { $_ -cin '8', 'u' } {
                        if ($state.Saved) {
                            foreach ($key in @('RowMin', 'RowMax', 'RangeKnown', 'Column', 'ColumnKnown', 'WrapPending')) {
                                $state[$key] = $state.Saved[$key]
                            }
                        } else { Set-ConsoleCursorUnknown -State $state }
                    }
                    'D' { Move-ConsoleCursorLine -State $state -Frame $frame; $state.WrapPending = $false }
                    'E' {
                        Move-ConsoleCursorLine -State $state -Frame $frame
                        $state.Column = 0; $state.ColumnKnown = $true; $state.WrapPending = $false
                    }
                    'c' {
                        $state.RowMin = 0; $state.RowMax = 0; $state.RangeKnown = $true
                        $state.Column = 0; $state.ColumnKnown = $true; $state.WrapPending = $false
                        $state.AutoWrap = $true; $state.MarginsKnown = $true; $state.OriginMode = $false
                        $state.ModesKnown = $true; $state.Saved = $null
                        if ($null -ne $frame) {
                            for ($row = 0; $row -lt 25; $row++) {
                                for ($col = 0; $col -lt 80; $col++) { $frame[$row, $col] = ' ' }
                            }
                        }
                    }
                    { $_ -cin '(', ')', '*', '+' } { $state.ParserMode = 'Charset' }
                    { $_ -cin '=', '>' } { } # Input keypad modes do not move the cursor.
                    default { Set-ConsoleCursorUnknown -State $state }
                }
                continue
            }
            if ($state.ParserMode -eq 'DiscardCSI') {
                if ($code -ge 0x40 -and $code -le 0x7e) { $state.ParserMode = 'Ground' }
                continue
            }
            if ($state.ParserMode -eq 'CSI') {
                if ($code -ge 0x40 -and $code -le 0x7e) {
                    $parameters = [string]$state.Csi
                    $state.Csi = ''; $state.ParserMode = 'Ground'
                    $private = $parameters.StartsWith('?', [StringComparison]::Ordinal)
                    $body = if ($private) { $parameters.Substring(1) } else { $parameters }
                    if ($body -notmatch '^[0-9;]*$') { Set-ConsoleCursorUnknown -State $state; continue }
                    $parts = if ($body.Length) { @($body.Split(';')) } else { @() }
                    $numbers = [Collections.Generic.List[int]]::new()
                    $invalidNumber = $false
                    foreach ($part in $parts) {
                        $number = 0
                        if ($part -and (-not [int]::TryParse($part, [ref]$number) -or $number -gt 1000000)) {
                            $invalidNumber = $true
                            break
                        }
                        $numbers.Add($number)
                    }
                    if ($invalidNumber) { Set-ConsoleCursorUnknown -State $state; continue }
                    $n = if ($numbers.Count -gt 0 -and $numbers[0] -gt 0) { $numbers[0] } else { 1 }
                    $second = if ($numbers.Count -gt 1 -and $numbers[1] -gt 0) { $numbers[1] } else { 1 }
                    switch -CaseSensitive ([string]$ch) {
                        'n' {
                            if (-not $private -and $parts.Count -eq 1 -and $parts[0] -ceq '6') {
                                # Boot, both login profiles and interactive shells share
                                # this connection. Keep a session-wide ceiling as well
                                # as the existing absolute console deadlines.
                                $state.QueryCount = [Math]::Min(65, $state.QueryCount + 1)
                                $known = $state.ModesKnown -and $state.MarginsKnown -and -not $state.OriginMode -and
                                    $state.RangeKnown -and $state.RowMin -eq $state.RowMax -and $state.ColumnKnown
                                # Snapshot now: the following bytes can restore a different cursor.
                                $queries.Add([pscustomobject]@{
                                    Known = $known; Exceeded = $state.QueryCount -gt 64
                                    Offset = $inputOffset
                                    Row = if ($known) { $state.RowMin + 1 } else { $null }
                                    Column = if ($known) { $state.Column + 1 } else { $null }
                                })
                            } else { Set-ConsoleCursorUnknown -State $state }
                        }
                        { $_ -cin 'H', 'f' } {
                            if ($private -or $numbers.Count -gt 2 -or -not $state.MarginsKnown -or
                                -not $state.ModesKnown -or $state.OriginMode) {
                                Set-ConsoleCursorUnknown -State $state
                            } else {
                                $state.RowMin = [Math]::Clamp($n - 1, 0, 24); $state.RowMax = $state.RowMin
                                $state.RangeKnown = $true
                                $state.Column = [Math]::Clamp($second - 1, 0, 79); $state.ColumnKnown = $true
                                $state.WrapPending = $false
                            }
                        }
                        { $_ -cin 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'd' } {
                            if ($private -or $numbers.Count -gt 1 -or -not $state.MarginsKnown -or
                                -not $state.ModesKnown -or $state.OriginMode) {
                                Set-ConsoleCursorUnknown -State $state
                                break
                            }
                            switch -CaseSensitive ([string]$ch) {
                                { $_ -cin 'A', 'F' } {
                                    if ($state.RangeKnown) {
                                        $state.RowMin = [Math]::Max(0, $state.RowMin - $n)
                                        $state.RowMax = [Math]::Max(0, $state.RowMax - $n)
                                    }
                                }
                                { $_ -cin 'B', 'E' } {
                                    if ($state.RangeKnown) {
                                        $state.RowMin = [Math]::Min(24, $state.RowMin + $n)
                                        $state.RowMax = [Math]::Min(24, $state.RowMax + $n)
                                    }
                                }
                                'd' { $state.RowMin = [Math]::Clamp($n - 1, 0, 24); $state.RowMax = $state.RowMin; $state.RangeKnown = $true }
                                'C' { if ($state.ColumnKnown) { $state.Column = [Math]::Min(79, $state.Column + $n) } }
                                'D' { if ($state.ColumnKnown) { $state.Column = [Math]::Max(0, $state.Column - $n) } }
                                'G' { $state.Column = [Math]::Clamp($n - 1, 0, 79); $state.ColumnKnown = $true }
                            }
                            if ($ch -cin @('E', 'F')) { $state.Column = 0; $state.ColumnKnown = $true }
                            $state.WrapPending = $false
                        }
                        'r' {
                            $bottom = if ($numbers.Count -gt 1 -and $numbers[1] -gt 0) { $numbers[1] } else { 25 }
                            $state.MarginsKnown = -not $private -and $numbers.Count -le 2 -and $n -eq 1 -and $bottom -eq 25
                            Set-ConsoleCursorUnknown -State $state
                            if ($state.MarginsKnown -and $state.ModesKnown -and -not $state.OriginMode) {
                                $state.RowMin = 0; $state.RowMax = 0; $state.RangeKnown = $true
                                $state.Column = 0; $state.ColumnKnown = $true
                            }
                        }
                        's' {
                            if ($private -or $numbers.Count) { Set-ConsoleCursorUnknown -State $state }
                            else {
                                $state.Saved = @{
                                    RowMin = $state.RowMin; RowMax = $state.RowMax; RangeKnown = $state.RangeKnown
                                    Column = $state.Column; ColumnKnown = $state.ColumnKnown; WrapPending = $state.WrapPending
                                }
                            }
                        }
                        'u' {
                            if ($private -or $numbers.Count -or -not $state.Saved) { Set-ConsoleCursorUnknown -State $state }
                            else {
                                foreach ($key in @('RowMin', 'RowMax', 'RangeKnown', 'Column', 'ColumnKnown', 'WrapPending')) {
                                    $state[$key] = $state.Saved[$key]
                                }
                            }
                        }
                        { $_ -cin 'J', 'K', 'X', 'm' } {
                            if ($ch -ceq 'm') { break }
                            if ($private -or $numbers.Count -gt 1) { Set-ConsoleCursorUnknown -State $state; break }
                            if ($null -eq $frame) { break }
                            $eraseMode = if ($numbers.Count) { $numbers[0] } else { 0 }
                            for ($row = 0; $row -lt 25; $row++) {
                                for ($col = 0; $col -lt 80; $col++) {
                                    $before = $row -lt $state.RowMin -or ($row -eq $state.RowMin -and $col -le $state.Column)
                                    $after = $row -gt $state.RowMin -or ($row -eq $state.RowMin -and $col -ge $state.Column)
                                    $erase = if ($ch -ceq 'J') {
                                        ($eraseMode -in 2, 3) -or ($eraseMode -eq 0 -and $after) -or ($eraseMode -eq 1 -and $before)
                                    } elseif ($ch -ceq 'K') {
                                        $row -eq $state.RowMin -and ($eraseMode -eq 2 -or
                                            ($eraseMode -eq 0 -and $col -ge $state.Column) -or ($eraseMode -eq 1 -and $col -le $state.Column))
                                    } else { $row -eq $state.RowMin -and $col -ge $state.Column -and $col -lt [Math]::Min(80, $state.Column + $n) }
                                    if ($erase) { $frame[$row, $col] = ' ' }
                                }
                            }
                        }
                        { $_ -cin 'h', 'l' } {
                            if (-not $private -or $numbers.Count -ne 1) {
                                $state.ModesKnown = $false; Set-ConsoleCursorUnknown -State $state
                                break
                            }
                            switch ($numbers[0]) {
                                { $_ -cin 1, 25, 2004 } { } # Nonmoving input/visibility modes.
                                7 { $state.AutoWrap = $ch -ceq 'h'; $state.WrapPending = $false; $state.Saved = $null }
                                6 {
                                    $state.OriginMode = $ch -ceq 'h'
                                    Set-ConsoleCursorUnknown -State $state
                                    if (-not $state.OriginMode -and $state.MarginsKnown -and $state.ModesKnown) {
                                        $state.RowMin = 0; $state.RowMax = 0; $state.RangeKnown = $true
                                        $state.Column = 0; $state.ColumnKnown = $true
                                    }
                                }
                                1049 { Set-ConsoleCursorUnknown -State $state } # Buffer switch; an explicit H/f can reanchor.
                                default { $state.ModesKnown = $false; Set-ConsoleCursorUnknown -State $state }
                            }
                        }
                        default { Set-ConsoleCursorUnknown -State $state }
                    }
                } elseif ($code -ge 0x20 -and $code -le 0x3f -and $state.Csi.Length -lt 64) {
                    $state.Csi += $ch
                } else {
                    $state.ParserMode = 'DiscardCSI'; $state.Csi = ''
                    Set-ConsoleCursorUnknown -State $state
                }
                continue
            }
            $control = $true
            switch ($code) {
                27 { $state.ParserMode = 'Escape' }
                13 { $state.Column = 0; $state.ColumnKnown = $true; $state.WrapPending = $false }
                10 { Move-ConsoleCursorLine -State $state -Frame $frame; $state.WrapPending = $false }
                8 { if ($state.ColumnKnown) { $state.Column = [Math]::Max(0, $state.Column - 1) }; $state.WrapPending = $false }
                9 { if ($state.ColumnKnown) { $state.Column = [Math]::Min(79, (($state.Column + 8) -band -8)) }; $state.WrapPending = $false }
                { $_ -cin 0, 7, 127 } { }
                default { $control = $false }
            }
            if ($control) { continue }
            if ($code -lt 32 -or $code -gt 126) { Set-ConsoleCursorUnknown -State $state; continue }
            if ($state.ColumnKnown -and $state.WrapPending -and $state.AutoWrap) {
                Move-ConsoleCursorLine -State $state -Frame $frame
                $state.Column = 0; $state.WrapPending = $false
            }
            if ($null -ne $frame) { $frame[$state.RowMin, $state.Column] = $ch }
            if ($state.ColumnKnown) {
                if ($state.Column -eq 79) { $state.WrapPending = $state.AutoWrap }
                else { $state.Column++ }
            } elseif ($state.RangeKnown) {
                # Unknown starting column can cause a wrap, so widen only the upper bound.
                $state.RowMax = [Math]::Min(24, $state.RowMax + 1)
            }
        }
        $state.RowKnown = $state.RangeKnown -and $state.RowMin -eq $state.RowMax
        if ($CursorOnly) { return $queries.ToArray() }
        $visible = [Collections.Generic.List[string]]::new()
        for ($row = 0; $row -lt 25; $row++) {
            $builder = [Text.StringBuilder]::new(80)
            for ($col = 0; $col -lt 80; $col++) { [void]$builder.Append($frame[$row, $col]) }
            $visible.Add($builder.ToString().TrimEnd())
        }
        return $visible.ToArray()
    }
    finally {
        if ($null -ne $frame) { [Array]::Clear($frame, 0, $frame.Length) }
        $Text = ''; $body = ''; $parameters = ''; $parts = $null
    }
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
Recognize standard installed shell prompts without exposing console contents.
.PARAMETER Text
Bounded in-memory console text with terminal color sequences removed.
.PARAMETER Account
Fixed installed account whose shell is expected.
#>
function Test-InstallationShellPrompt {
    [OutputType([bool])]
    param([string]$Text, [ValidateSet('root', 'admin')][string]$Account)
    if ($Text.Length -gt 262144) { throw 'Installed shell prompt input exceeds its bound.' }
    foreach ($changePrompt in @('You are required to change your password', 'Your password has expired',
            'Current password:', '(current) UNIX password:', 'New password:', 'Retype new password:', 'Changing password for')) {
        if ($Text.Contains($changePrompt, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Installed login requested a password change before shell verification.'
        }
    }
    if ($Account -eq 'admin') { return $Text.Contains('PS ', [StringComparison]::Ordinal) }
    # Photon profiles use bracketed prompts. Also recognize standard colon-path
    # root prompts and Bash's compiled fallback. This is
    # readiness only: the separate UID challenge remains authentication proof.
    $tail = $Text.Substring([Math]::Max(0, $Text.Length - 1024))
    $pattern = '(?:^|[\r\n])(?:root(?:@[A-Za-z0-9][A-Za-z0-9._-]{0,62})?(?:[ ]*\[[^\r\n\]\x00-\x1f]{0,256}\]|:[^\r\n\x00-\x1f]{0,256})?|-?bash-[0-9]+(?:\.[0-9]+){1,2})#[ \t]*(?:\r?\n)?\z'
    try {
        return [regex]::IsMatch($tail, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant, [TimeSpan]::FromMilliseconds(100))
    }
    catch [Text.RegularExpressions.RegexMatchTimeoutException] {
        throw 'Installed shell prompt recognition exceeded its bounded deadline.'
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
Report only fixed boot categories and answer proven cursor queries during startup.
.PARAMETER ReadLoginProgress
Report only fixed PAM and shell categories; never print login-console contents.
.PARAMETER CursorState
Cursor-only parser state for this admitted private pipe, shared across login waits.
.PARAMETER ShellAccount
Require a known installed shell prompt for this account and refuse password-change conversations.
.PARAMETER ExpectedCapacityDisk
Exact public fixture disk whose four-GiB capacity refusal is expected before consent.
.PARAMETER ReadInspectionReport
Return only one bounded encoded inspection record for independent schema validation.
#>
function Wait-InstallationConsoleState {
    param([IO.Pipes.NamedPipeServerStream]$Pipe, [string]$Pattern, [DateTimeOffset]$Deadline, [switch]$ReadDiskSelection, [string[]]$KnownProvisioningStages = @(), [switch]$ReadBootProgress, [switch]$ReadLoginProgress, [ValidateSet('', 'root', 'admin')][string]$ShellAccount = '', [string]$ExpectedCapacityDisk = '', [hashtable]$CursorState, [switch]$ReadInspectionReport)
    $buffer = [byte[]]::new(4096)
    $text = ''
    $failureDeadline = $null
    $capacityDialogDeadline = $null
    $bootFailureDeadline = $null
    $lastProvisioningStage = $null
    $knownStages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenProvisioningStages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenBootStages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenLoginStages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $loginActivity = $false
    $adminPromptSeen = $false
    $adminCursorReady = $false
    if (($ReadLoginProgress -or $ReadBootProgress) -and -not $CursorState) { $CursorState = @{} }
    foreach ($stage in $KnownProvisioningStages) { [void]$knownStages.Add($stage) }
    try {
        while ([DateTimeOffset]::UtcNow -lt $Deadline) {
            if ($failureDeadline -and [DateTimeOffset]::UtcNow -ge $failureDeadline) {
                throw 'The installer reported a Python failure before the expected console state.'
            }
            if ($capacityDialogDeadline -and [DateTimeOffset]::UtcNow -ge $capacityDialogDeadline) {
                throw 'The installer did not display a complete native capacity refusal.'
            }
            if ($bootFailureDeadline -and [DateTimeOffset]::UtcNow -ge $bootFailureDeadline) {
                throw 'The installed system reported a kernel panic before login.'
            }
            $readDeadline = if ($failureDeadline -and $failureDeadline -lt $Deadline) { $failureDeadline } else { $Deadline }
            if ($capacityDialogDeadline -and $capacityDialogDeadline -lt $readDeadline) { $readDeadline = $capacityDialogDeadline }
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
            $chunk = [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
            $text += $chunk
            if ($ReadLoginProgress -or $ReadBootProgress) {
                # Preserve high-bit bytes as non-ASCII markers instead of replacing
                # them with printable question marks of an invented display width.
                $cursorChunk = [Text.Encoding]::Latin1.GetString($buffer, 0, $count)
                $cursorQueries = @(ConvertFrom-InstallationConsoleFrame -Text $cursorChunk -CursorState $CursorState -CursorOnly)
                foreach ($cursorQuery in $cursorQueries) {
                    if ($cursorQuery.Exceeded) { throw 'Installed console exceeded its bounded cursor-position queries.' }
                    if ($seenLoginStages.Add('cursor-position-query')) {
                        if ($ReadLoginProgress) { Write-Host 'Public installed login stage: cursor-position-query' }
                        else { Write-Host 'Public boot stage: cursor-position-query' }
                    }
                    if ($cursorQuery.Known) {
                        Send-InstallationConsoleText -Pipe $pipe -Text ("`e[{0};{1}R" -f $cursorQuery.Row, $cursorQuery.Column)
                        Write-Host 'Answered a proven cursor-position query.'
                        # PowerShell can print its prompt before obtaining the cursor.
                        # Require the observed post-prompt handshake before queuing
                        # application input; prompt bytes alone are not readiness.
                        $promptOffset = $text.LastIndexOf('PS ', [StringComparison]::Ordinal)
                        $queryOffset = $text.Length - $cursorChunk.Length + $cursorQuery.Offset
                        if ($ShellAccount -eq 'admin' -and ($adminPromptSeen -or
                            ($promptOffset -ge 0 -and $queryOffset -ge $promptOffset + 3))) {
                            $adminCursorReady = $true
                        }
                    }
                }
            }
            $plain = [regex]::Replace($text, '\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Z0-9]|\x1b[=>su]', '')
            $plain = [regex]::Replace($plain, '\^?\[\[[0-9]{1,2};[0-9]{1,2}R', '')
            if ($ReadInspectionReport) {
                $inspectionFailure = [regex]::Match($plain, 'ATLASO-INSPECTION-FAILED(?::(?<stage>initialization|source-helpers|software-staging|software-verification|application-payload|public-identities))?[\r\n]+')
                if ($inspectionFailure.Success) {
                    $inspectionStage = $inspectionFailure.Groups['stage'].Value
                    if ($inspectionStage) { throw ('Installed inspection failed at public stage: ' + $inspectionStage + '.') }
                    throw 'Installed identity or application payload inspection failed.'
                }
                # Admit only a complete output line. The encoded command sent to
                # the shell contains no contiguous marker and cannot echo proof.
                $records = [regex]::Matches($plain, '(?:^|[\r\n])ATLASO-INSPECTION:([A-Za-z0-9+/=]{1,4096}):END(?=[\r\n]|$)')
                if ($records.Count -gt 1) { throw 'Installed inspection returned duplicate records.' }
                if ($records.Count -eq 1) { return $records[0].Groups[1].Value }
                if ($plain.Length -gt 16384) { throw 'Installed inspection console output exceeded its bound.' }
            }
            if ($ReadLoginProgress) {
                $loginActivity = $true
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
                    @{ Token = 'login:'; Name = 'login-prompt' },
                    @{ Token = 'timed out'; Name = 'login-timeout' },
                    @{ Token = 'PAM failure'; Name = 'pam-failure' },
                    @{ Token = 'Critical error - immediate abort'; Name = 'pam-critical-error' },
                    @{ Token = 'Authentication token manipulation error'; Name = 'password-token-error' },
                    @{ Token = 'Permission denied'; Name = 'access-denied' },
                    @{ Token = 'Cannot execute'; Name = 'shell-execution-failed' },
                    @{ Token = 'No shell'; Name = 'shell-unavailable' },
                    @{ Token = 'Cannot make/remove an entry for the specified session'; Name = 'session-creation-failed' },
                    @{ Token = 'cannot open session'; Name = 'session-open-failed' },
                    @{ Token = 'Maximum number of tries exceeded'; Name = 'authentication-attempt-limit' },
                    @{ Token = 'bash-'; Name = 'bash-fallback-prompt-candidate' },
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
                    if ($knownStages.Contains($candidateStage)) {
                        $lastProvisioningStage = $candidateStage
                        if ($seenProvisioningStages.Add($candidateStage)) {
                            Write-Host ('Public provisioning stage: ' + $lastProvisioningStage)
                        }
                    }
                }
            }
            if ($plain.Contains('Atlaso installation cancelled or failed (status ', [StringComparison]::Ordinal)) {
                throw 'The installation launcher reported failure before the expected console state.'
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
            if ($ExpectedCapacityDisk -and
                -not $plain.Contains('Traceback (most recent call last):', [StringComparison]::Ordinal)) {
                $capacityHeaderSeen = $plain.Contains('Insufficient disk capacity.', [StringComparison]::Ordinal)
                $capacityPromptSeen = $plain.Contains(
                    'default installation requires a disk of at least 64 GiB', [StringComparison]::Ordinal)
                if (($capacityHeaderSeen -or $capacityPromptSeen) -and -not $capacityDialogDeadline) {
                    # Allow fragmented serial frames to finish the bounded native message,
                    # then fail closed instead of waiting through the whole VM deadline.
                    $capacityDialogDeadline = [DateTimeOffset]::UtcNow.AddSeconds(2)
                }
                if ($capacityHeaderSeen -or $capacityPromptSeen) {
                    $visibleCapacityRows = @(ConvertFrom-InstallationConsoleFrame -Text $text |
                        ForEach-Object { $_.Trim() })
                    $capacityFound = $false
                    for ($row = 0; $row -le $visibleCapacityRows.Count - 4; $row++) {
                        if ($visibleCapacityRows[$row] -cne 'Insufficient disk capacity.' -or
                            $visibleCapacityRows[$row + 1] -cne 'default installation requires a disk of at least 64 GiB' -or
                            $visibleCapacityRows[$row + 3] -cne 'Press Enter to choose another disk, or Esc to cancel.') {
                            continue
                        }
                        $capacityLine = [regex]::Match($visibleCapacityRows[$row + 2],
                            '^Selected (?<disk>/dev/[a-zA-Z0-9_.-]{1,64}) has (?<bytes>[0-9]{1,20}) bytes\.$',
                            [Text.RegularExpressions.RegexOptions]::CultureInvariant)
                        if (-not $capacityLine.Success -or
                            $capacityLine.Groups['disk'].Value -cne $ExpectedCapacityDisk -or
                            $capacityLine.Groups['bytes'].Value -cne '4294967296') {
                            throw 'The installer displayed a mismatched or malformed native capacity refusal.'
                        }
                        $capacityFound = $true
                        break
                    }
                    if ($capacityFound) {
                        Write-Host ('Public capacity refusal: {0}, 4294967296 bytes; requires 68719476736 bytes.' -f
                            $ExpectedCapacityDisk)
                        Write-Host 'The selected four-GiB disk was refused before erasure consent.'
                        return
                    }
                }
            }
            if ($plain.Contains('Traceback (most recent call last):', [StringComparison]::Ordinal)) {
                if (-not $failureDeadline) { $failureDeadline = [DateTimeOffset]::UtcNow.AddSeconds(2) }
                # Wait briefly for fragmented frames, then emit only allowlisted
                # public source identifiers. Never emit paths, code or messages.
                $kind = [regex]::Match($plain, '(?m)^(ValueError|RuntimeError|ImportError|ModuleNotFoundError|FileNotFoundError|AttributeError|TypeError|_curses\.error|subprocess\.CalledProcessError):')
                if ($kind.Success) {
                    $frames = @([regex]::Matches($plain, 'File "[^"\r\n]*/(bootstrap\.py|manifest\.py|installer\.py|disks\.py|window\.py|menu\.py|readtext\.py|progressbar\.py)", line ([0-9]{1,6}),') |
                        Select-Object -Last 8 | ForEach-Object { $_.Groups[1].Value + ':' + $_.Groups[2].Value })
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
                    throw ('The installer reported a Python failure before the expected console state. Public location: {0}; {1}.' -f $kind.Groups[1].Value, ($frames -join ', '))
                }
            }
            $matched = if ($ShellAccount) { Test-InstallationShellPrompt -Text $plain -Account $ShellAccount }
                else { $plain.Contains($Pattern, [StringComparison]::Ordinal) }
            if ($ShellAccount -eq 'admin' -and $matched) {
                $adminPromptSeen = $true
                if (-not $adminCursorReady) { $matched = $false }
            }
            if (-not $ReadInspectionReport -and -not $ExpectedCapacityDisk -and -not $failureDeadline -and $matched) {
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
        if ($ReadLoginProgress) {
            $activity = if (-not $loginActivity) { 'no-console-activity' }
                elseif ([regex]::Replace($plain, '[\x00-\x20\x7f]', '').Length -eq 0) { 'control-only-console-activity' }
                else { 'unmatched-console-activity' }
            Write-Host ('Public installed login deadline: ' + $activity)
        }
        throw 'The installer did not reach the expected public console state before its deadline.'
    }
    finally {
        [Array]::Clear($buffer, 0, $buffer.Length)
        $text = ''; $plain = ''; $chunk = ''; $cursorChunk = ''; $cursorQueries = $null
    }
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
            EnterKey = "`n"
        }
    }
    # Shared provisioning selects /usr/bin/pwsh for the administrator. Keep
    # marker fragments separate so terminal echo cannot satisfy the checkpoint.
    [pscustomobject]@{
        Prompt = 'PS '
        Command = 'if ((id -un) -ceq ''admin'') { Write-Output (''ATLASO-'' + ''LOGIN-OK'') }'
        # .NET's Unix console maps LF to Ctrl+Enter. CR is ordinary Enter.
        EnterKey = "`r"
    }
}

<#
.SYNOPSIS
Load the existing native verifier for a receipt-bound console provider.
#>
function Initialize-InstallationConsolePeerVerifier {
    if ('AtlasoInstallationPipePeer' -as [type]) { return }
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
}

<#
.SYNOPSIS
Bind one loopback VNC listener to the existing native console-provider verifier.
.PARAMETER VmxPath
Original receipt-admitted VMX path.
.PARAMETER Port
Explicit loopback-only VNC listener port.
#>
function Get-InstallationVncPeer {
    param([Parameter(Mandatory)][string]$VmxPath, [Parameter(Mandatory)][int]$Port)
    if ($Port -lt 1024 -or $Port -gt 65535) { throw 'VNC requires an explicit non-privileged loopback port.' }
    $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop)
    if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -cne '127.0.0.1') {
        throw 'VNC listener must bind exclusively to IPv4 loopback.'
    }
    Initialize-InstallationConsolePeerVerifier
    $images = @(
        (Join-Path $env:ProgramFiles 'VMware/VMware Workstation/x64/vmware-vmx.exe'),
        (Join-Path $env:ProgramFiles 'VMware/VMware Workstation/vmware-vmx.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'VMware/VMware Workstation/x64/vmware-vmx.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    $peer = [uint32]$listeners[0].OwningProcess
    if (-not [AtlasoInstallationPipePeer]::MatchesExpectedProcess($peer, [string[]]$images, $VmxPath)) {
        throw 'VNC listener does not belong to the original receipt-bound VM.'
    }
    return $peer
}

<#
.SYNOPSIS
Reuse the bounded SDK and byte encoder for one observed concealed VNC field.
.PARAMETER Context
Source-pinned task ownership context for the original VM.
.PARAMETER Options
Public account, loopback, observed-frame and isolated-runtime admission inputs.
.PARAMETER Receipts
Original VM and baseline selectors preserved at creation.
#>
function Invoke-InstallationVncCredential {
    param([Parameter(Mandatory)][psobject]$Context, [Parameter(Mandatory)][hashtable]$Options,
        [Parameter(Mandatory)][hashtable]$Receipts)
    if ($Options.Account -notin @('admin', 'root') -or $Options.Port -lt 1024 -or
        $Options.ScreenSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Options.RuntimeSha256 -cnotmatch '^[0-9a-f]{64}$' -or $Options.RuntimeFileCount -lt 1 -or
        $Options.Rectangle -cnotmatch '^\d{1,4},\d{1,4},\d{1,4},\d{1,4}$') {
        throw 'VNC credential input requires an explicit account, observed field and original runtime inventory.'
    }
    foreach ($pair in @(
        @($Receipts.OriginalReceiptPath, $Receipts.OriginalReceiptSha256),
        @($Receipts.BaselineReceiptPath, $Receipts.BaselineReceiptSha256)
    )) {
        if (-not [IO.Path]::IsPathFullyQualified($pair[0]) -or $pair[1] -cnotmatch '^[0-9a-f]{64}$') {
            throw 'VNC requires original VM and baseline receipt selectors.'
        }
    }
    $ownedPrefix = [IO.Path]::GetFullPath($Context.Worktree).TrimEnd('\', '/') + '\'
    foreach ($path in @($Options.PythonPath, $Options.ScreenPath)) {
        if (-not [IO.Path]::IsPathFullyQualified($path) -or
            -not [IO.Path]::GetFullPath($path).StartsWith($ownedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'VNC runtime and observed frame must remain inside the original task checkout.'
        }
        & git -C $Context.Worktree check-ignore -q -- $path
        if ($LASTEXITCODE -ne 0) { throw 'VNC runtime and observed frame must be ignored task artifacts.' }
    }
    Import-Module (Join-Path $PSScriptRoot 'Atlaso.SourceSnapshot.psm1') -Force
    $runtime = $null
    $inspectorSource = $null
    $framePin = $null
    $frameDirectoryPin = $null
    $pair = $null
    $consumer = $null
    try {
        $vm = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode AdmitConsole `
            -Worktree $Context.Worktree -OutputDirectory $Context.OutputDirectory `
            -PullRequestNumber $Context.PullRequestNumber -CollisionSuffix $CollisionSuffix @Receipts
        if ($vm.IsoIdentity.Sha256 -cne $IsoSha256 -or
            -not [IO.Path]::GetFullPath($IsoPath).Equals($vm.IsoIdentity.Path, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'VNC ISO differs from its original creation receipt.'
        }
        $peer = Get-InstallationVncPeer -VmxPath $vm.VmxPath -Port $Options.Port
        # The SDK bridge must finish its durable state publication and cleanup
        # before the VNC guards hold read-only ancestor directory handles. Those
        # handles intentionally exclude atomic child-file replacement in the
        # checkout-local bridge marker directory. Retain only SecureStrings here;
        # client code/runtime/frame admission still precedes plaintext submission.
        Assert-AtlasoTestVmCheckoutSource -Context $Context
        Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
        $selector = Resolve-AtlasoOnePasswordEnvironmentId -RepositoryRoot $Context.Worktree
        $token = Resolve-AtlasoOnePasswordServiceAccountTokenFile -RepositoryRoot $Context.Worktree `
            -TokenFile (Join-Path $Context.Worktree '.atlaso-local/onepassword-service-account-token.dpapi')
        $pair = Get-AtlasoOnePasswordCredentialPair -RepositoryRoot $Context.Worktree -EnvironmentId $selector `
            -OnePasswordServiceAccountTokenFile $token -TimeoutSeconds 300 -ConsumerDescription 'development VNC installer console'
        $venv = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($Options.PythonPath))
        $inspectorSource = New-AtlasoCertificateInspectorSnapshot -RepositoryRoot $Context.Worktree `
            -EvidenceRoot ([IO.Path]::GetDirectoryName($venv)) -SourceCommit $Context.SourceCommit `
            -TaskId $Context.TaskId -Purpose installation-vnc
        Write-Host ('VNC inspector source receipt: path={0} sha256={1}' -f $inspectorSource.Manifest,
            (Get-FileHash -LiteralPath $inspectorSource.Manifest -Algorithm SHA256).Hash.ToLowerInvariant())
        # Keep the existing credentialed runtime guard and isolated bootstrap;
        # only the explicitly required optional client packages differ.
        $runtime = Protect-AtlasoCertificatePythonRuntime -PythonPath $Options.PythonPath `
            -EvidenceRoot ([IO.Path]::GetDirectoryName($venv)) -RequiredModules @('vncdotool', 'twisted', 'PIL')
        Assert-AtlasoCertificatePythonImportPaths -Runtime $runtime
        $null = Assert-AtlasoSourceSnapshot -Root (Join-Path $venv 'Lib/site-packages') `
            -ExpectedSha256 $Options.RuntimeSha256 -ExpectedFileCount $Options.RuntimeFileCount
        $frameDirectoryPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath(
            [IO.Path]::GetDirectoryName($Options.ScreenPath))
        $framePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Options.ScreenPath, $true)
        if ((Get-Item -LiteralPath $Options.ScreenPath).Length -gt 8MB -or
            (Get-FileHash -LiteralPath $Options.ScreenPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Options.ScreenSha256) {
            throw 'Observed VNC frame differs from its admitted digest or size.'
        }
        Assert-AtlasoTestVmCheckoutSource -Context $Context
        $arguments = New-AtlasoCertificatePythonArguments -Runtime $runtime `
            -ScriptPath (Join-Path $inspectorSource.Root 'scripts/installation/vnc_console.py') -ScriptArguments @(
                '--port', [string]$Options.Port, '--expected-screen', $Options.ScreenPath,
                '--expected-screen-sha256', $Options.ScreenSha256, '--field-rectangle', $Options.Rectangle)
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $runtime.Executable
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardInput = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
        foreach ($argument in $arguments) { $start.ArgumentList.Add($argument) }
        # This grandchild inherits the outer non-breakaway Windows job. No secret
        # is placed in its command line, environment, screenshot or ordinary file.
        $consumer = [Diagnostics.Process]::Start($start)
        $errors = $consumer.StandardError.ReadToEndAsync()
        $ready = $consumer.StandardOutput.ReadLineAsync()
        if (-not $ready.Wait(30000) -or $ready.Result -cne 'ATLASO-VNC-CREDENTIAL-READY') {
            throw 'VNC concealed-field frame admission refused; no credential was sent.'
        }
        Assert-AtlasoTestVmCheckoutSource -Context $Context
        $readmitted = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode AdmitConsole `
            -Worktree $Context.Worktree -OutputDirectory $Context.OutputDirectory `
            -PullRequestNumber $Context.PullRequestNumber -CollisionSuffix $CollisionSuffix @Receipts
        if ($readmitted.VmxPath -cne $vm.VmxPath -or
            $readmitted.IsoIdentity.Sha256 -cne $vm.IsoIdentity.Sha256) {
            throw 'VNC VM or media identity changed before credential submission.'
        }
        if ((Get-InstallationVncPeer -VmxPath $vm.VmxPath -Port $Options.Port) -ne $peer) {
            throw 'VNC console peer changed before credential submission.'
        }
        $secret = if ($Options.Account -ceq 'admin') { $pair.AdminPassword } else { $pair.RootPassword }
        Send-InstallationConsoleSecret -Pipe $consumer.StandardInput.BaseStream -Value $secret -JsonRequest
        $consumer.StandardInput.Close()
        $sent = $consumer.StandardOutput.ReadLineAsync()
        if (-not $sent.Wait(30000) -or $sent.Result -cne 'ATLASO-VNC-CREDENTIAL-SENT' -or
            -not $consumer.WaitForExit(30000) -or $consumer.ExitCode -ne 0 -or
            -not $errors.Wait(5000) -or $errors.Result.Length -ne 0) {
            throw 'The contained VNC credential operation did not complete; private diagnostics were withheld.'
        }
        Write-Host ('Concealed VNC installer field submitted for {0}.' -f $Options.Account)
    }
    finally {
        if ($consumer) {
            if (-not $consumer.HasExited) {
                $consumer.Kill($true)
                if (-not $consumer.WaitForExit(5000)) { throw 'VNC credential child termination is unproven.' }
            }
            $consumer.Dispose()
        }
        if ($pair) { $pair.AdminPassword.Dispose(); $pair.RootPassword.Dispose() }
        if ($framePin) { $framePin.Dispose() }
        if ($frameDirectoryPin) { $frameDirectoryPin.Dispose() }
        if ($runtime) { foreach ($pin in $runtime.Pins) { $pin.Dispose() } }
        if ($inspectorSource) {
            try { Unprotect-AtlasoSourceSnapshot -Root $inspectorSource.Root }
            finally { foreach ($pin in $inspectorSource.Pins) { $pin.Dispose() } }
        }
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
$vmName = (New-AtlasoVmwareTestIdentity -PullRequestNumber $PullRequestNumber -Purpose installation-iso -CollisionSuffix $CollisionSuffix).Name
$sourceContext = New-AtlasoTestVmOwnershipContext -Worktree $worktree -OutputDirectory $OutputDirectory `
    -VmxPath (Join-Path $OutputDirectory "$vmName.vmx") -Name $vmName -SourceCommit $commit `
    -SourceBranch $branch -PullRequestNumber $PullRequestNumber
Assert-AtlasoTestVmCheckoutSource -Context $sourceContext
if ($Scenario -eq 'VncCredential') {
    try {
        if ($InspectInstalled -or $InspectionPythonPath -or $BootReceiptPath -or $BootReceiptSha256) {
            throw 'VncCredential is restricted to an initial concealed installer field.'
        }
        $vncOptions = @{ Account = $VncAccount; Port = $VncPort; ScreenPath = $VncScreenPath
            ScreenSha256 = $VncScreenSha256; Rectangle = $VncFieldRectangle; PythonPath = $VncPythonPath
            RuntimeSha256 = $VncRuntimeSha256; RuntimeFileCount = $VncRuntimeFileCount }
        $vncReceipts = @{ OriginalReceiptPath = $OriginalReceiptPath; OriginalReceiptSha256 = $OriginalReceiptSha256
            BaselineReceiptPath = $BaselineReceiptPath; BaselineReceiptSha256 = $BaselineReceiptSha256 }
        Invoke-InstallationVncCredential -Context $sourceContext -Options $vncOptions -Receipts $vncReceipts
    }
    finally {
        if ($sourceContext.PSObject.Properties['CheckoutSourcePin'] -and $sourceContext.CheckoutSourcePin) {
            $sourceContext.CheckoutSourcePin.Dispose()
        }
    }
    return
}
if ($VncAccount -or $VncPort -or $VncScreenPath -or $VncScreenSha256 -or $VncFieldRectangle -or
    $VncPythonPath -or $VncRuntimeSha256 -or $VncRuntimeFileCount) {
    throw 'VNC inputs require the explicit VncCredential scenario.'
}
$knownProvisioningStages = @(Get-InstallationProvisioningStages -Text (Get-Content -LiteralPath `
    (Join-Path $worktree 'image/common/scripts/provision-atlaso.sh') -Raw -Encoding utf8))
$credentials = $null
$resumeSelectors = @{}
if ($Scenario -in @('LoginInstalled', 'BootInstalled')) {
    $requiredReceiptPairs = @(
        @($OriginalReceiptPath, $OriginalReceiptSha256),
        @($BaselineReceiptPath, $BaselineReceiptSha256)
    )
    if ($Scenario -eq 'LoginInstalled') { $requiredReceiptPairs += ,@($BootReceiptPath, $BootReceiptSha256) }
    elseif ($BootReceiptPath -or $BootReceiptSha256) { throw 'BootInstalled creates a new media-disconnection receipt; use LoginInstalled to resume it.' }
    foreach ($pair in $requiredReceiptPairs) {
        if (-not [IO.Path]::IsPathFullyQualified($pair[0]) -or $pair[1] -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Installed checks require the original VM, baseline, and applicable boot receipt selectors.'
        }
    }
    $resumeSelectors = @{
        OriginalReceiptPath = $OriginalReceiptPath; OriginalReceiptSha256 = $OriginalReceiptSha256
        BaselineReceiptPath = $BaselineReceiptPath; BaselineReceiptSha256 = $BaselineReceiptSha256
    }
    if ($Scenario -eq 'LoginInstalled') {
        $resumeSelectors.BootReceiptPath = $BootReceiptPath
        $resumeSelectors.BootReceiptSha256 = $BootReceiptSha256
    }
} elseif ($OriginalReceiptPath -or $OriginalReceiptSha256 -or $BaselineReceiptPath -or $BaselineReceiptSha256 -or $BootReceiptPath -or $BootReceiptSha256) {
    throw 'Existing VM receipt selectors require BootInstalled or LoginInstalled.'
}
$inspection = $null
$inspectionArguments = @()
$encodedExpectations = ''
if ($InspectInstalled) {
    if ($Scenario -notin @('AutoReboot', 'BootInstalled', 'LoginInstalled')) {
        throw 'Installed inspection requires AutoReboot, BootInstalled or LoginInstalled.'
    }
    if (-not [IO.Path]::IsPathFullyQualified($InspectionPythonPath) -or
        -not (Test-Path -LiteralPath $InspectionPythonPath -PathType Leaf)) {
        throw 'Installed inspection requires an existing absolute Python executable.'
    }
    # Reuse the bounded process runner and the admitted source tree. Resolve ISO
    # expectations before obtaining credentials or starting the owned VM.
    $inspectionArguments = @('-I', '-B', '-c',
        'import sys;sys.path.insert(0,sys.argv.pop(1));from scripts.installation.inspection import main;raise SystemExit(main())', $worktree)
    $prepared = Invoke-AtlasoBoundedProcess -FilePath $InspectionPythonPath `
        -ArgumentList ($inspectionArguments + @('prepare', '--iso', $IsoPath, '--iso-sha256', $IsoSha256)) `
        -TimeoutSeconds 120 -Action 'Installation inspection ISO admission'
    if ($prepared.Length -gt 16384) { throw 'Installation inspection preparation exceeded its bound.' }
    $inspection = $prepared | ConvertFrom-Json -AsHashtable
    if ($inspection.command -isnot [string] -or $inspection.command.Length -gt 3500 -or
        $inspection.command -cmatch '[^\x20-\x7e]' -or $inspection.command.Contains('ATLASO-INSPECTION')) {
        throw 'Installation inspection command failed its console boundary.'
    }
    $encodedExpectations = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
        ($inspection.expected | ConvertTo-Json -Compress -Depth 8)))
} elseif ($InspectionPythonPath) {
    throw 'InspectionPythonPath requires InspectInstalled.'
}
if ($Scenario -in @('Auto', 'AutoReboot', 'BootInstalled', 'LoginInstalled')) {
    Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
    $selector = Resolve-AtlasoOnePasswordEnvironmentId -RepositoryRoot $worktree
    $token = Resolve-AtlasoOnePasswordServiceAccountTokenFile -RepositoryRoot $worktree `
        -TokenFile (Join-Path $worktree '.atlaso-local/onepassword-service-account-token.dpapi')
    $credentials = Get-AtlasoOnePasswordCredentialPair -RepositoryRoot $worktree -EnvironmentId $selector `
        -OnePasswordServiceAccountTokenFile $token -TimeoutSeconds 300 -ConsumerDescription 'development installer console'
}

$pipeName = 'Atlaso-Installation-' + [guid]::NewGuid().ToString('N')
if ($Scenario -in @('LoginInstalled', 'BootInstalled')) {
    $vm = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode Verify -Worktree $worktree `
        -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber -CollisionSuffix $CollisionSuffix @resumeSelectors -Confirm:$false
    if (-not [IO.Path]::GetFullPath($IsoPath).Equals([string]$vm.IsoPath, [StringComparison]::OrdinalIgnoreCase) -or
        $IsoSha256 -cne [string]$vm.IsoSha256) {
        throw 'LoginInstalled ISO identity differs from the original VM creation receipt.'
    }
    # The owning verifier returns only the admitted local serial endpoint.
    # Reuse it with a newly created restrictive server; never edit the VMX.
    if ([string]$vm.SerialPipePath -cnotmatch '^\\\\\.\\pipe\\(?<name>Atlaso-Installation-[0-9a-f]{32})$') {
        throw 'The admitted installed VM serial endpoint is invalid.'
    }
    $pipeName = $Matches['name']
}
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
    if ($Scenario -eq 'LoginInstalled') {
        $boot = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode ResumeInstalled -Worktree $worktree `
            -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber -CollisionSuffix $CollisionSuffix @resumeSelectors -Confirm:$false
    } elseif ($Scenario -eq 'BootInstalled') {
        $boot = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode BootInstalled -Worktree $worktree `
            -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber -CollisionSuffix $CollisionSuffix @resumeSelectors -Confirm:$false
        Write-Host ('Installed boot ownership: ' + ($boot | ConvertTo-Json -Depth 4 -Compress))
    } else {
        $vm = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode Create -Worktree $worktree `
        -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber -CollisionSuffix $CollisionSuffix -IsoPath $IsoPath -IsoSha256 $IsoSha256 `
        -SerialPipePath "\\.\pipe\$pipeName" -Confirm:$false
    }
    Write-Host ('Installation VM ownership: ' + ($vm | ConvertTo-Json -Compress))
    if (-not $connection.Wait(120000)) { throw 'The owned VM did not connect its private serial console.' }

    Initialize-InstallationConsolePeerVerifier
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
    $cursorState = @{}
    if ($Scenario -notin @('LoginInstalled', 'BootInstalled')) {
        Write-Host 'Public installer phase: awaiting-disk-selection'
        $diskOptions = @(Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Select a disk' -Deadline $deadline -ReadBootProgress -CursorState $cursorState -ReadDiskSelection:($Scenario -in @('Probe', 'Auto', 'AutoReboot', 'CancelReview', 'Insufficient')))
        Write-Host 'Public installer phase: disk-selection-ready'
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
                Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Erase selected disks?' -Deadline $deadline
                if ($Scenario -eq 'CancelReview') {
                    # Photon's confirmation defaults to No; Enter declines erasure.
                    Send-InstallationConsoleText -Pipe $pipe -Text "`n"
                    Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Installation cancelled' -Deadline $deadline
                    Write-Host 'Planned-layout review cancelled before erasure consent.'
                } else {
                    # The native horizontal Yes/No menu starts on No. Select Yes explicitly.
                    Send-InstallationConsoleText -Pipe $pipe -Text "`eOD`n"
                    foreach ($account in @('admin', 'root')) {
                        $value = if ($account -eq 'admin') { $credentials.AdminPassword } else { $credentials.RootPassword }
                        foreach ($verb in @('Set', 'Confirm')) {
                            Wait-InstallationConsoleState -Pipe $pipe -Pattern "$verb $account password" -Deadline $deadline
                            Send-InstallationConsoleSecret -Pipe $pipe -Value $value
                        }
                    }
                    Write-Host 'Public installer phase: awaiting-installation-completion'
                    Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Atlaso installation completed.' -Deadline $deadline `
                        -KnownProvisioningStages $knownProvisioningStages
                    Write-Host 'Disconnected Auto installation completed; reboot and persistence acceptance remain separate.'
                }
            }
        }
        # Keep checked provider stop and disk comparison inside this runner's existing
        # whole-process-tree deadline, including the shared vmrun inactivity checks.
        $verification = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode Verify -Worktree $worktree `
            -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber -CollisionSuffix $CollisionSuffix `
            -OriginalReceiptPath $vm.ReceiptPath -OriginalReceiptSha256 $vm.ReceiptSha256 `
            -BaselineReceiptPath $vm.BaselineReceiptPath -BaselineReceiptSha256 $vm.BaselineReceiptSha256 `
            -VerifyTarget:($Scenario -notin @('Auto', 'AutoReboot')) -Confirm:$false
        Write-Host ('Installation disk verification: ' + ($verification | ConvertTo-Json -Depth 4 -Compress))
    }
    if ($Scenario -eq 'AutoReboot') {
        $pipe.Disconnect()
        $connection = $pipe.WaitForConnectionAsync()
        $boot = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode BootInstalled -Worktree $worktree `
            -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber -CollisionSuffix $CollisionSuffix `
            -OriginalReceiptPath $vm.ReceiptPath -OriginalReceiptSha256 $vm.ReceiptSha256 `
            -BaselineReceiptPath $vm.BaselineReceiptPath -BaselineReceiptSha256 $vm.BaselineReceiptSha256 -Confirm:$false
        if (-not $connection.Wait(120000)) { throw 'The installed VM did not reconnect its private console.' }
        $peerId = [uint32]0
        if (-not [AtlasoInstallationPipePeer]::GetNamedPipeClientProcessId($pipe.SafePipeHandle, [ref]$peerId) -or
            -not [AtlasoInstallationPipePeer]::MatchesExpectedProcess($peerId, [string[]]$providerImages, $vmxPath)) {
            throw 'The installed console peer is not the receipt-bound VMware guest.'
        }
        $cursorState = @{}
    }
    if ($Scenario -in @('AutoReboot', 'BootInstalled', 'LoginInstalled')) {
        foreach ($account in @('root', 'admin')) {
            $accountProbe = Get-InstallationAccountProbe -Account $account
            $loginDeadline = [DateTimeOffset]::UtcNow.AddSeconds(180)
            if ($loginDeadline -gt $deadline) { $loginDeadline = $deadline }
            Write-Host ('Installed console: awaiting {0} login prompt.' -f $account)
            Wait-InstallationConsoleState -Pipe $pipe -Pattern 'login:' -Deadline $loginDeadline -ReadBootProgress:($account -eq 'root') -ReadLoginProgress -CursorState $cursorState
            Send-InstallationConsoleText -Pipe $pipe -Text "$account`n"
            Write-Host ('Installed console: awaiting {0} password prompt.' -f $account)
            Wait-InstallationConsoleState -Pipe $pipe -Pattern 'Password:' -Deadline $loginDeadline -ReadLoginProgress -CursorState $cursorState
            $value = if ($account -eq 'root') { $credentials.RootPassword } else { $credentials.AdminPassword }
            Send-InstallationConsoleSecret -Pipe $pipe -Value $value
            # PAM/login may flush queued input before starting the shell. Never
            # send the checkpoint command until the ordinary shell prompt appears.
            Write-Host ('Installed console: awaiting {0} shell prompt.' -f $account)
            Wait-InstallationConsoleState -Pipe $pipe -Pattern $accountProbe.Prompt -Deadline $loginDeadline -ReadLoginProgress -ShellAccount $account -CursorState $cursorState
            Send-InstallationConsoleText -Pipe $pipe -Text ($accountProbe.Command + $accountProbe.EnterKey)
            Wait-InstallationConsoleState -Pipe $pipe -Pattern 'ATLASO-LOGIN-OK' -Deadline $loginDeadline -ReadLoginProgress -CursorState $cursorState
            Write-Host ("Installed password authentication passed for {0}." -f $account)
            if ($InspectInstalled -and $account -eq 'root') {
                Send-InstallationConsoleText -Pipe $pipe -Text ($inspection.command + "`n")
                $inspectionDeadline = [DateTimeOffset]::UtcNow.AddSeconds(180)
                if ($inspectionDeadline -gt $deadline) { $inspectionDeadline = $deadline }
                $encodedReport = Wait-InstallationConsoleState -Pipe $pipe -Pattern '' -Deadline $inspectionDeadline `
                    -ReadInspectionReport -ReadLoginProgress -CursorState $cursorState
                $publicReport = Invoke-AtlasoBoundedProcess -FilePath $InspectionPythonPath `
                    -ArgumentList ($inspectionArguments + @('validate', '--expected', $encodedExpectations, '--report', $encodedReport)) `
                    -TimeoutSeconds 30 -Action 'Installed inspection record validation'
                if ($publicReport.Length -gt 8192) { throw 'Validated installation inspection exceeded its bound.' }
                Write-Host ('Installed public identity and application payload: ' + $publicReport.Trim())
            }
            Send-InstallationConsoleText -Pipe $pipe -Text ('exit' + $accountProbe.EnterKey)
        }
        $verification = & (Join-Path $PSScriptRoot 'test-installation-iso.ps1') -Mode Verify -Worktree $worktree `
            -OutputDirectory $OutputDirectory -PullRequestNumber $PullRequestNumber -CollisionSuffix $CollisionSuffix `
            -OriginalReceiptPath $vm.ReceiptPath -OriginalReceiptSha256 $vm.ReceiptSha256 `
            -BaselineReceiptPath $vm.BaselineReceiptPath -BaselineReceiptSha256 $vm.BaselineReceiptSha256 `
            -BootReceiptPath $boot.BootReceiptPath -BootReceiptSha256 $boot.BootReceiptSha256 -Confirm:$false
        Write-Host ('Post-reboot installation disk verification: ' + ($verification | ConvertTo-Json -Depth 4 -Compress))
    }
}
finally {
    $pipe.Dispose()
    if ($cursorState) { $cursorState.Clear() }
    if ($credentials) { $credentials.AdminPassword.Dispose(); $credentials.RootPassword.Dispose() }
    if ($sourceContext.PSObject.Properties['CheckoutSourcePin'] -and $sourceContext.CheckoutSourcePin) {
        $sourceContext.CheckoutSourcePin.Dispose()
    }
}
