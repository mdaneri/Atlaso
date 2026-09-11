<#
.SYNOPSIS
Manage receipt-bound Workstation LAN segment registrations without adopting existing segments.
.DESCRIPTION
Loaded inside Atlaso.WorkstationCleanup so transactions share its filesystem identity
and recovery primitives. Callers supply independently verified lifecycle ownership.
#>

<#
.SYNOPSIS
Reject an active Workstation UI before changing its cached preferences.
#>
function Assert-AtlasoLanSegmentUiClosed {
    if (Get-Process -Name vmware -ErrorAction SilentlyContinue) {
        throw 'Close the VMware Workstation UI before changing LAN segment registrations; do not terminate it automatically.'
    }
}

<#
.SYNOPSIS
Parse LAN registrations strictly while preserving every original line and terminator.
.PARAMETER Bytes
Exact UTF-8 preferences bytes captured under the transaction lock.
#>
function ConvertFrom-AtlasoLanPreferences {
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
    if ($text.StartsWith([string][char]0xfeff, [StringComparison]::Ordinal)) { throw 'BOM-prefixed LAN preferences require encoding reconciliation.' }
    $lines = @([regex]::Matches($text, '[^\r\n]*(?:\r\n|\n|\r|$)') |
        Where-Object Length -GT 0 | ForEach-Object { $_.Value })
    $entries = @{}
    $count = $null
    foreach ($line in $lines) {
        if ($line -notmatch '^\s*pref\.namedPVNs') { continue }
        if ($line -match '^\s*pref\.namedPVNs\.count\s*=\s*"(0|[1-9][0-9]*)"\s*$') {
            if ($null -ne $count) { throw 'Duplicate LAN segment count; preferences preserved.' }
            $count = [int]$Matches[1]
        } elseif ($line -match '^\s*pref\.namedPVNs(0|[1-9][0-9]*)\.(name|pvnID)\s*=\s*"([^"\r\n]+)"\s*$') {
            $index = [int]$Matches[1]; $key = $Matches[2]; $value = $Matches[3]
            if (-not $entries.ContainsKey($index)) { $entries[$index] = @{} }
            if ($entries[$index].ContainsKey($key)) { throw 'Duplicate LAN segment field; preferences preserved.' }
            $entries[$index][$key] = $value
        } else { throw 'Unsupported LAN segment preferences record; preferences preserved.' }
    }
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($index in $entries.Keys) {
        $entry = $entries[$index]
        if ($entry.Count -ne 2 -or $null -eq $count -or $index -ge $count -or
            -not $names.Add($entry.name) -or -not $ids.Add($entry.pvnID) -or
            $entry.pvnID -notmatch '^[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7}-[0-9a-fA-F]{2}( [0-9a-fA-F]{2}){7}$') {
            throw 'Incomplete or ambiguous LAN segment registration; preferences preserved.'
        }
    }
    return @{ Lines = $lines; Entries = $entries; Count = $count }
}

<#
.SYNOPSIS
Atomically replace exact preferences bytes and verify both displaced and published identities.
.PARAMETER Path
Existing provider preferences file.
.PARAMETER Transform
Action receiving original bytes and returning replacement bytes under write exclusion.
.PARAMETER Validate
Optional live preconditions repeated immediately before and after publication.
#>
function Update-AtlasoLanPreferences {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][scriptblock]$Transform,
        [scriptblock]$Validate)
    Assert-AtlasoLanSegmentUiClosed
    $pins = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $Path), $true)
    $originalLock = $null; $stageLock = $null
    $stage = "$Path.atlaso-lan-$([guid]::NewGuid().ToString('N')).tmp"
    $backup = "$stage.backup"
    $applied = $false
    $displacedIdentity = $null; $displacedBytes = $null
    $stageIdentity = $null
    try {
        Assert-AtlasoPathHasNoReparsePoint -Path $Path
        if (@(Get-ChildItem -LiteralPath (Split-Path -Parent $Path) -Filter "$(Split-Path -Leaf $Path).atlaso-lan-*.tmp.backup" -Force -ErrorAction Stop).Count) {
            throw 'An interrupted LAN preferences transaction needs identity-checked recovery; preserve its backup before retry.'
        }
        # A single-link read pin rejects aliases before the share-delete transaction.
        $filePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Path, $true)
        try { $identity = Get-AtlasoPathIdentity -Path $Path -Description 'LAN preferences' }
        finally { $filePin.Dispose() }
        $originalLock = [System.IO.File]::Open($Path, 'Open', 'Read', ([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
        if ((Get-AtlasoPathIdentity -Path $Path -Description 'LAN preferences') -cne $identity) {
            throw 'LAN preferences identity changed before locking.'
        }
        [byte[]]$original = @(Read-AtlasoStreamBytes -Stream $originalLock)
        if ($original.Length -eq 0) { throw 'Initialize Workstation preferences through normal setup before managing LAN segments.' }
        [byte[]]$replacement = & $Transform $original
        if (Test-AtlasoByteArraysEqual -Left $original -Right $replacement) { return }
        $writer = [System.IO.FileStream]::new($stage, 'CreateNew', 'Write', 'None', 4096, 'WriteThrough')
        try {
            $stageIdentity = Get-AtlasoPathIdentity -Path $stage -Description 'LAN preferences stage'
            $writer.Write($replacement); $writer.Flush($true)
        } finally { $writer.Dispose() }
        Assert-AtlasoLanSegmentUiClosed
        if ($Validate) { & $Validate }
        [System.IO.File]::Replace($stage, $Path, $backup, $true)
        $applied = $true
        $stageLock = [System.IO.File]::Open($Path, 'Open', 'Read', ([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
        # File.Replace is not a compare-and-swap. Inspect what it actually displaced,
        # including file identity, before accepting the operation.
        $displacedIdentity = Get-AtlasoPathIdentity -Path $backup -Description 'Displaced LAN preferences'
        [byte[]]$displacedBytes = [System.IO.File]::ReadAllBytes($backup)
        if ($displacedIdentity -cne $identity -or
            -not (Test-AtlasoByteArraysEqual -Left $original -Right $displacedBytes)) {
            $stageLock.Dispose(); $stageLock = $null
            Restore-AtlasoFileAfterCasFailure -TargetPath $Path -ExpectedCurrentBytes $replacement `
                -ExpectedCurrentIdentity $stageIdentity -ReplacementPath $backup `
                -ReplacementBytes $displacedBytes -ReplacementIdentity $displacedIdentity `
                -Description 'LAN preferences'
            $applied = $false
            throw 'LAN preferences were replaced concurrently; displaced provider state was restored.'
        }
        if ((Get-AtlasoPathIdentity -Path $Path -Description 'Published LAN preferences') -cne $stageIdentity) {
            throw "LAN preferences changed after replacement; recovery copy retained at '$backup'."
        }
        # Hold the published object against writes while verifying its exact bytes.
        # Recheck the UI as well: it must not retain an obsolete in-memory copy.
        if (-not (Test-AtlasoByteArraysEqual -Left $replacement -Right (Read-AtlasoStreamBytes $stageLock))) {
            throw "LAN preferences verification failed; recovery copy retained at '$backup'."
        }
        Assert-AtlasoLanSegmentUiClosed
        if ($Validate) { & $Validate }
        $applied = $false
    } catch {
        $failure = $_
        if ($applied -and $displacedIdentity -and $null -ne $displacedBytes -and
            (Get-AtlasoPathIdentity -Path $Path -Description 'LAN preferences rollback target') -ceq $stageIdentity) {
            if ($stageLock) { $stageLock.Dispose(); $stageLock = $null }
            if ($originalLock) { $originalLock.Dispose(); $originalLock = $null }
            Restore-AtlasoFileAfterCasFailure -TargetPath $Path -ExpectedCurrentBytes $replacement `
                -ExpectedCurrentIdentity $stageIdentity -ReplacementPath $backup `
                -ReplacementBytes $displacedBytes -ReplacementIdentity $displacedIdentity `
                -Description 'LAN preferences'
            $applied = $false
        }
        throw $failure
    } finally {
        if ($stageLock) { $stageLock.Dispose() }
        if ($originalLock) { $originalLock.Dispose() }
        try {
        # A failed rollback retains the displaced bytes for explicit recovery.
        if (-not $applied -and (Test-Path -LiteralPath $backup)) {
            $backupPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($backup, $true, $true)
            try {
                if ((Get-AtlasoPathIdentity -Path $backup -Description 'LAN transaction backup') -cne $identity) {
                    throw 'LAN transaction backup identity changed; preserve it for recovery.'
                }
                [Atlaso.WorkstationFileIdentity]::DeletePinnedFile($backupPin)
            } finally { $backupPin.Dispose() }
        }
        if ($stageIdentity -and (Test-Path -LiteralPath $stage)) {
            $stagePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($stage, $true, $true)
            try {
                if ((Get-AtlasoPathIdentity -Path $stage -Description 'LAN preferences stage') -cne $stageIdentity) {
                    throw 'LAN preferences stage identity changed; preserve it for recovery.'
                }
                [Atlaso.WorkstationFileIdentity]::DeletePinnedFile($stagePin)
            } finally { $stagePin.Dispose() }
        }
        } finally { $pins.Dispose() }
    }
}

<#
.SYNOPSIS
Create a new segment with immutable ownership evidence or reuse a shared segment without claiming it.
.PARAMETER Name
Exact requested LAN segment name.
.PARAMETER Owner
Independent lifecycle owner: task_id, repository, source_commit, pr, and lab_root.
.PARAMETER PreferencesPath
Existing Workstation preferences path, or an isolated provider fixture.
#>
function Resolve-AtlasoOwnedLanSegment {
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$')][string]$Name,
        [Parameter(Mandatory)][hashtable]$Owner,
        [string]$PreferencesPath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'VMware\preferences.ini')
    )
    foreach ($field in @('task_id', 'repository', 'source_commit', 'pr', 'lab_root')) {
        if (-not $Owner.ContainsKey($field) -or -not $Owner[$field]) { throw "Missing LAN segment owner field: $field." }
    }
    if ([int]$Owner.pr -le 0 -or $Owner.source_commit -notmatch '^[0-9a-f]{40}$') { throw 'Invalid LAN segment source ownership.' }
    $receiptRoot = Join-Path $Owner.lab_root 'lan-segments'
    $labPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($Owner.lab_root, $true)
    $receiptPin = $null
    try {
        [System.IO.Directory]::CreateDirectory($receiptRoot) | Out-Null
        $receiptPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($receiptRoot, $true)
        $result = @{ Id = ''; ReceiptPath = ''; ReceiptSha256 = '' }
        Update-AtlasoLanPreferences -Path $PreferencesPath -Transform {
            param($original)
            $parsed = ConvertFrom-AtlasoLanPreferences -Bytes $original
            foreach ($entry in $parsed.Entries.Values) {
                if ($entry.name -ieq $Name) { $result.Id = $entry.pvnID; return ,$original }
            }
            $idBytes = [guid]::NewGuid().ToByteArray(); $idBytes[0] = 0x52
            $id = (($idBytes[0..7] | ForEach-Object { $_.ToString('x2') }) -join ' ') + '-' +
                (($idBytes[8..15] | ForEach-Object { $_.ToString('x2') }) -join ' ')
            $index = if ($null -eq $parsed.Count) { 0 } else { $parsed.Count }
            $receipt = $Owner.Clone()
            $receipt.schema = 1; $receipt.name = $Name; $receipt.pvn_id = $id
            $receipt.preferences_path = [System.IO.Path]::GetFullPath($PreferencesPath)
            $receipt.creation_id = [guid]::NewGuid().ToString('N')
            # Publish intent before registration. The immutable receipt records that this
            # exact random identity was absent under the provider lock, never a name claim.
            $receiptPath = Join-Path $receiptRoot "$($receipt.creation_id).json"
            $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($receipt | ConvertTo-Json))
            $writer = [System.IO.FileStream]::new($receiptPath, 'CreateNew', 'Write', 'None', 4096, 'WriteThrough')
            try { $writer.Write($bytes); $writer.Flush($true) } finally { $writer.Dispose() }
            $result.ReceiptPath = $receiptPath
            $result.ReceiptSha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes))
            $lines = @($parsed.Lines | Where-Object { $_ -notmatch '^\s*pref\.namedPVNs\.count\s*=' })
            $text = $lines -join ''
            if ($text -and $text -notmatch '[\r\n]$') { $text += "`r`n" }
            $text += "pref.namedPVNs$index.name = `"$Name`"`r`npref.namedPVNs$index.pvnID = `"$id`"`r`npref.namedPVNs.count = `"$($index + 1)`"`r`n"
            $result.Id = $id
            return ,([System.Text.UTF8Encoding]::new($false).GetBytes($text))
        }
        return [pscustomobject]$result
    } finally {
        if ($receiptPin) { $receiptPin.Dispose() }
        $labPin.Dispose()
    }
}

<#
.SYNOPSIS
Pin every registered and explicitly scoped VMX and reject surviving segment references.
.PARAMETER InventoryPath
Existing Workstation inventory to inspect under a read pin.
.PARAMETER VmRoots
Independently configured complete VM roots, including unregistered lifecycle outputs.
.PARAMETER SegmentId
Exact segment identifier being released.
.PARAMETER Pins
Disposable handles retained by the caller through preferences publication.
#>
function Assert-AtlasoLanSegmentUnreferenced {
    param([Parameter(Mandatory)][string]$InventoryPath,
        [Parameter(Mandatory)][string[]]$VmRoots,
        [Parameter(Mandatory)][string]$SegmentId,
        [Parameter(Mandatory)][System.Collections.Generic.List[System.IDisposable]]$Pins)
    if (Get-Process -Name vmware-vmx, vmrun -ErrorAction SilentlyContinue) {
        throw 'Stop VMware VM and vmrun activity before LAN segment cleanup; provider state preserved.'
    }
    $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $InventoryPath), $true))
    $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($InventoryPath, $true))
    $paths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in [System.IO.File]::ReadAllLines($InventoryPath)) {
        if ($line -notmatch '^\s*(vmlist\d+\.config|index\d+\.id)\s*=') { continue }
        if ($line -notmatch '^\s*(?:vmlist\d+\.config|index\d+\.id)\s*=\s*"([^"\r\n]+)"\s*$' -or
            -not [System.IO.Path]::IsPathFullyQualified($Matches[1])) {
            throw 'Cannot prove LAN segment reference absence from malformed Workstation inventory.'
        }
        $path = [System.IO.Path]::GetFullPath($Matches[1])
        # Missing library entries do not own a surviving adapter. Pin their parent
        # below when it exists; inaccessible paths fail rather than becoming absence.
        $paths.Add($path) | Out-Null
    }
    foreach ($root in $VmRoots) {
        $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($root, $true))
        foreach ($item in Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop) {
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw 'VM search root contains a reparse point; LAN segment cleanup refused.'
            }
            if (-not $item.PSIsContainer -and $item.Extension -ieq '.vmx') { $paths.Add($item.FullName) | Out-Null }
        }
    }
    foreach ($path in $paths) {
        Assert-AtlasoPathHasNoReparsePoint -Path $path
        if (-not [System.IO.File]::Exists($path)) {
            if (-not [System.IO.Directory]::Exists((Split-Path -Parent $path))) {
                throw 'A registered VM directory is unavailable; reconcile its inventory before LAN segment cleanup.'
            }
            continue
        }
        $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $path), $true))
        $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true))
        foreach ($line in [System.IO.File]::ReadAllLines($path)) {
            if ($line -notmatch '^\s*ethernet\d+\.pvnID\s*=') { continue }
            if ($line -notmatch '^\s*ethernet\d+\.pvnID\s*=\s*"([^"\r\n]+)"\s*$') {
                throw 'Malformed VM adapter segment reference; cleanup refused.'
            }
            if ($Matches[1] -ieq $SegmentId) { throw "LAN segment is still referenced by VMX '$path'." }
        }
    }
}

<#
.SYNOPSIS
Remove one receipt-bound unreferenced LAN registration and return independently checked absence evidence.
.PARAMETER ReceiptPath
Immutable creation receipt retained by the lifecycle run.
.PARAMETER ReceiptSha256
Creation receipt digest independently recorded by the originating task or controller.
.PARAMETER Owner
Independently verified lifecycle task, repository, commit, PR and lab root.
.PARAMETER VmRoots
Independently configured VM roots to search in addition to all Workstation inventory entries.
.PARAMETER PreferencesPath
Exact provider preferences path, never selected from an untrusted receipt.
.PARAMETER InventoryPath
Exact provider inventory path, never selected from an untrusted receipt.
#>
function Remove-AtlasoWorkstationLanSegment {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$ReceiptPath,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ReceiptSha256,
        [Parameter(Mandatory)][hashtable]$Owner,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$VmRoots,
        [string]$PreferencesPath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'VMware\preferences.ini'),
        [string]$InventoryPath = (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'VMware\inventory.vmls'))
    $pins = [System.Collections.Generic.List[System.IDisposable]]::new()
    try {
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $ReceiptPath), $true))
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($ReceiptPath, $true))
        if ((Get-FileHash -LiteralPath $ReceiptPath -Algorithm SHA256).Hash -ine $ReceiptSha256) { throw 'LAN creation receipt digest mismatch.' }
        $receipt = [System.IO.File]::ReadAllText($ReceiptPath) | ConvertFrom-Json -AsHashtable
        foreach ($field in @('task_id', 'repository', 'source_commit', 'pr', 'lab_root')) {
            if (-not $Owner.ContainsKey($field) -or -not $Owner[$field] -or $receipt[$field] -cne $Owner[$field]) {
                throw "LAN creation receipt owner mismatch: $field."
            }
        }
        if ($receipt.schema -ne 1 -or [int]$Owner.pr -le 0 -or $Owner.source_commit -notmatch '^[0-9a-f]{40}$' -or
            $receipt.creation_id -notmatch '^[0-9a-f]{32}$' -or
            $receipt.pvn_id -notmatch '^52( [0-9a-f]{2}){7}-[0-9a-f]{2}( [0-9a-f]{2}){7}$' -or
            -not (Test-AtlasoSamePath -Left $receipt.preferences_path -Right $PreferencesPath)) {
            throw 'LAN creation receipt identity is invalid.'
        }
        Assert-AtlasoLanSegmentUiClosed
        Assert-AtlasoLanSegmentUnreferenced -InventoryPath $InventoryPath -VmRoots $VmRoots -SegmentId $receipt.pvn_id -Pins $pins
        $changed = @{ Value = $false; Declined = $false }
        Update-AtlasoLanPreferences -Path $PreferencesPath -Validate {
            Assert-AtlasoLanSegmentUnreferenced -InventoryPath $InventoryPath -VmRoots $VmRoots -SegmentId $receipt.pvn_id -Pins $pins
        } -Transform {
            param($original)
            $parsed = ConvertFrom-AtlasoLanPreferences -Bytes $original
            $selected = @($parsed.Entries.Keys | Where-Object {
                $parsed.Entries[$_].name -ieq $receipt.name -or $parsed.Entries[$_].pvnID -ieq $receipt.pvn_id
            })
            if ($selected.Count -eq 0) { return ,$original }
            if ($selected.Count -ne 1 -or $parsed.Entries[$selected[0]].name -cne $receipt.name -or
                $parsed.Entries[$selected[0]].pvnID -cne $receipt.pvn_id) { throw 'LAN registration identity drift; preferences preserved.' }
            if (-not $PSCmdlet.ShouldProcess($receipt.name, 'Remove exact owned LAN segment registration')) {
                $changed.Declined = $true
                return ,$original
            }
            $index = $selected[0]
            $lines = @($parsed.Lines | Where-Object { $_ -notmatch "^\s*pref\.namedPVNs$index\." })
            # Keep the provider high-water count and every other byte intact: sparse
            # indices remain valid and another segment is never renumbered or rewritten.
            $changed.Value = $true
            return ,([System.Text.UTF8Encoding]::new($false).GetBytes(($lines -join '')))
        }
        if ($WhatIfPreference -or $changed.Declined) { return }
        # Fresh parse, reference inspection and UI check are separate from mutation.
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $PreferencesPath), $true))
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($PreferencesPath, $true))
        $parsed = ConvertFrom-AtlasoLanPreferences -Bytes ([System.IO.File]::ReadAllBytes($PreferencesPath))
        if (@($parsed.Entries.Values | Where-Object { $_.pvnID -ieq $receipt.pvn_id -or $_.name -ieq $receipt.name }).Count) {
            throw 'LAN segment registration absence was not verified.'
        }
        Assert-AtlasoLanSegmentUiClosed
        Assert-AtlasoLanSegmentUnreferenced -InventoryPath $InventoryPath -VmRoots $VmRoots -SegmentId $receipt.pvn_id -Pins $pins
        return [pscustomobject]@{ schema = 1; task_id = $Owner.task_id; pr = $Owner.pr
            provider_id = $receipt.pvn_id; name = $receipt.name; receipt_sha256 = $ReceiptSha256
            registration_absent = $true; adapter_references_absent = $true; changed = $changed.Value }
    } finally {
        for ($index = $pins.Count - 1; $index -ge 0; $index--) { $pins[$index].Dispose() }
    }
}
