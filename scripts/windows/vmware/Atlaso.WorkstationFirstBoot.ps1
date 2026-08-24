<#
.SYNOPSIS
Build and install Atlaso VMware Workstation first-boot metadata.

.DESCRIPTION
Provides the shared raw-VMX first-boot contract used by the normal Workstation
test-VM wrapper and the lifecycle runner. The helper validates deployment inputs,
serializes an OVF environment safely, and writes only the exact guestinfo entry.

The optional development administrator public key is accepted only as one canonical
Ed25519 OpenSSH key. Callers decide whether to include it; lifecycle and export paths
omit it.
#>

<#
.SYNOPSIS
Escape one value for an OVF XML attribute.

.PARAMETER Value
The possibly empty value to encode.
#>
function ConvertTo-AtlasoOvfXmlValue {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    return [System.Security.SecurityElement]::Escape($Value)
}

<#
.SYNOPSIS
Quote one string for a VMX assignment.

.PARAMETER Value
The unquoted VMX value.
#>
function ConvertTo-AtlasoVmxString {
    param([string]$Value)

    return '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

<#
.SYNOPSIS
Validate and normalize one OpenSSH Ed25519 public key.

.DESCRIPTION
Checks the bounded single-line text form, canonical base64, embedded SSH algorithm,
and exact 32-byte Ed25519 public-key payload. The private key is never accessed.

.PARAMETER PublicKey
The OpenSSH public-key line to validate.
#>
function Assert-AtlasoWorkstationEd25519PublicKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PublicKey
    )

    $key = $PublicKey
    # Public-key files conventionally end with one newline. Remove only that final
    # terminator so an embedded or repeated newline still fails closed below.
    if ($key.EndsWith("`r`n", [System.StringComparison]::Ordinal)) {
        $key = $key.Substring(0, $key.Length - 2)
    }
    elseif ($key.EndsWith("`n", [System.StringComparison]::Ordinal)) {
        $key = $key.Substring(0, $key.Length - 1)
    }
    $key = $key.Trim('"')
    if (
        [string]::IsNullOrWhiteSpace($key) -or
        $key.Length -gt 4096 -or
        $key -ne $key.Trim() -or
        $key -match '[\x00-\x1F\x7F]'
    ) {
        throw 'The SSH public key must be one bounded, non-empty OpenSSH line without surrounding whitespace or control characters.'
    }

    $parts = @($key -split ' +', 3)
    if ($parts.Count -lt 2 -or $parts[0] -ne 'ssh-ed25519') {
        throw 'The SSH public key must use the ssh-ed25519 algorithm.'
    }
    try {
        $blob = [System.Convert]::FromBase64String($parts[1])
    }
    catch {
        throw 'The SSH public key payload is not valid base64.'
    }
    if ([System.Convert]::ToBase64String($blob) -ne $parts[1] -or $blob.Length -ne 51) {
        throw 'The SSH public key payload is not a canonical Ed25519 OpenSSH key.'
    }

    <#
    .SYNOPSIS
    Read one big-endian length from an SSH wire-format blob.

    .PARAMETER Bytes
    The complete decoded SSH public-key blob.

    .PARAMETER Offset
    The zero-based position of the four-byte length.
    #>
    function Read-AtlasoSshBlobLength {
        param(
            [Parameter(Mandatory = $true)][byte[]]$Bytes,
            [Parameter(Mandatory = $true)][int]$Offset
        )

        if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) {
            throw 'The SSH public key payload is truncated.'
        }
        return [int](
            ([uint64]$Bytes[$Offset] * 16777216) +
            ([uint64]$Bytes[$Offset + 1] * 65536) +
            ([uint64]$Bytes[$Offset + 2] * 256) +
            [uint64]$Bytes[$Offset + 3]
        )
    }

    # Decode the wire format as well as the visible prefix so a mislabeled base64
    # payload cannot gain test-VM authorization.
    $algorithmLength = Read-AtlasoSshBlobLength -Bytes $blob -Offset 0
    if ($algorithmLength -ne 11 -or 4 + $algorithmLength + 4 -gt $blob.Length) {
        throw 'The SSH public key payload does not contain an Ed25519 algorithm identifier.'
    }
    $algorithm = [System.Text.Encoding]::ASCII.GetString($blob, 4, $algorithmLength)
    $publicKeyLengthOffset = 4 + $algorithmLength
    $publicKeyLength = Read-AtlasoSshBlobLength -Bytes $blob -Offset $publicKeyLengthOffset
    if (
        $algorithm -ne 'ssh-ed25519' -or
        $publicKeyLength -ne 32 -or
        $publicKeyLengthOffset + 4 + $publicKeyLength -ne $blob.Length
    ) {
        throw 'The SSH public key payload does not contain one complete Ed25519 public key.'
    }

    $normalized = "ssh-ed25519 $($parts[1])"
    if ($parts.Count -eq 3 -and $parts[2]) {
        $normalized += " $($parts[2])"
    }
    try {
        [void][System.Xml.XmlConvert]::VerifyXmlChars($normalized)
    }
    catch {
        throw 'The SSH public key contains characters that cannot be represented in the OVF environment.'
    }
    return $normalized
}

<#
.SYNOPSIS
Resolve the existing host public key used by the normal Workstation test VM.

.DESCRIPTION
Uses an explicit path when supplied; otherwise selects the current Windows user's
.ssh/id_ed25519.pub. This function validates only an existing public key and never
generates, reads, or copies a private key.

.PARAMETER Path
Optional path to an existing Ed25519 OpenSSH public-key file.
#>
function Resolve-AtlasoWorkstationAdminSshPublicKey {
    param([string]$Path = '')

    $resolvedPath = $Path
    if (-not $resolvedPath) {
        $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        if ([string]::IsNullOrWhiteSpace($userProfile)) {
            throw 'The current Windows user profile could not be resolved. Pass -SshPublicKeyPath or -SkipSshKeyProvisioning.'
        }
        # A deterministic file default lets every local coding task under the same
        # Windows user share the identity without agent-key ambiguity.
        $resolvedPath = Join-Path $userProfile '.ssh\id_ed25519.pub'
    }
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        throw "SSH public key not found: $resolvedPath. Create the existing key outside this script, pass -SshPublicKeyPath, or pass -SkipSshKeyProvisioning."
    }
    $fullPath = (Resolve-Path -LiteralPath $resolvedPath).Path
    $publicKey = Assert-AtlasoWorkstationEd25519PublicKey -PublicKey ([System.IO.File]::ReadAllText($fullPath))
    return [pscustomobject]@{
        Path      = $fullPath
        PublicKey = $publicKey
    }
}

<#
.SYNOPSIS
Normalize and fingerprint one verified Ed25519 SSH host public key.

.PARAMETER PublicKey
The host-derived OpenSSH public-key line.
#>
function ConvertTo-AtlasoWorkstationSshHostKeyEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$PublicKey
    )

    $normalized = Assert-AtlasoWorkstationEd25519PublicKey -PublicKey $PublicKey
    $parts = @($normalized -split ' +', 3)
    $hostPublicKey = "ssh-ed25519 $($parts[1])"
    $blob = [System.Convert]::FromBase64String($parts[1])
    $digest = [System.Security.Cryptography.SHA256]::HashData($blob)
    $fingerprint = 'SHA256:' + [System.Convert]::ToBase64String($digest).TrimEnd('=')
    return [pscustomobject]@{
        PublicKey   = $hostPublicKey
        Fingerprint = $fingerprint
    }
}

<#
.SYNOPSIS
Read and fingerprint the normal test VM's verified Ed25519 SSH host key.

.DESCRIPTION
Polls the test-only VMware runtime guest-info value written during first boot.
The value comes through the host-controlled VM channel rather than an
unauthenticated network scan.

.PARAMETER VmxPath
The exact running test VMX path.

.PARAMETER VmrunPath
Optional VMware vmrun executable override.

.PARAMETER TimeoutSeconds
The total time allowed for first boot to publish the host key.

.PARAMETER PollSeconds
The delay between empty guest-info reads.
#>
function Get-AtlasoWorkstationSshHostKey {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [string]$VmrunPath = '',
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$PollSeconds = 2
    )

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $resolvedVmrunPath = $VmrunPath
    if ($resolvedVmrunPath) {
        if (-not (Test-Path -LiteralPath $resolvedVmrunPath -PathType Leaf)) {
            throw "vmrun.exe not found: $resolvedVmrunPath"
        }
        $resolvedVmrunPath = (Resolve-Path -LiteralPath $resolvedVmrunPath).Path
    }
    else {
        $vmrunCommand = Get-Command vmrun -ErrorAction SilentlyContinue
        foreach ($candidate in @(
                'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
                'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
            )) {
            if (-not $resolvedVmrunPath -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                $resolvedVmrunPath = $candidate
            }
        }
        if (-not $resolvedVmrunPath -and $vmrunCommand) {
            $resolvedVmrunPath = $vmrunCommand.Source
        }
        if (-not $resolvedVmrunPath) {
            throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
        }
    }

    $guestInfoName = 'guestinfo.atlaso.test_vm_ssh_host_ed25519_public_key'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $value = (& $resolvedVmrunPath -T ws readVariable $resolvedVmxPath runtimeConfig $guestInfoName 2>$null |
            Select-Object -First 1)
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($value)) {
            return ConvertTo-AtlasoWorkstationSshHostKeyEvidence -PublicKey $value
        }
        if ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $PollSeconds
        }
    } while ((Get-Date) -lt $deadline)

    throw "Timed out after $TimeoutSeconds seconds waiting for the verified test VM SSH host key. Confirm first-boot customization and VMware Tools are healthy."
}

<#
.SYNOPSIS
Derive a valid development FQDN from a Workstation VM name.

.PARAMETER Name
The requested Workstation VM display name.
#>
function New-AtlasoWorkstationFqdn {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $label = ($Name.Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '-' -replace '-+', '-').Trim('-')
    if (-not $label) {
        $label = 'appliance'
    }
    if ($label.Length -gt 63) {
        $label = $label.Substring(0, 63).TrimEnd('-')
    }
    return "$label.atlaso.internal"
}

<#
.SYNOPSIS
Create the complete raw-clone OVF environment for Atlaso first boot.

.PARAMETER Fqdn
The appliance fully qualified domain name.

.PARAMETER AdminPassword
The initial Atlaso and Photon bootstrap administrator password.

.PARAMETER RootPassword
The Photon root console password.

.PARAMETER RootSshEnabled
Whether first boot enables password-backed root SSH.

.PARAMETER DevelopmentAdminSshPublicKey
Optional validated public key used only by the normal development test wrapper.
#>
function New-AtlasoWorkstationOvfEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fqdn,

        [Parameter(Mandatory = $true)]
        [string]$AdminPassword,

        [Parameter(Mandatory = $true)]
        [string]$RootPassword,

        [switch]$RootSshEnabled,

        [AllowEmptyString()]
        [string]$DevelopmentAdminSshPublicKey = ''
    )

    foreach ($passwordInput in @(
            @{ Name = 'AdminPassword'; Value = $AdminPassword },
            @{ Name = 'RootPassword'; Value = $RootPassword }
        )) {
        try {
            [void][System.Xml.XmlConvert]::VerifyXmlChars($passwordInput.Value)
        }
        catch {
            throw "$($passwordInput.Name) contains characters that cannot be represented in the OVF environment."
        }
        if ($passwordInput.Value -ne $passwordInput.Value.Trim() -or $passwordInput.Value -match '[\r\n\t]') {
            throw "$($passwordInput.Name) cannot contain leading, trailing, or XML-normalized control whitespace."
        }
        if ($passwordInput.Value.Length -lt 12) {
            throw "$($passwordInput.Name) must contain at least 12 characters for Atlaso first-boot customization."
        }
    }
    if ($Fqdn -notmatch '^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$') {
        throw "First-boot FQDN is invalid: $Fqdn"
    }
    if ($Fqdn.TrimEnd('.').ToLowerInvariant().EndsWith('.local')) {
        throw 'First-boot FQDN must not use .local.'
    }

    if ($DevelopmentAdminSshPublicKey) {
        # Revalidate at the serialization boundary so another caller cannot bypass
        # the test-wrapper resolver and inject arbitrary authorized_keys content.
        $DevelopmentAdminSshPublicKey = Assert-AtlasoWorkstationEd25519PublicKey -PublicKey $DevelopmentAdminSshPublicKey
    }

    $properties = [ordered]@{
        'atlaso.deployment_id'    = [guid]::NewGuid().ToString('D')
        'atlaso.management_mode'  = 'dhcp'
        'atlaso.cidr'             = ''
        'atlaso.gateway'          = ''
        'atlaso.ipv6_enabled'     = 'false'
        'atlaso.ipv6_cidr'        = ''
        'atlaso.ipv6_gateway'     = ''
        'atlaso.dns_servers'      = ''
        'atlaso.fqdn'             = $Fqdn
        'atlaso.admin_password'   = $AdminPassword
        'atlaso.root_password'    = $RootPassword
        'atlaso.root_ssh_enabled' = $RootSshEnabled.IsPresent.ToString().ToLowerInvariant()
    }
    if ($DevelopmentAdminSshPublicKey) {
        $properties['atlaso.development_admin_ssh_public_key'] = $DevelopmentAdminSshPublicKey
    }
    $propertyXml = foreach ($entry in $properties.GetEnumerator()) {
        $key = ConvertTo-AtlasoOvfXmlValue -Value $entry.Key
        $value = ConvertTo-AtlasoOvfXmlValue -Value $entry.Value
        "<Property oe:key='$key' oe:value='$value'/>"
    }
    return "<Environment xmlns='http://schemas.dmtf.org/ovf/environment/1' xmlns:oe='http://schemas.dmtf.org/ovf/environment/1' oe:id='vm'><PlatformSection><Kind>VMware Workstation</Kind><Version>17</Version><Vendor>VMware, Inc.</Vendor><Locale>en</Locale></PlatformSection><PropertySection>$($propertyXml -join '')</PropertySection></Environment>"
}

<#
.SYNOPSIS
Replace the exact guestinfo.ovfEnv assignment in a VMX file.

.PARAMETER VmxPath
The VMX file to update before power-on.

.PARAMETER OvfEnvironment
The complete validated OVF environment XML.
#>
function Set-AtlasoWorkstationOvfEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmxPath,

        [Parameter(Mandatory = $true)]
        [string]$OvfEnvironment
    )

    $line = "guestinfo.ovfEnv = " + (ConvertTo-AtlasoVmxString -Value $OvfEnvironment)
    $content = @(Get-Content -LiteralPath $VmxPath)
    $pattern = '^\s*guestinfo\.ovfEnv\s*='
    $updated = $false
    $content = @($content | ForEach-Object {
            if ($_ -match $pattern) {
                if (-not $updated) {
                    $line
                    $updated = $true
                }
            }
            else {
                $_
            }
        })
    if (-not $updated) {
        $content += $line
    }
    [System.IO.File]::WriteAllLines($VmxPath, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}
