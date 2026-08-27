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
Run one external process with a deadline and whole-tree termination.

.PARAMETER FilePath
Exact executable to start without shell interpretation.

.PARAMETER ArgumentList
Individual process arguments added without command-line interpolation.

.PARAMETER TimeoutSeconds
Positive deadline for the external process.

.PARAMETER Action
Safe action description used in failure messages.
#>
function Invoke-AtlasoBoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][ValidateRange(1, 86400)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$Action
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $ArgumentList) {
        $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "$Action could not be started."
        }
        # Drain both streams asynchronously so a verbose child cannot block
        # before the bounded wait has an opportunity to terminate its tree.
        $standardOutput = $process.StandardOutput.ReadToEndAsync()
        $standardError = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try {
                $process.Kill($true)
                if (-not $process.WaitForExit(10000)) {
                    throw 'The process remained active after whole-tree termination.'
                }
            }
            catch {
                $terminationFailure = [System.TimeoutException]::new(
                    "$Action exceeded its deadline and whole-process-tree cleanup could not be proven.",
                    $_.Exception
                )
                $terminationFailure.Data['AtlasoProcessTreeTerminationUnproven'] = $true
                throw $terminationFailure
            }
            throw "$Action exceeded its $TimeoutSeconds-second deadline."
        }
        $output = $standardOutput.GetAwaiter().GetResult()
        $null = $standardError.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "$Action failed with exit code $($process.ExitCode)."
        }
        return $output
    }
    finally {
        $process.Dispose()
    }
}

<#
.SYNOPSIS
Run one vmrun operation through the bounded process boundary.

.PARAMETER VmrunPath
Exact vmrun executable, or a focused-test function seam.

.PARAMETER ArgumentList
Individual vmrun arguments.

.PARAMETER TimeoutSeconds
Positive per-operation deadline.

.PARAMETER Action
Safe action description used in failure messages.
#>
function Invoke-AtlasoBoundedVmrun {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$Action
    )

    $command = Get-Command $VmrunPath -ErrorAction SilentlyContinue
    if ($command -and $command.CommandType -eq [System.Management.Automation.CommandTypes]::Function) {
        $output = @(& $VmrunPath @ArgumentList)
        if ($LASTEXITCODE -ne 0) {
            throw "$Action failed."
        }
        return ($output -join [Environment]::NewLine)
    }
    return Invoke-AtlasoBoundedProcess `
        -FilePath $VmrunPath `
        -ArgumentList $ArgumentList `
        -TimeoutSeconds $TimeoutSeconds `
        -Action $Action
}

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
Unquoted VMX property text to escape and surround with quotes.
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
        $remainingSeconds = [Math]::Max(1, [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
        $value = Invoke-AtlasoBoundedVmrun `
            -VmrunPath $resolvedVmrunPath `
            -ArgumentList @('-T', 'ws', 'readVariable', $resolvedVmxPath, 'runtimeConfig', $guestInfoName) `
            -TimeoutSeconds $remainingSeconds `
            -Action 'Read the normal test VM SSH host key guest-info value'
        if (-not [string]::IsNullOrWhiteSpace($value)) {
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

.PARAMETER NormalTestVm
Mark this raw clone as a normal test VM whose actual hostname may be published.

.PARAMETER DevelopmentRootCaCertificatePem
Optional public development root certificate used only by the normal test wrapper.
#>
function New-AtlasoWorkstationOvfEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fqdn,

        [Parameter(Mandatory = $true)]
        [SecureString]$AdminPassword,

        [Parameter(Mandatory = $true)]
        [SecureString]$RootPassword,

        [switch]$RootSshEnabled,

        [switch]$NormalTestVm,

        [AllowEmptyString()]
        [string]$DevelopmentAdminSshPublicKey = '',

        [AllowEmptyString()]
        [string]$DevelopmentRootCaCertificatePem = ''
    )

    # OVF properties are XML strings, so unwrap only inside the serializer that
    # validates and emits them; callers retain SecureString boundaries.
    $adminPasswordText = ConvertFrom-SecureString -SecureString $AdminPassword -AsPlainText
    $rootPasswordText = ConvertFrom-SecureString -SecureString $RootPassword -AsPlainText

    foreach ($passwordInput in @(
            @{ Name = 'AdminPassword'; Value = $adminPasswordText },
            @{ Name = 'RootPassword'; Value = $rootPasswordText }
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
        'atlaso.admin_password'   = $adminPasswordText
        'atlaso.root_password'    = $rootPasswordText
        'atlaso.root_ssh_enabled' = $RootSshEnabled.IsPresent.ToString().ToLowerInvariant()
    }
    if ($NormalTestVm) {
        # Keep the non-secret hostname publication decision independent of optional
        # SSH key provisioning while excluding lifecycle and exported appliances.
        $properties['atlaso.normal_test_vm'] = 'true'
    }
    if ($DevelopmentAdminSshPublicKey) {
        $properties['atlaso.development_admin_ssh_public_key'] = $DevelopmentAdminSshPublicKey
    }
    if ($DevelopmentRootCaCertificatePem) {
        # This internal marker is emitted only by the normal test wrapper. It
        # keeps shared-CA eligibility independent from optional SSH-key setup.
        $properties['atlaso.development_test_vm'] = 'true'
        $properties['atlaso.development_root_ca_certificate'] = [Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes($DevelopmentRootCaCertificatePem)
        )
    }
    $propertyXml = foreach ($entry in $properties.GetEnumerator()) {
        $key = ConvertTo-AtlasoOvfXmlValue -Value $entry.Key
        $value = ConvertTo-AtlasoOvfXmlValue -Value $entry.Value
        "<Property oe:key='$key' oe:value='$value'/>"
    }
    $environmentXml = "<Environment xmlns='http://schemas.dmtf.org/ovf/environment/1' xmlns:oe='http://schemas.dmtf.org/ovf/environment/1' oe:id='vm'><PlatformSection><Kind>VMware Workstation</Kind><Version>17</Version><Vendor>VMware, Inc.</Vendor><Locale>en</Locale></PlatformSection><PropertySection>$($propertyXml -join '')</PropertySection></Environment>"
    $adminPasswordText = $null
    $rootPasswordText = $null
    return $environmentXml
}

<#
.SYNOPSIS
Validate the checked-in development root certificate and matching private key.

.DESCRIPTION
Validates the development-only trust anchor before any normal test VM mutation.
The private key is accepted only in memory and is never written by this helper.

.PARAMETER CertificatePath
Exact path to the checked-in public development root certificate.

.PARAMETER PrivateKeyPem
Private-key PEM supplied by the bounded 1Password Environment child.
#>
function Assert-AtlasoDevelopmentRootCaMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPem
    )

    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        throw "Atlaso development root certificate not found: $CertificatePath"
    }
    $normalizedPrivateKeyPem = $PrivateKeyPem.Replace("`r`n", "`n").Replace("`r", "`n")
    $privateKeyPattern = '\A-----BEGIN (?<label>(?:RSA )?PRIVATE KEY)-----\n' +
        '(?<body>[A-Za-z0-9+/=]+(?:\n[A-Za-z0-9+/=]+)*)\n' +
        '-----END \k<label>-----(?:\n)?\z'
    if (
        $PrivateKeyPem.Length -gt 16384 -or
        -not [System.Text.RegularExpressions.Regex]::IsMatch(
            $normalizedPrivateKeyPem,
            $privateKeyPattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
    ) {
        throw 'ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY is absent or is not one bounded PEM private key.'
    }
    $certificatePem = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $CertificatePath).Path)
    try {
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(
            $certificatePem,
            $PrivateKeyPem
        )
    }
    catch {
        throw 'The Atlaso development root certificate and 1Password private key do not match.'
    }
    try {
        if (-not $certificate.HasPrivateKey -or $certificate.Subject -ne $certificate.Issuer) {
            throw 'The Atlaso development root certificate must be self-signed and match its private key.'
        }
        $commonName = $certificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
        if ($commonName -ne 'Atlaso Development Root CA') {
            throw 'The checked-in certificate is not the Atlaso Development Root CA.'
        }
        if ($certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
            throw 'The Atlaso development root certificate is not currently valid.'
        }
        if ($certificate.SignatureAlgorithm.Value -ne '1.2.840.113549.1.1.11') {
            throw 'The Atlaso development root certificate must use RSA with SHA-256.'
        }
        $basicConstraints = @($certificate.Extensions | Where-Object {
                $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
            }) | Select-Object -First 1
        $keyUsage = @($certificate.Extensions | Where-Object {
                $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]
            }) | Select-Object -First 1
        $requiredUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        if (-not $basicConstraints -or -not $basicConstraints.CertificateAuthority -or
            -not $keyUsage -or ($keyUsage.KeyUsages -band $requiredUsage) -ne $requiredUsage) {
            throw 'The Atlaso development root certificate is not CA-capable.'
        }
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(
            $certificate
        )
        if (-not $rsa -or $rsa.KeySize -ne 4096) {
            throw 'The Atlaso development root certificate must use a 4096-bit RSA key.'
        }
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            $chain.ChainPolicy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
            [void]$chain.ChainPolicy.CustomTrustStore.Add($certificate)
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            if (-not $chain.Build($certificate)) {
                throw 'The Atlaso development root certificate signature could not be verified.'
            }
        }
        finally {
            $chain.Dispose()
        }
    }
    finally {
        if ($rsa) {
            $rsa.Dispose()
        }
        $certificate.Dispose()
    }
}

<#
.SYNOPSIS
Atomically replace one VMX with write-through durability.

.PARAMETER VmxPath
Exact powered-off VMX to replace.

.PARAMETER Lines
Complete validated VMX lines to publish.
#>
function Write-AtlasoWorkstationDurableVmxLines {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines
    )

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $temporaryPath = "$resolvedVmxPath.$([guid]::NewGuid().ToString('N')).tmp"
    if (-not ('Atlaso.WorkstationDurableFile' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Atlaso
{
    public static class WorkstationDurableFile
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveFileEx(string existingPath, string newPath, uint flags);
    }
}
'@
    }
    try {
        $stream = [System.IO.FileStream]::new(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        try {
            $writer = [System.IO.StreamWriter]::new(
                $stream,
                [System.Text.UTF8Encoding]::new($false),
                4096,
                $true
            )
            try {
                foreach ($line in $Lines) {
                    $writer.WriteLine($line)
                }
                $writer.Flush()
                $stream.Flush($true)
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }
        # MOVEFILE_REPLACE_EXISTING plus MOVEFILE_WRITE_THROUGH binds the
        # durable phase transition to bytes already published at the VMX path.
        if (-not [Atlaso.WorkstationDurableFile]::MoveFileEx(
                $temporaryPath,
                $resolvedVmxPath,
                0x1 -bor 0x8
            )) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "The powered-off VMX durable replacement failed with Windows error $errorCode."
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
Stage the development root private key in one powered-off normal test VM.

.PARAMETER VmxPath
Exact VMX path owned by the current normal test VM invocation.

.PARAMETER PrivateKeyPem
Validated development root private-key PEM held only by the bounded child.
#>
function Set-AtlasoWorkstationDevelopmentRootCaPrivateKey {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPem
    )

    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($PrivateKeyPem))
    if ($encoded.Length -gt 16384) {
        throw 'The encoded Atlaso development root private key exceeds the bounded guest-info size.'
    }
    $guestInfoName = 'guestinfo.atlaso.test_vm_development_root_ca_private_key'
    $line = "$guestInfoName = " + (ConvertTo-AtlasoVmxString -Value $encoded)
    $content = @(Get-Content -LiteralPath $VmxPath)
    $pattern = '^\s*guestinfo\.atlaso\.test_vm_development_root_ca_private_key\s*='
    $importProofPattern = '^\s*guestinfo\.atlaso\.test_vm_development_root_ca_imported\s*='
    $updated = $false
    $content = @($content | ForEach-Object {
            # A prior matching proof must never satisfy this invocation before
            # the newly staged signer has been imported and scrubbed.
            if ($_ -match $importProofPattern) {
                return
            }
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
    Write-AtlasoWorkstationDurableVmxLines -VmxPath $VmxPath -Lines ([string[]]$content)
}

<#
.SYNOPSIS
Remove the development root private-key assignment from a powered-off VMX.

.PARAMETER VmxPath
Exact failed normal-test-VM VMX whose signer assignment must be scrubbed.
#>
function Clear-AtlasoWorkstationDevelopmentRootCaPrivateKey {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath
    )

    $pattern = '^\s*guestinfo\.atlaso\.test_vm_development_root_ca_private_key\s*='
    $content = @(Get-Content -LiteralPath $VmxPath | Where-Object { $_ -notmatch $pattern })
    Write-AtlasoWorkstationDurableVmxLines -VmxPath $VmxPath -Lines ([string[]]$content)
    if (Select-String -LiteralPath $VmxPath -Pattern $pattern -Quiet) {
        throw 'The powered-off normal test VM still contains the development signing-key assignment.'
    }
}

<#
.SYNOPSIS
Clear and verify the development signer through VMware runtime guest-info.

.PARAMETER VmxPath
Exact normal test VMX whose runtime signer value must be scrubbed.

.PARAMETER VmrunPath
Exact VMware vmrun executable path.

.PARAMETER TimeoutSeconds
Bounded time allowed for three empty runtime readbacks.

.PARAMETER PollSeconds
Delay between runtime readbacks.
#>
function Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$PollSeconds = 2
    )

    $guestInfoName = 'guestinfo.atlaso.test_vm_development_root_ca_private_key'
    Invoke-AtlasoBoundedVmrun `
        -VmrunPath $VmrunPath `
        -ArgumentList @('-T', 'ws', 'writeVariable', $VmxPath, 'runtimeConfig', $guestInfoName, '') `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'Clear the development signing key from runtime guest-info' | Out-Null
    Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub `
        -VmxPath $VmxPath `
        -VmrunPath $VmrunPath `
        -TimeoutSeconds $TimeoutSeconds `
        -PollSeconds $PollSeconds
}

<#
.SYNOPSIS
Return the SHA-256 fingerprint of one public development root certificate.

.PARAMETER CertificatePath
Exact checked-in PEM certificate path.
#>
function Get-AtlasoDevelopmentRootCaFingerprint {
    param(
        [Parameter(Mandatory = $true)][string]$CertificatePath
    )

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(
        [System.IO.File]::ReadAllText($CertificatePath)
    )
    try {
        return $certificate.GetCertHashString(
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        ).ToUpperInvariant()
    }
    finally {
        $certificate.Dispose()
    }
}

<#
.SYNOPSIS
Wait for proof that the guest encrypted the development signer and scrubbed staging.

.PARAMETER VmxPath
Exact running normal test VMX path.

.PARAMETER VmrunPath
Exact VMware vmrun executable path.

.PARAMETER ExpectedFingerprint
Checked-in development root SHA-256 fingerprint expected from the guest.

.PARAMETER TimeoutSeconds
Bounded time allowed for HTTPS bootstrap to import and scrub the signer.

.PARAMETER PollSeconds
Delay between guest-info reads.
#>
function Wait-AtlasoWorkstationDevelopmentRootCaImportProof {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$ExpectedFingerprint,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$PollSeconds = 2
    )

    $normalizedExpected = $ExpectedFingerprint.Replace(':', '').ToUpperInvariant()
    if ($normalizedExpected -notmatch '^[0-9A-F]{64}$') {
        throw 'The expected Atlaso development root SHA-256 fingerprint is invalid.'
    }
    $guestInfoName = 'guestinfo.atlaso.test_vm_development_root_ca_imported'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $matchingReads = 0
    do {
        $remainingSeconds = [Math]::Max(1, [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
        $value = Invoke-AtlasoBoundedVmrun `
            -VmrunPath $VmrunPath `
            -ArgumentList @('-T', 'ws', 'readVariable', $VmxPath, 'runtimeConfig', $guestInfoName) `
            -TimeoutSeconds $remainingSeconds `
            -Action 'Read the development-root encrypted-import proof'
        $normalizedValue = if ($null -ne $value) {
            $value.Trim().Replace(':', '').ToUpperInvariant()
        }
        else {
            ''
        }
        if ($normalizedValue -ceq $normalizedExpected) {
            $matchingReads += 1
            if ($matchingReads -ge 3) {
                return
            }
        }
        else {
            $matchingReads = 0
        }
        if ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $PollSeconds
        }
    } while ((Get-Date) -lt $deadline)
    throw 'The normal test VM did not prove encrypted development-root import and plaintext staging removal.'
}

<#
.SYNOPSIS
Wait until the guest proves the development signing key was scrubbed.

.PARAMETER VmxPath
Exact running normal test VMX path.

.PARAMETER VmrunPath
Exact VMware vmrun executable path.

.PARAMETER TimeoutSeconds
Bounded time allowed for guest-side staging and scrub.

.PARAMETER PollSeconds
Delay between guest-info reads.
#>
function Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$PollSeconds = 2
    )

    $guestInfoName = 'guestinfo.atlaso.test_vm_development_root_ca_private_key'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $emptyReads = 0
    do {
        $remainingSeconds = [Math]::Max(1, [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
        $value = Invoke-AtlasoBoundedVmrun `
            -VmrunPath $VmrunPath `
            -ArgumentList @('-T', 'ws', 'readVariable', $VmxPath, 'runtimeConfig', $guestInfoName) `
            -TimeoutSeconds $remainingSeconds `
            -Action 'Read the development signing-key guest-info value'
        $normalizedValue = if ($null -eq $value) { '' } else { $value.Trim() }
        # vmrun serializes an empty runtimeConfig value as the literal VMX
        # empty-string sentinel. Treat only that exact sentinel as empty; other
        # quoted or unquoted text remains a non-empty secret-bearing value.
        if ([string]::IsNullOrWhiteSpace($normalizedValue) -or $normalizedValue -ceq '""') {
            $emptyReads += 1
            if ($emptyReads -ge 3) {
                return
            }
        }
        else {
            $emptyReads = 0
        }
        if ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $PollSeconds
        }
    } while ((Get-Date) -lt $deadline)
    throw 'The normal test VM did not prove that its development signing key guest-info value was scrubbed.'
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
