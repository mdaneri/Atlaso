<#
.SYNOPSIS
Exercise the VMware Workstation first-boot public-key helpers.

.PARAMETER RepositoryRoot
Atlaso checkout containing the helper under test.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'
. (Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1')

<#
.SYNOPSIS
Assert that two scalar test values are equal.

.PARAMETER Actual
Value produced by the helper under test.

.PARAMETER Expected
Required value.

.PARAMETER Message
Failure context shown when the values differ.
#>
function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected', received '$Actual'."
    }
}

<#
.SYNOPSIS
Assert that one test action terminates with an error.

.PARAMETER Action
Action expected to throw.

.PARAMETER Message
Failure context shown when the action does not throw.
#>
function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Message
    )

    try {
        & $Action
    }
    catch {
        return
    }
    throw $Message
}

$validKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f atlaso&test'
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-workstation-key-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
try {
    $keyPath = Join-Path $temporaryRoot 'id_ed25519.pub'
    [System.IO.File]::WriteAllText($keyPath, "$validKey`r`n", [System.Text.UTF8Encoding]::new($false))
    $resolved = Resolve-AtlasoWorkstationAdminSshPublicKey -Path $keyPath
    Assert-Equal $resolved.PublicKey $validKey 'The public key resolver must preserve one normalized Ed25519 key.'
    Assert-Equal $resolved.Path (Resolve-Path -LiteralPath $keyPath).Path 'The public key resolver must return the exact path.'

    $hostKeyEvidence = ConvertTo-AtlasoWorkstationSshHostKeyEvidence -PublicKey $validKey
    Assert-Equal `
        $hostKeyEvidence.PublicKey `
        ($validKey -replace ' atlaso&test$', '') `
        'Host-key evidence must omit the non-identity comment.'
    Assert-Equal `
        $hostKeyEvidence.Fingerprint `
        'SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA' `
        'Host-key evidence must use the OpenSSH SHA-256 fingerprint format.'

    $withoutKey = New-AtlasoWorkstationOvfEnvironment `
        -Fqdn 'atlaso-test.atlaso.internal' `
        -AdminPassword 'VMware01!Test' `
        -RootPassword 'VMware01!Test'
    if ($withoutKey.Contains('development_admin_ssh_public_key', [System.StringComparison]::Ordinal)) {
        throw 'Ordinary Workstation OVF input must not contain the development administrator key property.'
    }

    $withKey = New-AtlasoWorkstationOvfEnvironment `
        -Fqdn 'atlaso-test.atlaso.internal' `
        -AdminPassword 'VMware01!Test' `
        -RootPassword 'VMware01!Test' `
        -DevelopmentAdminSshPublicKey $validKey
    if (-not $withKey.Contains("oe:key='atlaso.development_admin_ssh_public_key'", [System.StringComparison]::Ordinal)) {
        throw 'The test-VM OVF input must contain the development administrator key property.'
    }
    if (-not $withKey.Contains('atlaso&amp;test', [System.StringComparison]::Ordinal)) {
        throw 'The test-VM public-key comment must remain XML escaped.'
    }

    $rsa = [System.Security.Cryptography.RSA]::Create(4096)
    $otherRsa = [System.Security.Cryptography.RSA]::Create(4096)
    try {
        $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new(
            'CN=Atlaso Development Root CA,O=Atlaso Development'
        )
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $subject,
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $usage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage, $true)
        )
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-1),
            [DateTimeOffset]::UtcNow.AddDays(30)
        )
        $certificatePem = [System.Security.Cryptography.PemEncoding]::WriteString(
            'CERTIFICATE',
            $certificate.RawData
        )
        $privateKeyPem = [System.Security.Cryptography.PemEncoding]::WriteString(
            'PRIVATE KEY',
            $rsa.ExportPkcs8PrivateKey()
        )
        $certificatePath = Join-Path $temporaryRoot 'development-root-ca.pem'
        [System.IO.File]::WriteAllText(
            $certificatePath,
            $certificatePem,
            [System.Text.UTF8Encoding]::new($false)
        )
        Assert-AtlasoDevelopmentRootCaMaterial `
            -CertificatePath $certificatePath `
            -PrivateKeyPem $privateKeyPem
        $otherPrivateKeyPem = [System.Security.Cryptography.PemEncoding]::WriteString(
            'PRIVATE KEY',
            $otherRsa.ExportPkcs8PrivateKey()
        )
        Assert-Throws {
            Assert-AtlasoDevelopmentRootCaMaterial `
                -CertificatePath $certificatePath `
                -PrivateKeyPem $otherPrivateKeyPem
        } 'A mismatched development root key must fail.'

        $withDevelopmentRoot = New-AtlasoWorkstationOvfEnvironment `
            -Fqdn 'atlaso-test.atlaso.internal' `
            -AdminPassword 'VMware01!Test' `
            -RootPassword 'VMware01!Test' `
            -DevelopmentRootCaCertificatePem $certificatePem
        if (-not $withDevelopmentRoot.Contains("oe:key='atlaso.development_test_vm' oe:value='true'")) {
            throw 'The shared CA must identify the internal normal-test-wrapper path without requiring an SSH key.'
        }
        if (-not $withDevelopmentRoot.Contains("oe:key='atlaso.development_root_ca_certificate'")) {
            throw 'The normal test wrapper OVF input must carry the public development root.'
        }
        if ($withDevelopmentRoot.Contains('BEGIN CERTIFICATE')) {
            throw 'The public development root OVF property must use bounded base64.'
        }

        $vmxPath = Join-Path $temporaryRoot 'development.vmx'
        [System.IO.File]::WriteAllText(
            $vmxPath,
            "displayName = `"Atlaso-Test`"`n",
            [System.Text.UTF8Encoding]::new($false)
        )
        Set-AtlasoWorkstationDevelopmentRootCaPrivateKey `
            -VmxPath $vmxPath `
            -PrivateKeyPem $privateKeyPem
        $vmx = [System.IO.File]::ReadAllText($vmxPath)
        if ($vmx -notmatch 'guestinfo\.atlaso\.test_vm_development_root_ca_private_key') {
            throw 'The dedicated normal-test-VM signing-key guest-info field was not staged.'
        }
        if ($vmx.Contains('BEGIN PRIVATE KEY')) {
            throw 'The signing key guest-info field must use bounded base64.'
        }
        Clear-AtlasoWorkstationDevelopmentRootCaPrivateKey -VmxPath $vmxPath
        if ([System.IO.File]::ReadAllText($vmxPath) -match 'guestinfo\.atlaso\.test_vm_development_root_ca_private_key') {
            throw 'Powered-off rollback must remove the development signer assignment from the VMX.'
        }
    }
    finally {
        if ($certificate) {
            $certificate.Dispose()
        }
        $rsa.Dispose()
        $otherRsa.Dispose()
    }

    Assert-Throws { Assert-AtlasoWorkstationEd25519PublicKey -PublicKey 'ssh-rsa invalid' } 'Non-Ed25519 keys must fail.'
    Assert-Throws { Assert-AtlasoWorkstationEd25519PublicKey -PublicKey "$validKey`nsecond" } 'Multiline keys must fail.'
    $xmlInvalidKey = "$validKey$([char]0xFFFE)"
    Assert-Throws { Assert-AtlasoWorkstationEd25519PublicKey -PublicKey $xmlInvalidKey } 'XML-invalid key comments must fail.'
    Assert-Throws { Resolve-AtlasoWorkstationAdminSshPublicKey -Path (Join-Path $temporaryRoot 'missing.pub') } 'Missing key files must fail.'
}
finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Atlaso Workstation first-boot public-key tests passed.'
