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
Create a read-only SecureString from a non-secret test fixture.
.PARAMETER Value
Fixture text appended one character at a time.
#>
function ConvertTo-TestSecureString {
    param([Parameter(Mandatory = $true)][string]$Value)

    $secureValue = [SecureString]::new()
    foreach ($character in $Value.ToCharArray()) {
        $secureValue.AppendChar($character)
    }
    $secureValue.MakeReadOnly()
    return $secureValue
}

<#
.SYNOPSIS
Assert that two scalar test values are equal.

.PARAMETER Actual
Value produced by the helper under test.

.PARAMETER Expected
Reference result required by the test assertion.

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

<#
.SYNOPSIS
Return the configured guest-info import proof for wait-helper tests.

.PARAMETER Arguments
Ignored vmrun-compatible arguments accepted by the fake command.
#>
function Invoke-AtlasoImportProofVmrun {
    param(
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    $global:LASTEXITCODE = 0
    return $script:ImportProofFingerprint
}

<#
.SYNOPSIS
Simulate VMware runtime signer clearing and its quoted empty readback.

.PARAMETER Arguments
vmrun-compatible arguments captured for ordering assertions.
#>
function Invoke-AtlasoRuntimeSignerScrubVmrun {
    param(
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    $script:RuntimeSignerScrubCalls.Add(($Arguments -join ' '))
    $global:LASTEXITCODE = 0
    if ($Arguments -contains 'readVariable') {
        return '""'
    }
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
        -AdminPassword (ConvertTo-TestSecureString -Value 'VMware01!Test') `
        -RootPassword (ConvertTo-TestSecureString -Value 'VMware01!Test')
    if ($withoutKey.Contains('development_admin_ssh_public_key', [System.StringComparison]::Ordinal)) {
        throw 'Ordinary Workstation OVF input must not contain the development administrator key property.'
    }
    if ($withoutKey.Contains('normal_test_vm', [System.StringComparison]::Ordinal)) {
        throw 'Ordinary Workstation OVF input must not contain the normal-test-VM marker.'
    }

    $passwordOnlyTestVm = New-AtlasoWorkstationOvfEnvironment `
        -Fqdn 'atlaso-test.atlaso.internal' `
        -AdminPassword (ConvertTo-TestSecureString -Value 'VMware01!Test') `
        -RootPassword (ConvertTo-TestSecureString -Value 'VMware01!Test') `
        -NormalTestVm
    if (-not $passwordOnlyTestVm.Contains("oe:key='atlaso.normal_test_vm' oe:value='true'", [System.StringComparison]::Ordinal)) {
        throw 'A password-only normal test VM must retain its explicit identity-publication marker.'
    }
    if ($passwordOnlyTestVm.Contains('development_admin_ssh_public_key', [System.StringComparison]::Ordinal)) {
        throw 'A password-only normal test VM must not gain a development administrator key property.'
    }

    $withKey = New-AtlasoWorkstationOvfEnvironment `
        -Fqdn 'atlaso-test.atlaso.internal' `
        -AdminPassword (ConvertTo-TestSecureString -Value 'VMware01!Test') `
        -RootPassword (ConvertTo-TestSecureString -Value 'VMware01!Test') `
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
        $developmentFingerprint = Get-AtlasoDevelopmentRootCaFingerprint `
            -CertificatePath $certificatePath
        if ($developmentFingerprint -notmatch '^[0-9A-F]{64}$') {
            throw 'The development root helper did not return an uppercase SHA-256 fingerprint.'
        }
        $script:ImportProofFingerprint = $developmentFingerprint
        Wait-AtlasoWorkstationDevelopmentRootCaImportProof `
            -VmxPath (Join-Path $temporaryRoot 'proof.vmx') `
            -VmrunPath 'Invoke-AtlasoImportProofVmrun' `
            -ExpectedFingerprint $developmentFingerprint `
            -TimeoutSeconds 2 `
            -PollSeconds 0
        $script:ImportProofFingerprint = '0' * 64
        Assert-Throws {
            Wait-AtlasoWorkstationDevelopmentRootCaImportProof `
                -VmxPath (Join-Path $temporaryRoot 'proof.vmx') `
                -VmrunPath 'Invoke-AtlasoImportProofVmrun' `
                -ExpectedFingerprint $developmentFingerprint `
                -TimeoutSeconds 0 `
                -PollSeconds 0
        } 'A mismatched encrypted-import proof must fail closed.'
        $script:RuntimeSignerScrubCalls = [System.Collections.Generic.List[string]]::new()
        Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey `
            -VmxPath (Join-Path $temporaryRoot 'runtime-scrub.vmx') `
            -VmrunPath 'Invoke-AtlasoRuntimeSignerScrubVmrun' `
            -TimeoutSeconds 2 `
            -PollSeconds 0
        if (
            $script:RuntimeSignerScrubCalls.Count -lt 4 -or
            $script:RuntimeSignerScrubCalls[0] -notmatch '^\-T ws writeVariable .* runtimeConfig guestinfo\.atlaso\.test_vm_development_root_ca_private_key\s*$'
        ) {
            throw 'Runtime rollback must clear the signer before verifying three empty reads.'
        }
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
        Assert-Throws {
            Assert-AtlasoDevelopmentRootCaMaterial `
                -CertificatePath $certificatePath `
                -PrivateKeyPem ($privateKeyPem + "unrelated trailing data")
        } 'Trailing data after the matching development root key must fail.'
        Assert-Throws {
            Assert-AtlasoDevelopmentRootCaMaterial `
                -CertificatePath $certificatePath `
                -PrivateKeyPem ($privateKeyPem + $otherPrivateKeyPem)
        } 'A second PEM block after the matching development root key must fail.'

        $withDevelopmentRoot = New-AtlasoWorkstationOvfEnvironment `
            -Fqdn 'atlaso-test.atlaso.internal' `
            -AdminPassword (ConvertTo-TestSecureString -Value 'VMware01!Test') `
            -RootPassword (ConvertTo-TestSecureString -Value 'VMware01!Test') `
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
            "displayName = `"Atlaso-Test`"`n" +
                "guestinfo.atlaso.test_vm_development_root_ca_imported = `"$developmentFingerprint`"`n",
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
        if ($vmx -match 'guestinfo\.atlaso\.test_vm_development_root_ca_imported') {
            throw 'Staging a new signer must remove stale encrypted-import proof from the VMX.'
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
