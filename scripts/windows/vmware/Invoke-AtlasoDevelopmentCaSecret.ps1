<#
.SYNOPSIS
Validate or stage the normal VMware test VM development CA private key.

.DESCRIPTION
Runs only as a bounded child of create-atlaso-test-vm.ps1 under an exact
1Password Environment. The inherited variable is removed before validation,
and the private key is never printed or passed as a process argument.

.PARAMETER Action
Validate the certificate/key pair or stage the validated key in one new VMX.

.PARAMETER CertificatePath
Exact checked-in public development root certificate path.

.PARAMETER VmxPath
Exact new normal-test-VM VMX path required by the Stage action.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Validate', 'Stage')]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$CertificatePath,

    [string]$VmxPath = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')

$privateKey = [Environment]::GetEnvironmentVariable('ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY')
[Environment]::SetEnvironmentVariable('ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY', $null)
try {
    if ([string]::IsNullOrWhiteSpace($privateKey)) {
        throw 'The exact Atlaso 1Password Environment did not provide ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY.'
    }
    Assert-AtlasoDevelopmentRootCaMaterial `
        -CertificatePath $CertificatePath `
        -PrivateKeyPem $privateKey
    if ($Action -eq 'Stage') {
        if ([string]::IsNullOrWhiteSpace($VmxPath)) {
            throw 'The Stage action requires the exact new normal test VMX path.'
        }
        Set-AtlasoWorkstationDevelopmentRootCaPrivateKey `
            -VmxPath $VmxPath `
            -PrivateKeyPem $privateKey
    }
}
finally {
    $privateKey = $null
    [GC]::Collect()
}
