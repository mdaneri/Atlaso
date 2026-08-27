<#
.SYNOPSIS
Prepare or stage normal-test-VM first-boot credentials in a bounded child.

.DESCRIPTION
Keeps plaintext credentials outside the create-atlaso-test-vm.ps1 parent.
Prepare resolves only omitted defaults through the supported 1Password SDK,
combines them with DPAPI-protected explicit SecureString overrides, validates
the existing Atlaso OVF contract, and writes a DPAPI-protected OVF bundle.
Stage decrypts that bundle only long enough to update the exact new VMX.

.PARAMETER Action
Prepare the protected OVF bundle or stage it into the exact new VMX.

.PARAMETER RequestPath
Private JSON request containing non-secret OVF inputs and optional DPAPI
ciphertext for explicit SecureString overrides.

.PARAMETER StatusPath
Private JSON status written with safe machine-readable outcome codes.

.PARAMETER OvfBundlePath
DPAPI-protected complete OVF environment exchanged between bounded children.

.PARAMETER PythonCommand
Approved CPython 3.10 through 3.13 executable for omitted-value retrieval.

.PARAMETER DependencyPath
Isolated, hash-locked 1Password SDK dependency directory.

.PARAMETER OnePasswordAccount
Non-secret 1Password account name or ID used for desktop authorization.

.PARAMETER EnvironmentId
Opaque ID of the already pinned and verified Atlaso Environment.

.PARAMETER VmxPath
Exact newly created VMX that receives the protected OVF environment.

.PARAMETER TimeoutSeconds
Bounded SDK authorization and Environment retrieval deadline.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordAccount',
    Justification = 'Desktop authorization account identifier, not an account password.'
)]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('Prepare', 'Stage')][string]$Action,
    [string]$RequestPath = '',
    [Parameter(Mandatory = $true)][string]$StatusPath,
    [Parameter(Mandatory = $true)][string]$OvfBundlePath,
    [string]$PythonCommand = '',
    [string]$DependencyPath = '',
    [string]$OnePasswordAccount = '',
    [string]$EnvironmentId = '',
    [string]$VmxPath = '',
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')

$status = [ordered]@{
    Success = $false
    Code    = 'credential_bridge_failed'
}
$defaultBundlePath = ''
$pythonChildPath = ''
$adminPasswordText = $null
$rootPasswordText = $null
$ovfEnvironment = $null

try {
    if ($Action -eq 'Stage') {
        if (
            [string]::IsNullOrWhiteSpace($VmxPath) -or
            -not (Test-Path -LiteralPath $VmxPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $OvfBundlePath -PathType Leaf)
        ) {
            $status.Code = 'stage_input_invalid'
            return
        }
        $ovfCiphertext = [System.IO.File]::ReadAllText($OvfBundlePath)
        $ovfSecureString = ConvertTo-SecureString -String $ovfCiphertext
        $ovfEnvironment = ConvertFrom-SecureString -SecureString $ovfSecureString -AsPlainText
        Set-AtlasoWorkstationOvfEnvironment -VmxPath $VmxPath -OvfEnvironment $ovfEnvironment
        $status.Success = $true
        $status.Code = 'staged'
        return
    }

    if (
        [string]::IsNullOrWhiteSpace($RequestPath) -or
        -not (Test-Path -LiteralPath $RequestPath -PathType Leaf)
    ) {
        $status.Code = 'prepare_request_invalid'
        return
    }
    $request = [System.IO.File]::ReadAllText($RequestPath) | ConvertFrom-Json
    $adminCiphertext = [string]$request.AdminPasswordCiphertext
    $rootCiphertext = [string]$request.RootPasswordCiphertext
    $needsAdminDefault = [string]::IsNullOrWhiteSpace($adminCiphertext)
    $needsRootDefault = [string]::IsNullOrWhiteSpace($rootCiphertext)

    if ($needsAdminDefault -or $needsRootDefault) {
        if (
            [string]::IsNullOrWhiteSpace($PythonCommand) -or
            [string]::IsNullOrWhiteSpace($DependencyPath) -or
            [string]::IsNullOrWhiteSpace($OnePasswordAccount) -or
            [string]::IsNullOrWhiteSpace($EnvironmentId)
        ) {
            $status.Code = 'sdk_configuration_missing'
            return
        }
        $bridgeDirectory = [System.IO.Path]::GetDirectoryName($StatusPath)
        $defaultBundlePath = Join-Path $bridgeDirectory 'onepassword-defaults.json'
        $pythonChildPath = Join-Path $bridgeDirectory 'atlaso-test-vm-onepassword.py'
        $pythonSource = @'
import argparse
import asyncio
import ctypes
import json
import os
import pathlib
import sys


class DataBlob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def protect_password(value):
    raw = value.encode("utf-16-le")
    source_buffer = ctypes.create_string_buffer(raw)
    source = DataBlob(
        len(raw), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    protected = DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    try:
        crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(DataBlob),
            ctypes.c_wchar_p,
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(DataBlob),
        ]
        crypt32.CryptProtectData.restype = ctypes.c_bool
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        if not crypt32.CryptProtectData(
            ctypes.byref(source),
            None,
            None,
            None,
            None,
            0x1,
            ctypes.byref(protected),
        ):
            raise OSError("DPAPI protection failed")
        try:
            return ctypes.string_at(protected.data, protected.size).hex()
        finally:
            kernel32.LocalFree(ctypes.cast(protected.data, ctypes.c_void_p))
    finally:
        ctypes.memset(source_buffer, 0, len(raw))
        raw = None


def password_is_valid(value):
    if not isinstance(value, str) or len(value) < 12:
        return False
    if value != value.strip() or any(character in value for character in "\r\n\t"):
        return False
    for character in value:
        codepoint = ord(character)
        if not (
            codepoint in (0x9, 0xA, 0xD)
            or 0x20 <= codepoint <= 0xD7FF
            or 0xE000 <= codepoint <= 0xFFFD
            or 0x10000 <= codepoint <= 0x10FFFF
        ):
            return False
    return True


async def retrieve_defaults(args, request):
    sys.path.insert(0, args.dependency_path)
    try:
        from onepassword import Client, DesktopAuth
    except ImportError:
        raise SystemExit(26) from None
    try:
        client = await asyncio.wait_for(
            Client.authenticate(
                auth=DesktopAuth(account_name=args.onepassword_account),
                integration_name="Atlaso VMware test VM",
                integration_version="v1",
            ),
            timeout=args.timeout,
        )
        response = await asyncio.wait_for(
            client.environments.get_variables(args.onepassword_environment_id),
            timeout=args.timeout,
        )
    except Exception:
        raise SystemExit(20) from None

    selected = {}
    for field_name, variable_name, contract_code, validation_code in (
        ("AdminPasswordCiphertext", "DEFAULT_ADMIN_PASSWORD", 21, 23),
        ("RootPasswordCiphertext", "DEFAULT_ROOT_PASSWORD", 22, 24),
    ):
        if request.get(field_name):
            continue
        matches = [
            variable for variable in response.variables if variable.name == variable_name
        ]
        if len(matches) != 1 or not matches[0].masked or not matches[0].value:
            raise SystemExit(contract_code)
        value = matches[0].value
        if not password_is_valid(value):
            raise SystemExit(validation_code)
        selected[field_name] = protect_password(value)
        value = None
        matches = None
    response = None
    return selected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dependency-path", required=True)
    parser.add_argument("--onepassword-account", required=True)
    parser.add_argument("--onepassword-environment-id", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", required=True, type=int)
    args = parser.parse_args()

    # Caller-controlled variables are never credential sources for this bridge.
    os.environ.pop("DEFAULT_ADMIN_PASSWORD", None)
    os.environ.pop("DEFAULT_ROOT_PASSWORD", None)
    try:
        request = json.loads(pathlib.Path(args.request).read_text(encoding="utf-8"))
        selected = asyncio.run(retrieve_defaults(args, request))
        output_path = pathlib.Path(args.output)
        temporary_path = output_path.with_name(output_path.name + ".tmp")
        temporary_path.write_text(
            json.dumps(selected, separators=(",", ":")), encoding="utf-8"
        )
        os.replace(temporary_path, output_path)
    except SystemExit:
        raise
    except Exception:
        raise SystemExit(25) from None


if __name__ == "__main__":
    main()
'@
        [System.IO.File]::WriteAllText(
            $pythonChildPath,
            ($pythonSource -replace "`r?`n", "`n"),
            [System.Text.UTF8Encoding]::new($false)
        )
        $null = & $PythonCommand @(
            '-I', '-S', $pythonChildPath,
            '--dependency-path', $DependencyPath,
            '--onepassword-account', $OnePasswordAccount,
            '--onepassword-environment-id', $EnvironmentId,
            '--request', $RequestPath,
            '--output', $defaultBundlePath,
            '--timeout', "$TimeoutSeconds"
        ) 2>$null
        $pythonExitCode = $LASTEXITCODE
        $status.Code = switch ($pythonExitCode) {
            0 { 'sdk_defaults_ready' }
            20 { 'sdk_access_failed' }
            21 { 'admin_variable_invalid' }
            22 { 'root_variable_invalid' }
            23 { 'admin_password_invalid' }
            24 { 'root_password_invalid' }
            25 { 'sdk_output_protection_failed' }
            26 { 'sdk_runtime_invalid' }
            default { 'sdk_child_failed' }
        }
        if ($pythonExitCode -ne 0) {
            return
        }
        $defaults = [System.IO.File]::ReadAllText($defaultBundlePath) | ConvertFrom-Json
        if ($needsAdminDefault) {
            $adminCiphertext = [string]$defaults.AdminPasswordCiphertext
        }
        if ($needsRootDefault) {
            $rootCiphertext = [string]$defaults.RootPasswordCiphertext
        }
    }

    if ([string]::IsNullOrWhiteSpace($adminCiphertext)) {
        $status.Code = 'admin_credential_missing'
        return
    }
    if ([string]::IsNullOrWhiteSpace($rootCiphertext)) {
        $status.Code = 'root_credential_missing'
        return
    }
    try {
        $adminPassword = ConvertTo-SecureString -String $adminCiphertext
        $rootPassword = ConvertTo-SecureString -String $rootCiphertext
    }
    catch {
        $status.Code = 'credential_ciphertext_invalid'
        return
    }

    try {
        $ovfEnvironment = New-AtlasoWorkstationOvfEnvironment `
            -Fqdn ([string]$request.Fqdn) `
            -AdminPassword $adminPassword `
            -RootPassword $rootPassword `
            -RootSshEnabled:([bool]$request.RootSshEnabled) `
            -NormalTestVm `
            -DevelopmentAdminSshPublicKey ([string]$request.DevelopmentAdminSshPublicKey) `
            -DevelopmentRootCaCertificatePem ([string]$request.DevelopmentRootCaCertificatePem)
    }
    catch {
        $message = $_.Exception.Message
        if ($message.StartsWith('AdminPassword', [System.StringComparison]::Ordinal)) {
            $status.Code = 'admin_password_invalid'
        }
        elseif ($message.StartsWith('RootPassword', [System.StringComparison]::Ordinal)) {
            $status.Code = 'root_password_invalid'
        }
        else {
            $status.Code = 'ovf_input_invalid'
        }
        return
    }
    $ovfSecureString = [SecureString]::new()
    foreach ($character in $ovfEnvironment.ToCharArray()) {
        $ovfSecureString.AppendChar($character)
    }
    $ovfCiphertext = ConvertFrom-SecureString -SecureString $ovfSecureString
    [System.IO.File]::WriteAllText($OvfBundlePath, $ovfCiphertext)
    $status.Success = $true
    $status.Code = 'prepared'
}
catch {
    $status.Success = $false
    $status.Code = if ($Action -eq 'Stage') { 'stage_failed' } else { 'prepare_failed' }
}
finally {
    $adminPasswordText = $null
    $rootPasswordText = $null
    $ovfEnvironment = $null
    if ($defaultBundlePath -and (Test-Path -LiteralPath $defaultBundlePath -PathType Leaf)) {
        [System.IO.File]::Delete($defaultBundlePath)
    }
    if ($pythonChildPath -and (Test-Path -LiteralPath $pythonChildPath -PathType Leaf)) {
        [System.IO.File]::Delete($pythonChildPath)
    }
    [System.IO.File]::WriteAllText(
        $StatusPath,
        ($status | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
}
