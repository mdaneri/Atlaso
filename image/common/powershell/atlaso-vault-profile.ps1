function global:Get-AtlasoVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    $value = & '/opt/atlaso/.venv/bin/atlaso-vault' get --key $Key
    if ($LASTEXITCODE -ne 0) {
        throw "Atlaso vault lookup failed for key: $Key"
    }
    return ($value -join [Environment]::NewLine)
}
