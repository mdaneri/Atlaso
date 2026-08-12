param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts/windows/common/Atlaso.PhotonImage.psm1'
$module = Import-Module $modulePath -Force -PassThru
$passwords = @(
    [string]::Concat('quote', [char]39, 'break'),
    [string]::Concat(
        'meta',
        [char]36,
        [char]40,
        'value',
        [char]41,
        [char]59,
        [char]38,
        [char]124,
        [char]60,
        [char]62,
        [char]34,
        [char]92,
        [char]96,
        'end'
    )
)

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
try {
    foreach ($target in @('hyperv', 'vmware-workstation')) {
        foreach ($password in $passwords) {
            $path = Join-Path $OutputDirectory "$target-kickstart.json"
            & $module {
                param($KickstartPath, $Credential)
                New-AtlasoPhotonKickstart `
                    -Path $KickstartPath `
                    -RootPassword $Credential `
                    -BuildPassword $Credential `
                    -BuildUsername 'atlaso-build'
            } $path $password

            $kickstart = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if ($kickstart.password.text -cne $password) {
                throw 'Photon kickstart did not preserve the root password exactly.'
            }

            $postInstall = @($kickstart.postinstall)
            if (($postInstall -join "`n").Contains($password)) {
                throw 'Photon post-install commands contain the raw build password.'
            }

            $credentialCommand = @(
                $postInstall | Where-Object { $_ -like "*base64 -d | chpasswd" }
            )
            if ($credentialCommand.Count -ne 1) {
                throw 'Photon kickstart must contain exactly one encoded chpasswd command.'
            }

            $match = [regex]::Match(
                [string]$credentialCommand[0],
                "^printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d \| chpasswd$"
            )
            if (-not $match.Success) {
                throw 'Photon chpasswd command does not use the bounded Base64 stdin contract.'
            }

            $actualBytes = [System.Convert]::FromBase64String($match.Groups[1].Value)
            $expectedBytes = [System.Text.UTF8Encoding]::new($false).GetBytes("atlaso-build:$password`n")
            if (-not [System.Linq.Enumerable]::SequenceEqual[byte]($actualBytes, $expectedBytes)) {
                throw 'Photon chpasswd input did not preserve the original credential bytes.'
            }

            ($postInstall -join "`n") | & bash -n - 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw 'Photon post-install shell failed syntax validation.'
            }
        }
    }
} finally {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output 'Atlaso Photon image credential transport tests passed.'
