[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
param(
    [Parameter(Mandatory = $false)]
    [string]$Password
)
$ErrorActionPreference = 'Stop'

$OvfTool = 'C:\Program Files\VMware\VMware Workstation\OVFTool\ovftool.exe'

$SourceOva = 'C:\Users\m_dan\Downloads\VCF-SDDC-Manager-Appliance-9.1.0.0400.25570100.ova'

$VmDirectory = 'C:\Users\m_dan\Documents\Virtual Machines\VCF-SDDC-Manager-9.1'
$DestinationVmx = Join-Path $VmDirectory 'VCF-SDDC-Manager-9.1.vmx'

$VmName = 'VCF-SDDC-Manager-9.1'
$Network = 'VMnet1'

$Hostname = 'sddcm.test.internal'
$IpAddress = '192.168.87.12'
$Netmask = '255.255.255.0'
$Gateway = '192.168.87.22'
$DnsServer = '192.168.87.22'
$NtpServer = '192.168.87.22'
$Domain = 'test.internal'

if (-not (Test-Path -LiteralPath $OvfTool)) {
    throw "OVF Tool was not found at: $OvfTool"
}

if (-not (Test-Path -LiteralPath $SourceOva)) {
    throw "OVA file was not found at: $SourceOva"
}

New-Item -ItemType Directory -Path $VmDirectory -Force | Out-Null

if (-not $Password) {
    $SecurePassword = Read-Host `
        'Enter the password for root, admin@local, and vcf SSH users' `
        -AsSecureString
    $Password = ConvertFrom-SecureString -SecureString $SecurePassword -AsPlainText
}

$Arguments = @(
    '--acceptAllEulas'
    '--overwrite'
    '--powerOffTarget'
    "--name=$VmName"
    "--net:Network 1=$Network"

    "--prop:ROOT_PASSWORD=$Password"
    "--prop:LOCAL_USER_PASSWORD=$Password"

    "--prop:vami.hostname=$Hostname"
    "--prop:guestinfo.ntp=$NtpServer"

    '--prop:ip_address_version=IPv4'
    "--prop:ip0=$IpAddress"
    "--prop:netmask0=$Netmask"
    "--prop:gateway=$Gateway"
    "--prop:domain=$Domain"
    "--prop:searchpath=$Domain"
    "--prop:DNS=$DnsServer"

    $SourceOva
    $DestinationVmx
)

Write-Host "Deploying $VmName..."
Write-Host "Destination: $DestinationVmx"
Write-Host "Network:     $Network"
Write-Host "Address:     $IpAddress/24"

& $OvfTool @Arguments

if ($LASTEXITCODE -ne 0) {
    throw "OVF Tool failed with exit code $LASTEXITCODE."
}

Write-Host ''
Write-Host 'Deployment completed successfully.'
Write-Host 'Open this VMX in VMware Workstation:'
Write-Host $DestinationVmx



$VmxContent = Get-Content -LiteralPath $DestinationVmx

$Settings = @{
    'ethernet0.present'        = 'TRUE'
    'ethernet0.connectionType' = 'custom'
    'ethernet0.vnet'           = 'VMnet1'
    'ethernet0.startConnected' = 'TRUE'
}

foreach ($Setting in $Settings.GetEnumerator()) {
    $Pattern = '^\s*' + [regex]::Escape($Setting.Key) + '\s*='
    $NewLine = '{0} = "{1}"' -f $Setting.Key, $Setting.Value

    if ($VmxContent -match $Pattern) {
        $VmxContent = $VmxContent |
        ForEach-Object {
            if ($_ -match $Pattern) {
                $NewLine
            }
            else {
                $_
            }
        }
    }
    else {
        $VmxContent += $NewLine
    }
}

Set-Content `
    -LiteralPath $DestinationVmx `
    -Value $VmxContent `
    -Encoding UTF8


function Set-VmxValue {
    param(
        [Parameter(Mandatory)]
        [string[]] $Content,

        [Parameter(Mandatory)]
        [string] $Key,

        [Parameter(Mandatory)]
        [string] $Value
    )

    $Pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $Line = '{0} = "{1}"' -f $Key, $Value

    $Found = $false

    $Updated = foreach ($ExistingLine in $Content) {
        if ($ExistingLine -match $Pattern) {
            if (-not $Found) {
                $Line
                $Found = $true
            }
        }
        else {
            $ExistingLine
        }
    }

    if (-not $Found) {
        $Updated += $Line
    }

    return $Updated
}

function ConvertTo-OvfXmlValue {
    param(
        [AllowEmptyString()]
        [string] $Value
    )

    return [System.Security.SecurityElement]::Escape($Value)
}

$RootPasswordXml = ConvertTo-OvfXmlValue $Password
$LocalPasswordXml = ConvertTo-OvfXmlValue $Password
$HostnameXml = ConvertTo-OvfXmlValue $Hostname
$NtpServerXml = ConvertTo-OvfXmlValue $NtpServer
$IpAddressXml = ConvertTo-OvfXmlValue $IpAddress
$NetmaskXml = ConvertTo-OvfXmlValue $Netmask
$GatewayXml = ConvertTo-OvfXmlValue $Gateway
$DomainXml = ConvertTo-OvfXmlValue $Domain
$DnsServerXml = ConvertTo-OvfXmlValue $DnsServer

# Use single quotes inside the XML so it can safely be stored in a
# double-quoted VMX setting.
$OvfEnvironment = @"
<Environment xmlns='http://schemas.dmtf.org/ovf/environment/1' xmlns:ovfenv='http://schemas.dmtf.org/ovf/environment/1' xmlns:oe='http://schemas.dmtf.org/ovf/environment/1' xmlns:ve='http://www.vmware.com/schema/ovfenv' oe:id='vm'><PlatformSection><Kind>VMware Workstation</Kind><Version>17</Version><Vendor>VMware, Inc.</Vendor><Locale>en</Locale></PlatformSection><PropertySection><Property oe:key='ROOT_PASSWORD' oe:value='$RootPasswordXml'/><Property oe:key='LOCAL_USER_PASSWORD' oe:value='$LocalPasswordXml'/><Property oe:key='vami.hostname' oe:value='$HostnameXml'/><Property oe:key='guestinfo.ntp' oe:value='$NtpServerXml'/><Property oe:key='vami.ip_address_version.SDDC-Manager' oe:value='IPv4'/><Property oe:key='vami.ip0.SDDC-Manager' oe:value='$IpAddressXml'/><Property oe:key='vami.netmask0.SDDC-Manager' oe:value='$NetmaskXml'/><Property oe:key='vami.gateway.SDDC-Manager' oe:value='$GatewayXml'/><Property oe:key='vami.domain.SDDC-Manager' oe:value='$DomainXml'/><Property oe:key='vami.searchpath.SDDC-Manager' oe:value='$DomainXml'/><Property oe:key='vami.DNS.SDDC-Manager' oe:value='$DnsServerXml'/></PropertySection></Environment>
"@

# It must be a single VMX line.
$OvfEnvironment = ($OvfEnvironment -replace '\r?\n', '').Trim()

$VmxContent = Get-Content -LiteralPath $DestinationVmx

# Force VMnet1.
$VmxContent = Set-VmxValue `
    -Content $VmxContent `
    -Key 'ethernet0.present' `
    -Value 'TRUE'

$VmxContent = Set-VmxValue `
    -Content $VmxContent `
    -Key 'ethernet0.connectionType' `
    -Value 'custom'

$VmxContent = Set-VmxValue `
    -Content $VmxContent `
    -Key 'ethernet0.vnet' `
    -Value 'VMnet1'

$VmxContent = Set-VmxValue `
    -Content $VmxContent `
    -Key 'ethernet0.startConnected' `
    -Value 'TRUE'

# Inject the OVF environment expected by the appliance.
$VmxContent = Set-VmxValue `
    -Content $VmxContent `
    -Key 'guestinfo.ovfEnv' `
    -Value $OvfEnvironment

# Also expose NTP directly because the original OVF property is literally
# called guestinfo.ntp.
#$VmxContent = Set-VmxValue `
#    -Content $VmxContent `
#    -Key 'guestinfo.ntp' `
#    -Value $NtpServer

# Write UTF-8 without BOM.
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

[System.IO.File]::WriteAllLines(
    $DestinationVmx,
    $VmxContent,
    $Utf8NoBom
)