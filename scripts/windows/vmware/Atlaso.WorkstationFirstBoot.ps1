function ConvertTo-AtlasoOvfXmlValue {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    return [System.Security.SecurityElement]::Escape($Value)
}

function ConvertTo-AtlasoVmxString {
    param([string]$Value)

    return '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

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

function New-AtlasoWorkstationOvfEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Fqdn,

        [Parameter(Mandatory = $true)]
        [string]$AdminPassword,

        [Parameter(Mandatory = $true)]
        [string]$RootPassword,

        [switch]$RootSshEnabled
    )

    foreach ($passwordInput in @(
            @{ Name = 'AdminPassword'; Value = $AdminPassword },
            @{ Name = 'RootPassword'; Value = $RootPassword }
        )) {
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

    $properties = [ordered]@{
        'atlaso.management_mode' = 'dhcp'
        'atlaso.cidr' = ''
        'atlaso.gateway' = ''
        'atlaso.ipv6_enabled' = 'false'
        'atlaso.ipv6_cidr' = ''
        'atlaso.ipv6_gateway' = ''
        'atlaso.dns_servers' = ''
        'atlaso.fqdn' = $Fqdn
        'atlaso.admin_password' = $AdminPassword
        'atlaso.root_password' = $RootPassword
        'atlaso.root_ssh_enabled' = $RootSshEnabled.IsPresent.ToString().ToLowerInvariant()
    }
    $propertyXml = foreach ($entry in $properties.GetEnumerator()) {
        $key = ConvertTo-AtlasoOvfXmlValue -Value $entry.Key
        $value = ConvertTo-AtlasoOvfXmlValue -Value $entry.Value
        "<Property oe:key='$key' oe:value='$value'/>"
    }
    return "<Environment xmlns='http://schemas.dmtf.org/ovf/environment/1' xmlns:oe='http://schemas.dmtf.org/ovf/environment/1' oe:id='vm'><PlatformSection><Kind>VMware Workstation</Kind><Version>17</Version><Vendor>VMware, Inc.</Vendor><Locale>en</Locale></PlatformSection><PropertySection>$($propertyXml -join '')</PropertySection></Environment>"
}

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
